#!/usr/bin/env python3
"""Prove Inventory Linux reporting and audited reboot during Hyper-V lifecycle."""

from __future__ import annotations

import argparse
import atexit
import http.cookiejar
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


def request_json(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    method: str,
    path: str,
    *,
    token: str = "",
    payload: dict | None = None,
) -> dict | list:
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with opener.open(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path} failed with HTTP {exc.code}: {detail}") from exc


def request_form(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    path: str,
    payload: dict[str, str],
    *,
    expect_json: bool = False,
) -> dict | str:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=urllib.parse.urlencode(payload).encode(),
        headers={
            "Accept": "application/json" if expect_json else "text/html",
            "Content-Type": "application/x-www-form-urlencoded",
            **({"X-Atlaso-Grid": "1"} if expect_json else {}),
        },
        method="POST",
    )
    with opener.open(request, timeout=30) as response:
        body = response.read().decode()
        return json.loads(body) if expect_json else body


def csrf_from_page(page: str) -> str:
    match = re.search(r'name="csrf"\s+value="([^"]+)"', page)
    if not match:
        raise RuntimeError("Atlaso page did not contain a CSRF token.")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--appliance-url", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--mac", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    password = os.environ.get("ATLASO_LIFECYCLE_ADMIN_PASSWORD", "")
    if not password:
        raise RuntimeError("ATLASO_LIFECYCLE_ADMIN_PASSWORD is required.")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=context),
    )
    with opener.open(f"{args.appliance_url.rstrip('/')}/login", timeout=30) as response:
        login_page = response.read().decode()
    login_csrf = csrf_from_page(login_page)
    request_form(
        opener,
        args.appliance_url,
        "/login",
        {"username": args.username, "password": password, "csrf": login_csrf},
    )
    with opener.open(f"{args.appliance_url.rstrip('/')}/authentication", timeout=30) as response:
        authentication_page = response.read().decode()
    token_csrf = csrf_from_page(authentication_page)
    token_result = request_form(
        opener,
        args.appliance_url,
        "/authentication/api-tokens",
        {
            "name": "Network Boot lifecycle proof",
            "description": "Temporary Hyper-V lifecycle token",
            "scopes": "read:pxe write:pxe",
            "csrf": token_csrf,
        },
        expect_json=True,
    )
    token = str(token_result["raw_token"])
    token_id = int(token_result["resource"]["id"])
    def revoke_temporary_token() -> None:
        request_form(
            opener,
            args.appliance_url,
            f"/authentication/api-tokens/{token_id}/revoke",
            {"csrf": token_csrf},
        )

    atexit.register(revoke_temporary_token)
    expected_mac = args.mac.lower().replace("-", ":")
    deadline = time.monotonic() + args.timeout
    host = None
    while time.monotonic() < deadline:
        hosts = request_json(
            opener,
            args.appliance_url,
            "GET",
            "/api/v1/network-boot/hosts",
            token=token,
        )
        host = next(
            (
                row
                for row in hosts
                if expected_mac in {str(value).lower() for value in row.get("macs", [])}
            ),
            None,
        )
        if host and host.get("session_state") == "online":
            break
        time.sleep(3)
    if not host or host.get("session_state") != "online":
        raise RuntimeError("Inventory Linux did not submit an online report before timeout.")
    detail = request_json(
        opener,
        args.appliance_url,
        "GET",
        f"/api/v1/network-boot/hosts/{host['id']}",
        token=token,
    )
    report = detail.get("latest_report") or {}
    if not detail.get("dmi_uuid"):
        raise RuntimeError("Inventory report is missing the Hyper-V DMI UUID.")
    if not detail.get("cpu_model") or int(detail.get("total_memory_bytes") or 0) <= 0:
        raise RuntimeError("Inventory report is missing CPU or memory evidence.")
    if int(detail.get("disk_count") or 0) < 1 or int(detail.get("interface_count") or 0) < 1:
        raise RuntimeError("Inventory report did not include the lifecycle disk and NIC.")
    command = request_json(
        opener,
        args.appliance_url,
        "POST",
        f"/api/v1/network-boot/hosts/{host['id']}/reboot",
        token=token,
    )
    while time.monotonic() < deadline:
        status = request_json(
            opener,
            args.appliance_url,
            "GET",
            f"/api/v1/network-boot/commands/{command['id']}",
            token=token,
        )
        if status.get("status") == "acknowledged":
            break
        time.sleep(2)
    else:
        raise RuntimeError("Inventory Linux did not acknowledge the reboot command.")
    evidence = {
        "host": {
            "id": detail["id"],
            "dmi_uuid": detail["dmi_uuid"],
            "macs": detail["macs"],
            "cpu_model": detail["cpu_model"],
            "total_memory_bytes": detail["total_memory_bytes"],
            "disk_count": detail["disk_count"],
            "interface_count": detail["interface_count"],
        },
        "firmware_mode": report.get("firmware_mode"),
        "command": status,
    }
    with open(args.output, "w", encoding="utf-8") as output:
        json.dump(evidence, output, indent=2, sort_keys=True)
        output.write("\n")
    revoke_temporary_token()
    atexit.unregister(revoke_temporary_token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

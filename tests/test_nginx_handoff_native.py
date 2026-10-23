"""Exercise wildcard migration and rollback with real Linux nginx sockets."""

import importlib.machinery
import importlib.util
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

NGINX = os.environ.get("ATLASO_TEST_NGINX") or shutil.which("nginx")
HELPER = Path(__file__).resolve().parents[1] / "scripts/appliance/atlaso-helper"


@unittest.skipUnless(sys.platform == "linux" and NGINX, "Requires Linux and a native nginx binary")
class NativeNginxHandoffTests(unittest.TestCase):
    """Prove actual bind behavior rather than mocking reload exit status."""

    def test_wildcard_migration_and_exact_rollback(self):
        """Keep the old endpoint live while activating and reverting scoped sockets."""
        loader = importlib.machinery.SourceFileLoader("native_handoff_helper", str(HELPER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        helper = importlib.util.module_from_spec(spec)
        loader.exec_module(helper)
        with tempfile.TemporaryDirectory(dir=os.environ.get("ATLASO_NATIVE_TEST_ROOT")) as temporary:
            root = Path(temporary)
            sites = root / "sites"
            sites.mkdir()
            management = sites / "management.conf"
            public = sites / "public.conf"
            main = root / "nginx.conf"
            log = root / "error.log"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]

            def site(binding, body):
                """Render only the socket and response needed by this fixture.

                Args:
                    binding: nginx listen endpoint for the generated server.
                    body: Response body that identifies the serving generation.
                """
                return ("# Managed by Atlaso. Local changes may be overwritten.\n"
                        "server {\n"
                        f"  listen {binding} default_server;\n"
                        "  server_name _;\n"
                        f'  location / {{ return 200 "{body}"; }}\n'
                        "}\n")

            original = site(str(port), "old").replace(
                "  server_name _;", f"  listen [::]:{port} default_server;\n  server_name _;",
            )
            management.write_text(original)
            main.write_text(
                f"daemon off; worker_processes 1; pid {root}/nginx.pid; error_log {log} notice;\n"
                "events {}\nhttp { access_log off;\n"
                + "".join(f"{name}_temp_path {root}/{name};\n" for name in (
                    "client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
                + f"include {sites}/*.conf;\n}}\n"
            )
            process = subprocess.Popen(
                [NGINX, "-c", str(main)], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True,
            )
            direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def response(address, host=None):
                """Read a fresh connection without proxy or keepalive reuse.

                Args:
                    address: Numeric loopback address to contact.
                    host: Optional Host header selecting a cohosted virtual server.
                """
                request = urllib.request.Request(
                    f"http://{address}:{port}/openapi.json",
                    headers={"Host": host} if host else {},
                )
                with direct.open(request, timeout=1) as result:
                    return result.read().decode()

            def wait_for(predicate):
                """Bound asynchronous nginx activation and bind-failure observation.

                Args:
                    predicate: Observation that must become true before timeout.
                """
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    try:
                        if predicate():
                            return
                    except OSError:
                        pass
                    time.sleep(0.05)
                self.fail("Native nginx did not reach the expected state")

            real_run = subprocess.run

            def run(command, **kwargs):
                """Replace only systemd supervision; execute the real nginx signaler.

                Args:
                    command: Process command intercepted by the native fixture.
                    **kwargs: Process-run options forwarded to the nginx signaler.
                """
                if command[:3] == ["systemctl", "show", "nginx.service"]:
                    if "--property=ActiveState,MainPID" in command:
                        return subprocess.CompletedProcess(command, 0, f"ActiveState=active\nMainPID={process.pid}\n", "")
                    return subprocess.CompletedProcess(command, 0, str(process.pid), "")
                if command == ["systemctl", "reload", "nginx"]:
                    return real_run([NGINX, "-s", "reload", "-c", str(main)],
                                    capture_output=True, text=True, timeout=kwargs.get("timeout", 5))
                if command == ["systemctl", "enable", "--now", "nginx"]:
                    return subprocess.CompletedProcess(command, 0, "", "")
                self.fail(f"Unexpected native fixture command: {command}")

            state = {"previous_management_addresses": ["127.0.0.2"],
                     "previous_https_enabled": False, "previous_management_public_port": port}
            try:
                wait_for(lambda: response("127.0.0.2") == "old")
                with (patch.object(helper, "NGINX_MANAGEMENT_SITE_PATH", management),
                      patch.object(helper, "NGINX_PUBLIC_SERVICES_SITE_PATH", public),
                      patch.object(helper, "NGINX_SITES_DIR", sites),
                      patch.object(helper, "_nginx_binary", lambda: NGINX),
                      patch.object(helper, "_install_nginx_include", lambda: None),
                      patch.object(helper, "_write_management_handoff_state", lambda *_args: None),
                      patch.object(helper, "_run", run),
                      patch.object(helper, "_nginx_test_command", lambda: real_run(
                          [NGINX, "-t", "-c", str(main)], capture_output=True, text=True))):
                    # Demonstrate the raw nginx failure that verified reloads guard:
                    # syntax and signal succeed while the accepting workers stay old.
                    previous = helper._nginx_active_workers()
                    management.write_text(site(f"127.0.0.2:{port}", "unactivated"))
                    syntax = real_run([NGINX, "-t", "-c", str(main)], capture_output=True, text=True)
                    self.assertEqual(syntax.returncode, 0, syntax.stderr)
                    signaled = real_run([NGINX, "-s", "reload", "-c", str(main)], capture_output=True, text=True)
                    self.assertEqual(signaled.returncode, 0, signaled.stderr)
                    wait_for(lambda: "still could not bind" in log.read_text())
                    self.assertEqual(response("127.0.0.2"), "old")
                    self.assertEqual(helper._nginx_active_workers(), previous)
                    management.write_text(original)
                    self.assertEqual(helper._reload_nginx(verify_activation=True), 0)

                    # Production migration must activate scoped sockets without a restart.
                    helper._scope_management_handoff_old_listener(state)
                    self.assertTrue(state["nginx_reuseport_bridge"])
                    self.assertEqual(response("127.0.0.2"), "old")
                    self.assertEqual(set(helper._existing_management_scoped_addresses()[0]),
                                     {"127.0.0.1", "127.0.0.2", "::1"})
                    shared_candidate = (
                        "# Managed by Atlaso. Local changes may be overwritten.\n"
                        "server {\n"
                        f"  listen 127.0.0.3:{port};\n"
                        "  server_name identity.example.test;\n"
                        '  location / { return 200 "oidc"; }\n'
                        "}\n"
                        "server {\n"
                        f"  listen 127.0.0.3:{port};\n"
                        "  server_name ca.example.test;\n"
                        '  location / { return 200 "ca"; }\n'
                        "}\n"
                        "server {\n"
                        f"  listen 127.0.0.3:{port} default_server;\n"
                        "  server_name _;\n"
                        '  location / { return 200 "candidate"; }\n'
                        "}\n"
                    )
                    invalid_candidate = sites / "candidate-invalid.conf"
                    invalid_candidate.write_text(re.sub(
                        r"(?m)^(\s*listen\s+[^;\n]+);$", r"\1 reuseport;", shared_candidate,
                    ))
                    invalid_test = real_run(
                        [NGINX, "-t", "-c", str(main)], capture_output=True, text=True,
                    )
                    invalid_candidate.unlink()
                    self.assertNotEqual(invalid_test.returncode, 0, invalid_test.stderr)
                    self.assertIn("duplicate listen options", invalid_test.stderr.lower())

                    candidate = helper._management_handoff_reuseport_site(shared_candidate)
                    self.assertEqual(candidate.count("reuseport"), 1)
                    previous_generation = helper._nginx_active_workers()
                    self.assertEqual(helper._install_nginx_site(
                        public, candidate, verify_activation=True,
                    ), 0)
                    wait_for(lambda: helper._nginx_active_workers() != previous_generation)
                    self.assertEqual(helper._nginx_active_workers()[0], previous_generation[0])
                    self.assertEqual(public.read_text().count("reuseport"), 1)
                    self.assertEqual(response("127.0.0.3"), "candidate")
                    self.assertEqual(response("127.0.0.3", "identity.example.test"), "oidc")
                    self.assertEqual(response("127.0.0.3", "ca.example.test"), "ca")
                    self.assertEqual(response("127.0.0.2"), "old")

                    pxe_site = (
                        "# Managed by Atlaso. Local changes may be overwritten.\n"
                        "server {\n"
                        f"  listen 127.0.0.2:{port} reuseport;\n"
                        "  server_name pxe.example.test;\n"
                        '  location / { return 200 "pxe"; }\n'
                        "}\n"
                    )
                    invalid_candidate.write_text(pxe_site)
                    invalid_test = real_run(
                        [NGINX, "-t", "-c", str(main)], capture_output=True, text=True,
                    )
                    invalid_candidate.unlink()
                    self.assertNotEqual(invalid_test.returncode, 0, invalid_test.stderr)
                    self.assertIn("duplicate listen options", invalid_test.stderr.lower())

                    public_candidate = candidate + "\n" + pxe_site
                    previous_generation = helper._nginx_active_workers()
                    self.assertEqual(helper._install_nginx_site(
                        public, public_candidate, verify_activation=True,
                    ), 0)
                    wait_for(lambda: helper._nginx_active_workers() != previous_generation)
                    self.assertEqual(helper._nginx_active_workers()[0], previous_generation[0])
                    management_owner = sum(
                        "reuseport" in line and f"127.0.0.2:{port}" in line
                        for line in management.read_text().splitlines()
                    )
                    public_owner = sum(
                        "reuseport" in line and f"127.0.0.2:{port}" in line
                        for line in public.read_text().splitlines()
                    )
                    self.assertEqual((management_owner, public_owner), (1, 0))
                    self.assertEqual(response("127.0.0.2"), "old")
                    self.assertEqual(response("127.0.0.2", "pxe.example.test"), "pxe")
                    self.assertEqual(response("127.0.0.3"), "candidate")
                    self.assertEqual(response("127.0.0.3", "identity.example.test"), "oidc")

                    # The final paired publisher moves the one option owner to
                    # Public Services without changing the shared socket twice.
                    management_candidate = management.read_text()
                    previous_generation = helper._nginx_active_workers()
                    self.assertEqual(helper._management_handoff_publish_final_sites(
                        management_candidate, public_candidate, verify_activation=True,
                    ), 0)
                    wait_for(lambda: helper._nginx_active_workers() != previous_generation)
                    self.assertEqual(helper._nginx_active_workers()[0], previous_generation[0])
                    management_owner = sum(
                        "reuseport" in line and f"127.0.0.2:{port}" in line
                        for line in management.read_text().splitlines()
                    )
                    public_owner = sum(
                        "reuseport" in line and f"127.0.0.2:{port}" in line
                        for line in public.read_text().splitlines()
                    )
                    self.assertEqual((management_owner, public_owner), (0, 1))
                    self.assertEqual(
                        sum("reuseport" in line and f"127.0.0.3:{port}" in line
                            for line in public.read_text().splitlines()),
                        1,
                    )
                    self.assertEqual(response("127.0.0.2"), "old")
                    self.assertEqual(response("127.0.0.2", "pxe.example.test"), "pxe")

                    # As in recovery, files restore first while candidate sockets still exist.
                    public.unlink()
                    management.write_text(original)
                    helper._restore_management_handoff_nginx_bridge(state)
                    self.assertEqual(management.read_text(), original)
                    self.assertEqual(response("127.0.0.2"), "old")
                    self.assertIsNone(process.poll())
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()

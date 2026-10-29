"""Bounded public network observations and certificate-pinned host API probes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import ssl
import time
import zlib
from typing import Any

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_MAX_OPENAPI = 16 * 1024 * 1024


class OpenAPIReadinessPending(ValueError):
    """The pinned HTTPS peer has not exposed a ready API upstream yet."""


def _private_address(value: Any) -> str:
    """Require one canonical RFC 1918 IPv4 literal.

    Args:
        value: Public guest or caller-supplied address.
    """
    if not isinstance(value, str) or len(value) > 15:
        raise ValueError("network inspection address is invalid")
    address = ipaddress.IPv4Address(value)
    if str(address) != value or not any(address in network for network in _PRIVATE_NETWORKS):
        raise ValueError("network inspection requires an RFC 1918 address")
    return value


def guest_network_program(iso_sha256: str) -> str:
    """Generate a read-only address and public TLS-certificate observation.

    Args:
        iso_sha256: Completely admitted original installation ISO digest.
    """
    if not _DIGEST.fullmatch(iso_sha256):
        raise ValueError("network inspection media identity is invalid")
    body = _GUEST_PROGRAM.replace("ISO_DIGEST", repr(iso_sha256))
    encoded = base64.b64encode(zlib.compress(body.encode(), 9)).decode()
    command = '/opt/atlaso/.venv/bin/python -B -I -c \'exec(__import__("zlib").decompress(__import__("base64").b64decode("' + encoded + '")))\''
    if len(command) > 3500:
        raise ValueError("network observation exceeds the console bound")
    return command


def validate_network_report(raw: bytes, iso_sha256: str, mac: str, subnet: str, prefixlen: int) -> dict[str, Any]:
    """Reduce one exact, media-bound report to public network observations.

    Args:
        raw: Private-console record decoded within the producer bound.
        iso_sha256: Original admitted installation media digest.
        mac: Adapter MAC read from the receipt-bound VMX.
        subnet: Native vmrun host-only network address.
        prefixlen: Native host-only network prefix length.
    """
    if not _DIGEST.fullmatch(iso_sha256) or not raw or len(raw) > 4096:
        raise ValueError("network observation exceeds its bound")
    value = json.loads(raw)
    keys = {"schema", "kind", "iso_sha256", "interface", "mac", "address", "prefixlen", "certificate_sha256", "default_routes_absent"}
    if (not isinstance(value, dict) or set(value) != keys or type(value["schema"]) is not int or value["schema"] != 1
            or value["kind"] != "network" or value["iso_sha256"] != iso_sha256):
        raise ValueError("network observation schema or media identity differs")
    if (not isinstance(value["interface"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}", value["interface"])
            or value["interface"] == "lo" or not isinstance(value["mac"], str)
            or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value["mac"])
            or int(value["mac"][:2], 16) & 1 or value["mac"] == "00:00:00:00:00:00"
            or type(value["prefixlen"]) is not int or not 8 <= value["prefixlen"] <= 30
            or not isinstance(value["certificate_sha256"], str) or not _DIGEST.fullmatch(value["certificate_sha256"])
            or value["default_routes_absent"] is not True):
        raise ValueError("network observation fields are invalid")
    _private_address(value["address"])
    network = ipaddress.IPv4Network(f"{subnet}/{prefixlen}", strict=True)
    if (value["mac"] != mac or value["prefixlen"] != prefixlen or ipaddress.IPv4Address(value["address"]) not in network
            or ipaddress.IPv4Address(value["address"]) in {network.network_address, network.broadcast_address}
            or not any(network.subnet_of(private) for private in _PRIVATE_NETWORKS)):
        raise ValueError("guest network differs from the receipt-bound host-only adapter")
    return value


def probe_openapi(address: str, certificate_sha256: str, version: str) -> dict[str, Any]:
    """GET public OpenAPI only after matching the console-observed TLS leaf.

    Args:
        address: Observed private IPv4 address, independently matched to the vmnet.
        certificate_sha256: Public leaf digest measured through the owned console.
        version: Signed installed software version expected from the admitted ISO.
    """
    _private_address(address)
    if not _DIGEST.fullmatch(certificate_sha256) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("host API probe identity is invalid")
    # This lab read uses the exact leaf observed through the independently owned
    # console. It does not install a CA, send credentials, or issue a certificate.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(address, 443, timeout=10, context=context)
    try:
        connection.connect()
        if connection.sock is None:
            raise ValueError("host API TLS connection is unavailable")
        certificate = connection.sock.getpeercert(binary_form=True)
        if not certificate or len(certificate) > 65536 or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), certificate_sha256):
            raise ValueError("host API certificate differs from the owned console observation")
        connection.request("GET", "/openapi.json", headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if response.status in {502, 503, 504}:
            raise OpenAPIReadinessPending("host API upstream is not ready")
        if response.status != 200 or response.getheader("Content-Type", "").split(";")[0].strip() != "application/json":
            raise ValueError("host API did not return JSON with HTTP 200")
        raw = response.read(_MAX_OPENAPI + 1)
        if len(raw) > _MAX_OPENAPI:
            raise ValueError("host API schema exceeds its bound")
        value = json.loads(raw)
        if (not isinstance(value, dict) or not isinstance(value.get("info"), dict) or value["info"].get("version") != version
                or not isinstance(value.get("openapi"), str) or not re.fullmatch(r"3\.[0-9]+\.[0-9]+", value["openapi"])
                or not isinstance(value.get("paths"), dict) or not 1 <= len(value["paths"]) <= 8192):
            raise ValueError("host API schema or installed version differs")
        return {"address": address, "status": 200, "version": version, "openapi": value["openapi"],
                "path_count": len(value["paths"]), "body_sha256": hashlib.sha256(raw).hexdigest(),
                "certificate_sha256": certificate_sha256}
    finally:
        connection.close()


def wait_for_openapi(address: str, certificate_sha256: str, version: str, timeout_seconds: int = 45) -> dict[str, Any]:
    """Wait for a valid pinned API, retrying only transient upstream statuses.

    The caller's bounded process owns the hard wall-clock limit. A response that
    arrives after this readiness deadline never becomes successful evidence.

    Args:
        address: Original console-observed private IPv4 address.
        certificate_sha256: Exact public leaf digest required on every attempt.
        version: Signed installed version required before readiness is admitted.
        timeout_seconds: Fixed readiness window, at most 45 seconds.
    """
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 45:
        raise ValueError("host API readiness bound is invalid")
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    while True:
        if time.monotonic() >= deadline:
            raise ValueError("host API readiness deadline exceeded")
        attempts += 1
        try:
            measurement = probe_openapi(address, certificate_sha256, version)
        except OpenAPIReadinessPending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("host API readiness deadline exceeded") from None
            time.sleep(min(1, remaining))
        else:
            if time.monotonic() >= deadline:
                raise ValueError("host API readiness deadline exceeded")
            return {**measurement, "readiness_attempts": attempts}


_GUEST_PROGRAM = r'''
import base64,hashlib,ipaddress,json,re,socket,ssl,subprocess,time
stage="system-network-addresses"
try:
 end=time.monotonic()+90
 while True:
  c=subprocess.run(["ip","-j","addr","show","scope","global"],capture_output=True,timeout=5,check=True)
  if len(c.stdout)+len(c.stderr)>65536 or c.stderr: raise ValueError()
  rows=json.loads(c.stdout);candidates=[]
  if not isinstance(rows,list) or len(rows)>32: raise ValueError()
  for row in rows:
   if row.get("ifname")=="lo": continue
   for a in row.get("addr_info",[]):
    if a.get("family")=="inet" and a.get("scope")=="global":
     candidates.append((row["ifname"],row["address"].lower(),a["local"],a["prefixlen"]))
  if len(candidates)>1: raise ValueError()
  if candidates:
   name,mac,address,prefix=candidates[0]
   ip=ipaddress.IPv4Address(address)
   if not any(ip in ipaddress.IPv4Network(n) for n in ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]): raise ValueError()
   stage="system-network-routes"
   for family in ["-4","-6"]:
    routes=subprocess.run(["ip","-j",family,"route","show","default"],capture_output=True,timeout=5,check=True)
    if len(routes.stdout)+len(routes.stderr)>65536 or routes.stderr or json.loads(routes.stdout)!=[]: raise ValueError()
   stage="system-network-https"
   context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
   try:
    with socket.create_connection((address,443),timeout=3) as tcp:
     with context.wrap_socket(tcp,server_hostname=None) as tls: cert=tls.getpeercert(binary_form=True)
    if not cert or len(cert)>65536: raise ValueError()
    break
   except (OSError,ssl.SSLError): pass
  if time.monotonic()>=end: raise ValueError()
  time.sleep(2)
 r=dict(schema=1,kind="network",iso_sha256=ISO_DIGEST,interface=name,mac=mac,address=address,prefixlen=prefix,certificate_sha256=hashlib.sha256(cert).hexdigest(),default_routes_absent=True)
 raw=json.dumps(r,sort_keys=True,separators=(",", ":")).encode()
 if len(raw)>4096: raise ValueError()
 print("ATLASO-INSPECTION:"+base64.b64encode(raw).decode()+":END")
except BaseException:
 print("ATLASO-INSPECTION-FAILED:"+stage)
'''

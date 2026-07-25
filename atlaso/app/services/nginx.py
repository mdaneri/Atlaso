from __future__ import annotations

from ipaddress import ip_address


def format_nginx_listen(address: str, port: int) -> str:
    """Return an nginx listen endpoint with IPv6 literals bracketed."""
    candidate = address.strip().strip("[]")
    try:
        normalized = str(ip_address(candidate)).lower()
    except ValueError:
        normalized = candidate.lower()
    return f"[{normalized}]:{port}" if ":" in normalized else f"{normalized}:{port}"

from __future__ import annotations

import ssl
import sys
from typing import Any


def _compat_ssl_context(
    *,
    server_side: bool,
    cert_reqs: int,
    ca_certs: str | None,
    certfile: str | None,
    keyfile: str | None,
    ciphers: str | None,
) -> ssl.SSLContext:
    protocol = ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
    context = ssl.SSLContext(protocol)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not server_side:
        # Legacy ssl.wrap_socket did not perform hostname verification.
        context.check_hostname = False
    context.verify_mode = cert_reqs
    if ca_certs:
        context.load_verify_locations(ca_certs)
    if certfile:
        context.load_cert_chain(certfile, keyfile)
    if ciphers:
        context.set_ciphers(ciphers)
    return context


def install_ssl_wrap_socket_compat() -> None:
    if hasattr(ssl, "wrap_socket"):
        return

    def wrap_socket(
        sock,
        keyfile: str | None = None,
        certfile: str | None = None,
        server_side: bool = False,
        cert_reqs: int = ssl.CERT_NONE,
        ssl_version: int = ssl.PROTOCOL_TLS,
        ca_certs: str | None = None,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        ciphers: str | None = None,
        **_kwargs: Any,
    ):
        # PyKMIP passes a legacy fixed-version protocol. The compatibility
        # wrapper deliberately replaces it with a modern context and floor.
        _ = ssl_version
        context = _compat_ssl_context(
            server_side=server_side,
            cert_reqs=cert_reqs,
            ca_certs=ca_certs,
            certfile=certfile,
            keyfile=keyfile,
            ciphers=ciphers,
        )
        return context.wrap_socket(
            sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
        )

    ssl.wrap_socket = wrap_socket  # type: ignore[attr-defined]


def main() -> int:
    install_ssl_wrap_socket_compat()
    from kmip.services.server.server import main as pykmip_main

    return int(pykmip_main() or 0)


if __name__ == "__main__":
    sys.exit(main())

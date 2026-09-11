"""Serve an authenticated, isolated test application on loopback for browser checks.

Run from the repository root with an explicit unused --root beneath the configured
task worktree root. This uses synthetic pytest credentials and the dry-run adapter;
it must never proxy a deployed appliance. Stop with Ctrl+C after browser validation.
"""

import argparse
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main() -> None:
    """Run the bounded loopback fixture with caller-selected task-owned storage."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    os.environ.update(TEMP=str(root), TMP=str(root), ATLASO_APP_LOG_PATH=str(root / "app.log"))

    from pytest import MonkeyPatch

    from tests.conftest import client as client_fixture
    from tests.routers.ui.helpers import login

    patch = MonkeyPatch()
    fixture = client_fixture.__wrapped__(root, patch)
    client = next(fixture)
    login(client)

    class Handler(BaseHTTPRequestHandler):
        """Forward loopback browser requests to the isolated application fixture."""

        def handle_request(self) -> None:
            """Preserve request semantics while retaining the fixture login session."""
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            excluded = {"host", "cookie", "content-length", "accept-encoding"}
            headers = {key: value for key, value in self.headers.items() if key.lower() not in excluded}
            response = client.request(self.command, self.path, content=body, headers=headers, follow_redirects=False)
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in {"content-length", "transfer-encoding", "content-encoding"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)

        do_GET = handle_request
        do_POST = handle_request
        do_PATCH = handle_request
        do_DELETE = handle_request

        def log_message(self, format: str, *args: object) -> None:
            """Suppress HTTP request logging; application logs use the explicit root.

            Args:
                format: Unused HTTP log format.
                *args: Unused HTTP log values.
            """

    try:
        with HTTPServer(("127.0.0.1", args.port), Handler) as server:
            print(f"Isolated browser fixture ready on loopback port {args.port}", flush=True)
            server.serve_forever()
    finally:
        fixture.close()
        patch.undo()


if __name__ == "__main__":
    main()

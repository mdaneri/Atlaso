"""Test ui behavior."""

import json
import os
import re
from pathlib import Path

import pytest

from tests.routers.ui.helpers import assert_apply_redirect, login


def create_api_token(client, scopes):
    """Create api token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.


    Returns:
        The created api token.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "test token", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_login_and_dashboard_render(client):
    """Verify that login and dashboard render.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from pathlib import Path

    login(client)
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/ui/management"
    response = client.get("/ui/management/dashboard")
    assert response.status_code == 200
    assert "Atlaso" in response.text
    assert "Routes &amp; WAN Simulation" in response.text
    assert "VCF Offline Depot" in response.text
    assert "HTTPS Repository" not in response.text
    assert "Users" in response.text
    assert "LDAP / Users" not in response.text
    assert 'href="/ui/management/monitor"' in response.text
    nav = response.text.split('<nav class="nav-stack"', 1)[1].split("</nav>", 1)[0]
    for section in ["Overview", "Appliance Setup", "Core Services", "Identity &amp; Trust", "VCF Workflows", "Operations"]:
        assert section in nav
    assert nav.count("data-primary-nav-group") == 6
    assert nav.count("data-primary-nav-toggle") == 6
    assert nav.count('aria-expanded="true"') == 6
    assert nav.count('role="group"') == 6
    assert 'data-nav-group-key="overview"' in nav
    assert 'id="primary-nav-overview-toggle"' in nav
    assert 'aria-controls="primary-nav-overview-links"' in nav
    assert 'id="primary-nav-overview-links"' in nav
    assert 'aria-labelledby="primary-nav-overview-toggle"' in nav
    assert 'href="/ui/management/dashboard" aria-current="page"' in nav
    assert 'type="button"' in nav
    assert "data-appliance-apply-sidebar" not in nav
    expected_nav_order = [
        "/ui/management/dashboard",
        "/ui/management/monitor",
        "/ui/management/settings",
        "/ui/management/physical-interfaces",
        "/ui/management/vlan-interfaces",
        "/ui/management/routes-wan",
        "/ui/management/firewall",
        "/ui/management/dns",
        "/ui/management/ntp",
        "/ui/management/dhcp",
        "/ui/management/authentication",
        "/ui/management/users",
        "/ui/management/ldap",
        "/ui/management/certificate-authority",
        "/ui/management/vsphere-key-providers",
        "/ui/management/network-boot",
        "/ui/management/esx-storage",
        "/ui/management/vcf-helper",
        "/ui/management/vcf-offline-depot",
        "/ui/management/vcf-private-registry",
        "/ui/management/vcf-backups",
        "/ui/management/services",
        "/ui/management/tasks",
        "/ui/management/logs",
        "/ui/management/audit-log",
        "/ui/management/appliance-update",
        "/ui/management/backup-restore",
    ]
    position = -1
    for href in expected_nav_order:
        next_position = nav.index(f'href="{href}"')
        assert next_position > position
        position = next_position
    assert "/ca/requests" not in nav
    topbar = response.text.split('<header class="topbar"', 1)[1].split("</header>", 1)[0]
    footer = response.text.split('<footer class="management-info-footnote"', 1)[1].split("</footer>", 1)[0]
    assert 'data-server-time' not in topbar
    assert 'data-server-time' in footer
    documentation_link = (
        'href="https://mdaneri.github.io/Atlaso/docs/" target="_blank" rel="noopener" '
        'title="Atlaso documentation"'
    )
    assert documentation_link in footer
    assert ">Documentation<" in footer
    assert footer.index("https://github.com/mdaneri/Atlaso") < footer.index(documentation_link)
    assert footer.index(documentation_link) < footer.index('href="/api/docs"')
    app_js = Path("atlaso/app/static/app.js").read_text()
    assert "function initializeServerTime()" in app_js
    assert 'window.setInterval(sync, 60000)' in app_js
    assert "data-account-menu" in response.text
    assert 'aria-label="Open account menu for admin"' in response.text
    assert "About" in response.text
    assert "Sign out (admin)" in response.text
    assert 'action="/ui/management/appliance/power/reboot"' in response.text
    assert 'action="/ui/management/appliance/power/shutdown"' in response.text
    assert 'data-confirm-title="Reboot Atlaso appliance?"' in response.text
    assert 'data-confirm-title="Shut down Atlaso appliance?"' in response.text
    assert 'id="about-modal"' in response.text
    assert 'class="about-brand-mark" src="/static/brand/atlaso-icon.svg"' in response.text
    assert '<span class="role-chip">admin</span>' not in response.text
    assert 'href="/ui/management/logs"' in response.text
    assert 'href="/ui/management/audit-log"' in response.text
    assert "cdn.tailwindcss.com" not in response.text
    assert "unpkg.com/htmx" not in response.text
    assert 'body class="bg-slate-100 text-slate-900"' not in response.text
    assert "/static/brand/atlaso-icon.svg" in response.text
    sidebar_brand = response.text.split('<a class="brand sidebar-brand"', 1)[1].split("</a>", 1)[0]
    assert 'aria-label="Atlaso Dashboard"' in sidebar_brand
    assert "/static/brand/atlaso-logo-horizontal-transparent-1200x300.png" in sidebar_brand
    assert "<strong>Atlaso</strong>" not in sidebar_brand
    assert "Photon appliance" not in sidebar_brand
    assert 'class="management-info-footnote"' in response.text
    from atlaso import __version__

    assert f"Atlaso {__version__}" in response.text
    assert 'href="/api/docs"' in response.text
    assert "Python " in response.text
    assert '<link rel="icon" href="/favicon.ico" type="image/x-icon">' in response.text
    assert '<link rel="manifest" href="/manifest.webmanifest">' in response.text
    assert '<meta name="theme-color"' not in response.text
    assert "/static/pwa.js?v=issue-287-2" in response.text
    assert "Everything your virtualization lab needs." in response.text
    assert "Infrastructure • Storage • Identity • Networking • Lifecycle" in response.text
    assert "simplifying deployment, maintenance, and validation" in response.text
    assert "LF</span>" not in response.text
    assert "/static/vendor/prism/prism-core.min.js" in response.text
    assert "/static/vendor/prism/prism-diff.min.js" in response.text


def test_web_terminal_requires_login_and_renders_admin_only_unavailable_state(client):
    """Verify that web terminal requires login and renders admin only unavailable state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    unauthenticated = client.get("/ui/management/terminal", follow_redirects=False)
    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/ui/management/login?next=/ui/management/terminal"

    login(client)
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.web_terminal_access = False
        db.commit()
    response = client.get("/ui/management/terminal")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Appliance Web Terminal" in response.text
    assert "Terminal status for admin" in response.text
    assert "No shell starts until the requirement below is resolved." in response.text
    assert "Passwordless local SSH as admin" not in response.text
    assert "Web terminal access is disabled in Appliance Settings." in response.text
    assert '"detail":' not in response.text
    assert "/static/vendor/xterm/xterm.js?v=5.5.0" in response.text
    assert "/static/terminal.js?v=issue-287-2" in response.text
    assert "data-terminal-connect" not in response.text
    assert "data-terminal-disconnect" not in response.text

    dashboard = client.get("/ui/management/dashboard")
    assert 'href="/ui/management/terminal"' in dashboard.text
    assert dashboard.text.count('href="/ui/management/terminal"') == 1
    assert '<a class="account-menu-item" href="/ui/management/terminal"' not in dashboard.text
    assert dashboard.text.index("Operations") < dashboard.text.index('href="/ui/management/terminal"') < dashboard.text.index('href="/ui/management/services"')


def test_disabled_web_terminal_page_accepts_only_management_listener(client, monkeypatch):
    """Verify that disabled web terminal page accepts only management listener.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from types import SimpleNamespace

    from atlaso.app import web_terminal

    allowed_addresses = []

    def capture_listener(_headers, _client_host, addresses):
        """Return capture listener.

        Args:
            _headers: Headers supplied to the test scenario.
            _client_host: Client host supplied to the test scenario.
            addresses: Addresses supplied to the test scenario.
        """
        allowed_addresses.extend(addresses)
        return addresses == ["192.168.49.1"]

    monkeypatch.setattr(web_terminal, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    monkeypatch.setattr(
        web_terminal,
        "_terminal_network_state",
        lambda _db: (SimpleNamespace(web_terminal_enabled=False), [], [], ["192.168.49.1"]),
    )
    monkeypatch.setattr(web_terminal, "_request_uses_selected_listener", capture_listener)

    login(client)
    response = client.get("/ui/management/terminal")

    assert response.status_code == 200
    assert allowed_addresses == ["192.168.49.1"]
    assert "Web terminal access is disabled in Appliance Settings." in response.text


def test_public_web_terminal_uses_public_shell_and_explicit_user_access(client, monkeypatch):
    """Verify that public web terminal uses public shell and explicit user access.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from types import SimpleNamespace

    from sqlalchemy import select

    from atlaso.app import ui, web_terminal
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, PhysicalInterface, User

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.management_https_enabled = True
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["eth0", "eth2"]'
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.ip_cidr = "192.168.167.10/24"
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        user = User(
            username="test",
            role="viewer",
            roles_json='["viewer"]',
            shell="/bin/bash",
            web_terminal_access=True,
            enabled=True,
        )
        db.add(user)
        db.commit()
        user_id = user.id

    class LocalAuthenticationAdapter:
        """Represent local authentication adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        def authenticate_local_user(self, username: str, password: str) -> AdapterResult:
            """Return authenticate local user.

            Args:
                username: Account name used for authentication or lookup.
                password: Password supplied for the immediate authenticated operation.
            """
            return AdapterResult(
                command=["atlaso-helper", "local-users", "authenticate", username],
                dry_run=False,
                returncode=0 if username == "test" and password == "Test-user1!" else 1,
            )

    monkeypatch.setattr(ui, "SystemAdapter", LocalAuthenticationAdapter)
    monkeypatch.setattr(web_terminal, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    monkeypatch.setattr(web_terminal, "_helper_applied", lambda: True)
    monkeypatch.setattr(web_terminal, "_request_is_https", lambda *_args: True)
    monkeypatch.setattr(
        web_terminal,
        "_request_uses_selected_listener",
        lambda _headers, _server_host, addresses: "192.168.87.32" in addresses,
    )

    login_page = client.get(
        "/ui/public/login?next=/ui/public/terminal",
        headers={"host": "192.168.87.32"},
    )
    assert login_page.status_code == 200
    assert "Sign in to Web Terminal" in login_page.text
    assert 'class="public-portal-shell"' in login_page.text
    assert 'class="app-shell"' not in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/ui/public/login",
        headers={"host": "192.168.87.32"},
        data={
            "username": "test",
            "password": "Test-user1!",
            "csrf": csrf,
            "next": "/ui/public/terminal",
        },
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    assert signed_in.headers["location"] == "/ui/public/terminal"

    terminal = client.get("/ui/public/terminal", headers={"host": "192.168.87.32"})
    assert terminal.status_code == 200
    assert "Passwordless local SSH as test" in terminal.text
    assert 'class="public-portal-shell"' in terminal.text
    assert 'class="app-shell"' not in terminal.text
    assert "Back to Public Services" not in terminal.text
    assert 'action="/ui/public/logout"' in terminal.text
    assert 'name="next" value="/ui/public/terminal"' in terminal.text
    assert terminal.text.index("/static/ui-routes.js?v=issue-287-1") < terminal.text.index("/static/terminal.js?v=issue-287-2")

    directory = client.get("/ui/public", headers={"host": "192.168.87.32"})
    assert directory.status_code == 200
    assert 'action="/ui/public/logout"' in directory.text
    assert 'action="/ui/public/ca/requests/logout"' not in directory.text

    with SessionLocal() as db:
        user = db.get(User, user_id)
        user.web_terminal_access = False
        db.commit()
    denied = client.get("/ui/public/terminal", headers={"host": "192.168.87.32"})
    assert denied.status_code == 403
    assert "Web SSH access is not enabled" in denied.text
    logout = client.post(
        "/ui/public/logout",
        headers={"host": "192.168.87.32"},
        data={"csrf": csrf, "next": "/ui/public/terminal"},
        follow_redirects=False,
    )
    assert logout.status_code == 303
    assert logout.headers["location"] == "/ui/public/terminal"

    expired_ticket = client.post(
        "/ui/public/terminal/tickets",
        headers={"host": "192.168.87.32"},
        data={"csrf": csrf, "browser_session_id": "browser_session_1234"},
        follow_redirects=False,
    )
    assert expired_ticket.status_code == 303
    assert expired_ticket.headers["location"] == "/ui/public/login?next=/ui/public/terminal"


def test_web_terminal_uses_one_use_ticket_and_bridges_websocket_input(client, monkeypatch):
    """Verify that web terminal uses one use ticket and bridges websocket input.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import threading
    from types import SimpleNamespace

    from sqlalchemy import select

    from atlaso.app import web_terminal
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, User

    class FakeChannel:
        """Represent fake channel.

        Attributes:
            closed: Closed captured or supplied by this test helper.
            sent: Sent captured or supplied by this test helper.
            output_sent: Output sent captured or supplied by this test helper.
            finished: Finished captured or supplied by this test helper.
        """
        def __init__(self):
            """Initialize the fake channel."""
            self.closed = False
            self.sent = []
            self.output_sent = False
            self.finished = threading.Event()

        def recv(self, _size):
            """Return recv.

            Args:
                _size: Size supplied to the test scenario.
            """
            if not self.output_sent:
                self.output_sent = True
                return b"shell ready\r\n"
            self.finished.wait(timeout=2)
            return b""

        def sendall(self, data):
            """Handle sendall.

            Args:
                data: Data supplied to the test scenario.
            """
            self.sent.append(data)
            self.closed = True
            self.finished.set()

        def resize_pty(self, **_kwargs):
            """Return resize pty.

            Args:
                **_kwargs: Additional keyword arguments accepted by the callable.
            """
            return None

        def close(self):
            """Handle close."""
            self.closed = True
            self.finished.set()

    class FakeTransport:
        """Represent fake transport."""
        def close(self):
            """Return close."""
            return None

    channel = FakeChannel()
    open_count = 0

    def open_channel(*_args):
        """Return open channel.

        Args:
            *_args: Additional positional arguments accepted by the callable.
        """
        nonlocal open_count
        open_count += 1
        return FakeTransport(), channel

    monkeypatch.setattr(web_terminal, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    monkeypatch.setattr(web_terminal, "_request_uses_selected_listener", lambda *_args: True)
    monkeypatch.setattr(web_terminal, "_request_is_https", lambda *_args: True)
    monkeypatch.setattr(web_terminal, "_helper_applied", lambda: True)
    monkeypatch.setattr(web_terminal, "_open_ssh_channel", open_channel)

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.management_https_enabled = True
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["eth0"]'
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.shell = "/bin/bash"
        db.commit()

    page = client.get("/ui/management/terminal")
    assert page.status_code == 200
    assert "data-terminal-reconnect" in page.text
    assert "data-terminal-copy" in page.text
    assert "data-terminal-download" in page.text
    assert "data-terminal-connect" not in page.text
    assert "data-terminal-disconnect" not in page.text
    csrf = page.text.split('data-csrf="', 1)[1].split('"', 1)[0]
    ticket_response = client.post(
        "/ui/management/terminal/tickets",
        data={"csrf": csrf, "browser_session_id": "browser_session_1234"},
    )
    assert ticket_response.status_code == 200
    assert ticket_response.headers["cache-control"] == "no-store"
    assert ticket_response.json()["websocket_path"] == "/terminal/ws"
    ticket = ticket_response.json()["ticket"]

    with client.websocket_connect("/ui/management/terminal/ws", headers={"origin": "http://testserver"}) as websocket:
        websocket.send_json({"type": "authenticate", "ticket": ticket})
        first_ready = websocket.receive_json()
        assert first_ready["type"] == "ready"
        assert first_ready["resumed"] is False
        assert websocket.receive_bytes() == b"shell ready\r\n"

        reload_ticket = client.post(
            "/ui/management/terminal/tickets",
            data={"csrf": csrf, "browser_session_id": "browser_session_1234"},
        )
        assert reload_ticket.status_code == 200
        with client.websocket_connect("/ui/management/terminal/ws", headers={"origin": "http://testserver"}) as reloaded_websocket:
            reloaded_websocket.send_json({"type": "authenticate", "ticket": reload_ticket.json()["ticket"]})
            reload_ready = reloaded_websocket.receive_json()
            assert reload_ready["type"] == "ready"
            assert reload_ready["resumed"] is True
            assert reloaded_websocket.receive_bytes() == b"shell ready\r\n"

        conflict = client.post(
            "/ui/management/terminal/tickets",
            data={"csrf": csrf, "browser_session_id": "other_browser_1234"},
        )
        assert conflict.status_code == 409
        assert conflict.json()["error_code"] == "TERMINAL_SESSION_ACTIVE"

        takeover = client.post(
            "/ui/management/terminal/tickets",
            data={"csrf": csrf, "browser_session_id": "other_browser_1234", "takeover": "true"},
        )
        assert takeover.status_code == 200
        with client.websocket_connect("/ui/management/terminal/ws", headers={"origin": "http://testserver"}) as moved_websocket:
            moved_websocket.send_json({"type": "authenticate", "ticket": takeover.json()["ticket"]})
            moved_ready = moved_websocket.receive_json()
            assert moved_ready["type"] == "ready"
            assert moved_ready["resumed"] is True
            assert moved_websocket.receive_bytes() == b"shell ready\r\n"
            moved_websocket.send_json({"type": "input", "data": "whoami\r"})

    assert channel.sent == [b"whoami\r"]
    assert open_count == 1
    assert web_terminal._consume_ticket(ticket, 1, "admin", csrf) is None
    assert client.get("/static/brand/atlaso-icon.svg").status_code == 200
    assert client.get("/static/brand/atlaso-logo-horizontal-light.svg").status_code == 200
    assert client.get("/static/brand/atlaso-logo-horizontal-transparent-1200x300.png").status_code == 200
    favicon = client.get("/favicon.ico")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/x-icon")
    terminal_js = client.get("/static/terminal.js")
    assert 'JSON.stringify({ type: "input", data })' in terminal_js.text
    assert "if (response.redirected)" in terminal_js.text
    assert "window.location.assign(response.url)" in terminal_js.text
    assert 'data === "\\u0004" ? "exit\\r" : data' not in terminal_js.text


def test_appliance_power_action_creates_task_before_scheduling(client, monkeypatch):
    """Verify that appliance power action creates task before scheduling.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job, JobStatus
    from atlaso.app.ui import SystemAdapter

    observed: list[tuple[str, str]] = []

    def fake_schedule(_self, action: str) -> AdapterResult:
        """Return fake schedule.

        Args:
            _self: Self supplied to the test scenario.
            action: Action supplied to the test scenario.
        """
        with SessionLocal() as db:
            job = db.execute(select(Job).where(Job.type == f"appliance-{action}")).scalar_one()
            observed.append((job.status, action))
        return AdapterResult(
            command=["sudo", "-n", SystemAdapter.HELPER_PATH, "appliance-power", action, "--real"],
            dry_run=False,
            stdout="scheduled",
        )

    monkeypatch.setattr(SystemAdapter, "schedule_appliance_power", fake_schedule)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance/power/reboot",
        data={"csrf": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith("/ui/management/tasks?job_id=job_")
    assert observed == [(JobStatus.RUNNING.value, "reboot")]
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-reboot")).scalar_one()
        payload = json.loads(job.result or "{}")
        assert job.status == JobStatus.SUCCEEDED.value
        assert job.progress_percent == 100
        assert payload["action"] == "reboot"
        assert payload["scheduled"] is True
        assert payload["delay_seconds"] == 5
        actions = set(db.execute(select(AuditEvent.action).where(AuditEvent.resource_id == job.id)).scalars())
        assert actions == {"submit_appliance_reboot", "schedule_appliance_reboot"}

    tasks = client.get(response.headers["location"])
    assert tasks.status_code == 200
    assert "Appliance Reboot" in tasks.text


def test_account_menu_uses_defined_opaque_surface_tokens():
    """Verify that account menu uses defined opaque surface tokens."""
    from pathlib import Path

    app_css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    menu_css = app_css.split(".account-menu {", 1)[1].split(".inline-help-row", 1)[0]

    assert "var(--panel)" not in menu_css
    assert "var(--primary)" not in menu_css
    assert menu_css.count("background: var(--surface);") == 2
    assert "border-color: var(--accent);" in menu_css


def test_appliance_shutdown_task_reports_helper_failure(client, monkeypatch):
    """Verify that appliance shutdown task reports helper failure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.ui import SystemAdapter

    monkeypatch.setattr(
        SystemAdapter,
        "schedule_appliance_power",
        lambda _self, action: AdapterResult(
            command=["atlaso-helper", "appliance-power", action],
            dry_run=False,
            stderr="systemd-run unavailable",
            returncode=127,
        ),
    )
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post("/appliance/power/shutdown", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-shutdown")).scalar_one()
        payload = json.loads(job.result or "{}")
        assert job.status == JobStatus.FAILED.value
        assert job.error == "Appliance shutdown scheduling failed."
        assert payload["scheduled"] is False
def test_tasks_page_lists_redacts_logs_and_cancels(client):
    """Verify that tasks page lists redacts logs and cancels.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json
    from pathlib import Path

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep, utcnow

    login(client)
    with SessionLocal() as db:
        job = Job(
            id="job_taskgrid001",
            type="vcf-sddc-manager-deploy",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            started_at=utcnow(),
            progress_percent=42,
            result=json.dumps(
                {
                    "state": "uploading-disk1.vmdk",
                    "target": "sddcm.atlaso.internal",
                    "api_password": "VMware01!",
                    "tls_fingerprint": "AA:BB",
                }
            ),
            error="",
        )
        db.add(job)
        db.add(
            JobStep(
                id="job_taskgrid001:ldap",
                job_id=job.id,
                component_key="ldap",
                label="Managed LDAP",
                position=1,
                status=JobStatus.FAILED.value,
                progress_percent=100,
                result=json.dumps(
                    {
                        "success": False,
                        "commands": [
                            {
                                "returncode": 1,
                                "stderr": "LDAP validation failed without exposing bind_password=DirectorySecret1!",
                            }
                        ],
                    }
                ),
                error="The component reported an apply failure.",
            )
        )
        db.add(
            Job(
                id="job_taskgrid_leaf",
                type="appliance-update",
                status=JobStatus.SUCCEEDED.value,
                created_by="admin",
                progress_percent=100,
                task_config_json=json.dumps({"mode": "check"}),
                result=json.dumps(
                    {
                        "mode": "check",
                        "state": "succeeded",
                        "stdout": (
                            '{"action":"run","args":["script.ps1"],"dry_run":false,'
                            '"group":"automation","helper":"atlaso-helper","timestamp":"2026-07-21T18:50:14Z"}\n'
                            "PowerShell output"
                        ),
                        "stderr": "",
                    }
                ),
            )
        )
        db.commit()

    page = client.get("/tasks?job_id=job_taskgrid001")
    assert page.status_code == 200
    assert "Tasks" in page.text
    assert 'href="/ui/management/tasks"' in page.text
    assert "job_taskgrid001" in page.text
    assert "uploading-disk1.vmdk" in page.text
    assert "VMware01!" not in page.text
    assert "[redacted]" in page.text
    assert "data-task-detail-cancel" in page.text
    assert "data-task-detail-log" in page.text
    assert 'class="terminal-note task-result-preview"' in page.text
    assert 'class="language-json" data-task-detail-result' in page.text
    assert "data-task-detail-errors" in page.text
    assert "data-task-detail-errors-content" in page.text
    assert 'class="alert error hidden" data-task-detail-error' not in page.text
    assert "data-task-detail-console" in page.text
    assert "data-task-detail-console-content" in page.text
    assert "data-task-detail-console-error-content" in page.text
    assert 'class="terminal-note task-log-preview"' in page.text
    assert 'class="language-atlaso-log" data-task-log-content' in page.text
    assert "task-grid-shell" in page.text
    assert "data-task-component-options" in page.text
    assert "Appliance Update check" in page.text
    assert "Appliance Update install" in page.text
    assert "Appliance Update repository sync" in page.text
    assert 'data-selected-task-id="job_taskgrid001"' in page.text
    plain_page = client.get("/tasks")
    assert plain_page.status_code == 200
    assert 'data-selected-task-id=""' in plain_page.text
    app_js = Path("atlaso/app/static/app.js").read_text()
    tasks_table_js = app_js.split("function initializeTasksPage", 1)[1].split("function updateVcfDepotSummary", 1)[0]
    assert 'paginationMode: "remote"' in tasks_table_js
    assert "paginationSizeSelector" not in tasks_table_js
    assert 'atlasoTasksTable?.on("rowDblClick", (_event, row) => openTaskDetail(row.getData()))' in app_js
    assert "rowContextMenu" in tasks_table_js
    assert 'label: "Details"' in tasks_table_js
    assert 'label: "Log"' in tasks_table_js
    assert 'label: "Cancel task"' in tasks_table_js
    assert 'filterMode: "remote"' in tasks_table_js
    assert "ajaxRequestFunc: requestTasksTableData" in tasks_table_js
    assert 'query.set("task_type", page.dataset.taskType);' in app_js
    assert 'const componentFilterLocked = page.dataset.taskLockComponentFilter === "true";' in tasks_table_js
    assert 'initialHeaderFilter: initialComponentFilter && !componentFilterLocked ? [{ field: "id", value: initialComponentFilter }] : []' in tasks_table_js
    assert '...(componentFilterLocked ? {} : {' in tasks_table_js
    assert "function initializeApplianceUpdateSubmission()" in app_js
    assert "function initializeApplianceUpdateSourceSync()" in app_js
    assert "function selectedUnsynchronizedUpdateStreams()" in app_js
    assert "updateApplianceUpdateSourceSyncState(selected);" in app_js
    assert "task.id !== atlasoNewTaskId" in app_js
    assert "task.result.source_results.filter" in app_js
    assert 'headers: { Accept: "application/json" }' in app_js
    assert 'setApplianceUpdateActionsDisabled(true);' in app_js
    source_sync_js = app_js.split("function initializeApplianceUpdateSourceSync()", 1)[1].split("function ", 1)[0]
    assert "window.location" not in source_sync_js
    assert "await refreshTasksPage();" in source_sync_js
    assert 'row.getElement().classList.toggle("task-grid-new-task"' in tasks_table_js
    assert "task-grid-new-badge" in tasks_table_js
    assert 'height: page.dataset.taskGridHeight || "100%"' in tasks_table_js
    assert 'query.set("filters", JSON.stringify(params.filters || params.filter || []));' in app_js
    assert "const expandedRowIds = expandedTaskRowIds(atlasoTasksTable);" in app_js
    assert "restoreExpandedTaskRows(atlasoTasksTable, expandedRowIds);" in app_js
    assert 'headerFilterPlaceholder: "Choose or type custom"' in tasks_table_js
    assert "values: atlasoTaskComponentOptions" in tasks_table_js
    assert "autocomplete: true" in tasks_table_js
    assert "freetext: true" in tasks_table_js
    assert 'title: "State"' in tasks_table_js
    assert 'pending: "Pending", running: "Running", succeeded: "Succeeded", failed: "Failed", cancelled: "Cancelled"' in tasks_table_js
    assert 'title: "Actions"' not in tasks_table_js
    assert "data-task-row-menu-toggle" not in app_js
    app_css = Path("atlaso/app/static/app.css").read_text()
    assert ".tasks-panel {\n  display: grid;\n  gap: 14px;\n  grid-template-rows: auto minmax(0, 1fr);\n  min-width: 0;\n  max-width: 100%;" in app_css
    assert ".task-grid-shell {\n  width: 100%;\n  max-width: 100%;" in app_css
    assert ".task-detail-facts {\n  grid-template-columns: repeat(2, minmax(0, 1fr));" in app_css
    assert ".task-detail-facts div {\n  grid-template-columns: 92px minmax(0, 1fr);" in app_css
    assert ".task-row-menu" not in app_css
    assert ".task-result-preview code," in app_css
    assert "highlightConfigPreviewElement(result);" in app_js
    assert "highlightConfigPreviewElement(content);" in app_js
    assert 'errorContent.textContent = errorMessages.join("\\n\\n");' in app_js
    assert 'modal.querySelector("[data-task-detail-error]")' not in app_js

    status_response = client.get("/tasks/status?job_id=job_taskgrid001")
    assert status_response.status_code == 200
    payload = status_response.json()
    selected = payload["selected_task"]
    assert selected["id"] == "job_taskgrid001"
    assert selected["can_cancel"] is True
    assert selected["result"]["api_password"] == "[redacted]"
    failed_step = selected["_children"][0]
    assert failed_step["error_messages"][0] == "LDAP validation failed without exposing bind_password=[redacted]"
    assert failed_step["status_pill"] == "error"
    assert "DirectorySecret1!" not in json.dumps(failed_step)
    assert payload["active_count"] == 1
    assert payload["filtered_count"] == 2
    assert payload["total_count"] == 2
    leaf = next(row for row in payload["tasks"] if row["id"] == "job_taskgrid_leaf")
    assert "_children" not in leaf
    assert leaf["console_output"] == "PowerShell output"
    assert leaf["console_stdout"] == "PowerShell output"
    assert leaf["console_stderr"] == ""
    assert '"action":"run"' in leaf["result"]["stdout"]

    component_filter = client.get(
        "/tasks/status",
        params={"filters": json.dumps([{"field": "id", "type": "like", "value": "Managed LDAP"}])},
    )
    assert component_filter.status_code == 200
    component_payload = component_filter.json()
    assert [row["id"] for row in component_payload["tasks"]] == ["job_taskgrid001"]
    assert component_payload["filtered_count"] == 1
    assert component_payload["total_count"] == 2

    appliance_update_mode_filter = client.get(
        "/tasks/status",
        params={"filters": json.dumps([{"field": "id", "type": "like", "value": "Appliance Update check"}])},
    )
    assert appliance_update_mode_filter.status_code == 200
    appliance_update_mode_payload = appliance_update_mode_filter.json()
    assert [row["id"] for row in appliance_update_mode_payload["tasks"]] == ["job_taskgrid_leaf"]
    assert appliance_update_mode_payload["filtered_count"] == 1
    assert appliance_update_mode_payload["total_count"] == 2

    status_filter = client.get(
        "/tasks/status",
        params={"filters": json.dumps([{"field": "status", "type": "=", "value": "succeeded"}])},
    )
    assert status_filter.status_code == 200
    assert [row["id"] for row in status_filter.json()["tasks"]] == ["job_taskgrid_leaf"]

    scoped_filter = client.get("/tasks/status", params={"task_type": "appliance-update"})
    assert scoped_filter.status_code == 200
    scoped_payload = scoped_filter.json()
    assert [row["id"] for row in scoped_payload["tasks"]] == ["job_taskgrid_leaf"]
    assert scoped_payload["active_count"] == 0
    assert scoped_payload["filtered_count"] == 1
    assert scoped_payload["total_count"] == 1

    scoped_selected = client.get(
        "/tasks/status",
        params={"task_type": "appliance-update", "job_id": "job_taskgrid001"},
    )
    assert scoped_selected.status_code == 200
    assert scoped_selected.json()["selected_task"] is None

    invalid_task_type = client.get("/tasks/status", params={"task_type": "x" * 101})
    assert invalid_task_type.status_code == 400

    invalid_filter = client.get(
        "/tasks/status",
        params={"filters": json.dumps([{"field": "error", "type": "regex", "value": ".*"}])},
    )
    assert invalid_filter.status_code == 400
    assert "_children" not in failed_step

    log_response = client.get("/tasks/job_taskgrid001/log")
    assert log_response.status_code == 200
    log_payload = log_response.json()
    assert "uploading-disk1.vmdk" in log_payload["text"]
    assert "VMware01!" not in log_payload["text"]
    assert "[redacted]" in log_payload["text"]

    csrf = page.text.split('data-csrf="', 1)[1].split('"', 1)[0]
    cancel_response = client.post("/tasks/job_taskgrid001/cancel", data={"csrf": csrf})
    assert cancel_response.status_code == 200
    assert cancel_response.json()["task"]["status"] == "cancelled"

    status_response = client.get("/tasks/status?job_id=job_taskgrid001")
    assert status_response.json()["selected_task"]["can_cancel"] is False


def test_service_admin_task_cancellation_is_limited_to_vcf_helpers(client):
    """Verify that service admin task cancellation is limited to vcf helpers.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.SERVICE_ADMIN.value
        admin.roles_json = roles_to_json([Role.SERVICE_ADMIN.value])
        db.add_all(
            [
                Job(
                    id="job_admin_only_cancel",
                    type="appliance-update",
                    status=JobStatus.RUNNING.value,
                    created_by="admin",
                    progress_percent=10,
                ),
                Job(
                    id="job_vcf_helper_cancel",
                    type="vcf-ca-trust",
                    status=JobStatus.RUNNING.value,
                    created_by="admin",
                    progress_percent=10,
                ),
            ]
        )
        db.commit()

    login(client)
    page = client.get("/tasks")
    assert page.status_code == 200
    csrf = page.text.split('data-csrf="', 1)[1].split('"', 1)[0]

    denied = client.post("/tasks/job_admin_only_cancel/cancel", data={"csrf": csrf})
    assert denied.status_code == 403
    assert "Administrator role required for this task type" in denied.text

    allowed = client.post("/tasks/job_vcf_helper_cancel/cancel", data={"csrf": csrf})
    assert allowed.status_code == 200
    assert allowed.json()["task"]["status"] == "cancelled"


def test_pwa_manifest_service_worker_and_offline_shell(client):
    """Verify that pwa manifest service worker and offline shell.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    manifest = client.get("/manifest.webmanifest")
    assert manifest.status_code == 200
    assert manifest.headers["content-type"].startswith("application/manifest+json")
    assert manifest.headers["cache-control"] == "no-cache"
    manifest_json = manifest.json()
    assert manifest_json["name"] == "Atlaso"
    assert manifest_json["short_name"] == "Atlaso"
    assert manifest_json["id"] == "/ui/management"
    assert manifest_json["start_url"] == "/ui/management/dashboard"
    assert manifest_json["scope"] == "/ui/management/"
    assert manifest_json["display"] == "standalone"
    assert manifest_json["launch_handler"] == {"client_mode": "navigate-existing"}
    assert manifest_json["background_color"] == "#071A3A"
    assert manifest_json["theme_color"] == "#1769E0"
    assert manifest_json["icons"][0]["src"] == "/static/brand/atlaso-app-icon-dark-192.png"
    assert manifest_json["icons"][1]["src"] == "/static/brand/atlaso-app-icon-dark-512.png"
    assert manifest_json["icons"][0]["purpose"] == "any maskable"

    service_worker = client.get("/service-worker.js")
    assert service_worker.status_code == 200
    assert service_worker.headers["content-type"].startswith("application/javascript")
    assert service_worker.headers["cache-control"] == "no-cache"
    assert service_worker.headers["service-worker-allowed"] == "/ui/management/"
    assert "ATLASO_CACHE" in service_worker.text
    assert "atlaso-management-pwa-v258" in service_worker.text
    assert 'fetch(asset, { cache: "reload" })' in service_worker.text
    assert ".catch(() => undefined)" in service_worker.text
    assert 'request.mode === "navigate"' in service_worker.text
    assert 'url.pathname.startsWith("/ui/management/")' in service_worker.text
    assert 'caches.match("/static/offline.html")' in service_worker.text
    assert 'request.method !== "GET"' in service_worker.text
    assert 'url.pathname.startsWith("/ca/downloads/")' in service_worker.text
    assert 'url.pathname.startsWith("/certificate-authority/downloads/")' in service_worker.text
    assert 'url.pathname.startsWith("/api/")' in service_worker.text
    assert "hasDownloadLikePath(url)" in service_worker.text
    assert 'accept.includes("text/html")' in service_worker.text
    assert '!hasDownloadLikePath(url)' in service_worker.text
    assert "/static/vendor/monaco/atlaso-monaco.min.js?v=atlaso-monaco-20260806-7" in service_worker.text
    assert "/static/app.css?v=network-boot-lifecycle-430-432-20260820-1" in service_worker.text
    assert "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-8" in service_worker.text
    assert "/static/appliance-apply-polling.js?v=issue-294-2" in service_worker.text
    assert "/static/ui-routes.js?v=issue-287-1" in service_worker.text
    assert "/static/app.js?v=network-boot-lifecycle-430-432-20260820-1" in service_worker.text
    assert "/static/terminal.js?v=issue-287-2" in service_worker.text
    assert "/static/pwa.js?v=issue-287-2" in service_worker.text
    assert "vcfdt-configuration-248-20260807-14" not in service_worker.text

    registration = client.get("/static/pwa.js")
    assert registration.status_code == 200
    assert "navigator.serviceWorker.getRegistrations()" in registration.text
    assert "registration.scope === legacyScope" in registration.text
    assert "registration.unregister()" in registration.text
    assert registration.text.index("registration.unregister()") < registration.text.index("navigator.serviceWorker.register")
    assert 'navigator.serviceWorker.register("/service-worker.js", { scope: managementScope })' in registration.text

    offline = client.get("/static/offline.html")
    assert offline.status_code == 200
    assert "Appliance connection unavailable" in offline.text
    assert "/static/app.css?v=issue-338-1" in offline.text


def test_shared_ui_pattern_shell_and_wizard_contracts(client):
    """Verify that shared ui pattern shell and wizard contracts.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re
    from pathlib import Path

    templates = Path("atlaso/app/templates")
    base = (templates / "base.html").read_text(encoding="utf-8")
    public_base = (templates / "public_portal_base.html").read_text(encoding="utf-8")
    for shell, app_asset in (
        (base, "/static/app.js?v=network-boot-lifecycle-430-432-20260820-1"),
        (public_base, "/static/app.js?v=network-boot-lifecycle-430-432-20260820-1"),
        (base, "/static/appliance-apply-polling.js?v=issue-294-2"),
    ):
        assert shell.index("/static/vendor/tabulator/tabulator.min.js") < shell.index(
            "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-8"
        )
        assert shell.index(
            "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-8"
        ) < shell.index(app_asset)

    wizard_templates = [
        templates / "automation.html",
        templates / "esx_storage.html",
        templates / "routes_wan.html",
        templates / "vlan_interfaces.html",
        templates / "vcf_offline_depot.html",
        templates / "partials" / "vcf_trust_modal.html",
        templates / "partials" / "vcf_sddc_deploy_modal.html",
        templates / "partials" / "vcf_target_depot_modal.html",
    ]
    wizard_markup = "\n".join(
        path.read_text(encoding="utf-8") for path in wizard_templates
    )
    assert len(re.findall(r"<form\b[^>]*\bdata-atlaso-wizard(?:\s|>)", wizard_markup)) == 7
    for marker in (
        "data-atlaso-wizard-step=",
        "data-atlaso-wizard-nav=",
        "data-atlaso-wizard-cancel",
        "data-atlaso-wizard-back",
        "data-atlaso-wizard-next",
        "data-atlaso-wizard-submit",
        "data-atlaso-wizard-error",
    ):
        assert wizard_markup.count(marker) >= 6

    foundation = client.get("/static/ui-patterns.js")
    assert foundation.status_code == 200
    assert "global.AtlasoUiPatterns" in foundation.text
    assert "createGrid" in foundation.text
    assert "createWizard" in foundation.text
    assert "button:not([disabled]):not([tabindex='-1'])" in foundation.text
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert 'control.setAttribute("tabindex", "-1")' in app_js.text
    assert 'event.target.closest(".help-icon")' in app_js.text
    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200
    assert "height: min(720px, calc(100vh - 48px));" in app_css.text
    assert ".vcf-sddc-wizard-body [data-atlaso-wizard-step] {" in app_css.text
    assert ".vcf-sddc-wizard-body [data-atlaso-wizard-step] > .form-stack {" in app_css.text


def test_persisted_tabulator_formatter_text_safety_contract():
    """Verify accepted persisted text is escaped at the affected grid formatter sinks."""
    from atlaso.app.services.esx_storage import normalize_relative_path
    from atlaso.app.services.esxi_pxe import normalize_kickstart_name

    hostile_path = '<img src=x onerror="globalThis.pathInjected=true">'
    hostile_name = '<img src=x onerror="globalThis.kickstartInjected=true">'
    assert normalize_relative_path(hostile_path) == hostile_path
    assert normalize_kickstart_name(hostile_name) == hostile_name

    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    assert 'field: "relative_path", formatter: esxStoragePathFormatter' in app_js
    assert "formatter: (cell) => esxiHostKickstartFormatter(cell, kickstartValues)" in app_js
    assert 'return cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue());' in app_js
    assert 'escapeHtml(kickstartValues[cell.getValue()] || "No Kickstart")' in app_js


def test_every_existing_tabulator_uses_the_shared_grid_foundation(client):
    """Verify that every existing tabulator uses the shared grid foundation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re

    app_js = client.get("/static/app.js").text
    create_grid = "window.AtlasoUiPatterns.createGrid({"

    assert app_js.count(create_grid) == 40
    assert app_js.count('pattern: "direct-edit"') == 8
    assert app_js.count('pattern: "read-only"') == 16
    assert app_js.count('pattern: "wizard-backed"') == 16
    assert "new Tabulator(" not in app_js
    assert "new window.Tabulator(" not in app_js
    assert "atlaso-legacy-tabulator: #117" not in app_js

    def function_block(name):
        """Return function block.

        Args:
            name: Stable name identifying the resource or operation.
        """
        start = app_js.index(f"function {name}(")
        match = re.search(r"\n(?:async )?function ", app_js[start + 1:])
        end = len(app_js) if match is None else start + 1 + match.start()
        return app_js[start:end]

    single_grid_patterns = {
        "initializeDhcpLeasesTable": "read-only",
        "initializeManagedFirewallRulesTable": "direct-edit",
        "initializeServicesTable": "direct-edit",
        "initializeNTPsecUpstreamsTable": "wizard-backed",
        "initializeRoutesWanRoutingTable": "wizard-backed",
        "initializeRoutesWanNatTable": "wizard-backed",
        "initializeRoutesWanRoutesTable": "wizard-backed",
        "initializeRoutesWanPoliciesTable": "wizard-backed",
        "initializePhysicalInterfacesTable": "direct-edit",
        "initializeOidcGroupMappingsTable": "direct-edit",
        "initializeVlanInterfacesTable": "wizard-backed",
        "initializeDnsRecordsTableElement": "direct-edit",
        "initializeDhcpReservationsTable": "direct-edit",
        "initializeEsxiPxeHostsTable": "wizard-backed",
        "initializeEsxiInstallerIsosTable": "wizard-backed",
        "initializeEsxiPxePreviewTable": "read-only",
        "initializeTasksPage": "read-only",
        "initializeAuditEventsTable": "read-only",
        "initializeCaRequestsTable": "read-only",
        "initializeDepotBrowserTable": "read-only",
        "renderApplianceApplyTask": "read-only",
    }
    for name, pattern in single_grid_patterns.items():
        block = function_block(name)
        assert block.count(create_grid) == 1, name
        assert block.count(f'pattern: "{pattern}"') == 1, name

    monitor_tables = function_block("initializeMonitorDetailTables")
    assert monitor_tables.count(create_grid) == 2
    assert monitor_tables.count('pattern: "read-only"') == 2

    host_wizard = function_block("initializeEsxiHostReferenceWizard")
    assert host_wizard.count(create_grid) == 1
    assert host_wizard.count('pattern: "direct-edit"') == 1

    network_boot = function_block("initializeNetworkBootPage")
    assert network_boot.count(create_grid) == 2
    assert network_boot.count('pattern: "direct-edit"') == 1
    assert network_boot.count('pattern: "read-only"') == 1
    assert 'data-network-boot-action="download"' not in network_boot
    assert 'data-network-boot-action="upload"' not in network_boot
    assert 'title: "Actions"' not in network_boot
    assert "/api/v1/network-boot/environments/${environmentKey}/upload" in network_boot
    assert 'component.getData().enabled ? "Disable" : "Enable"' in network_boot
    assert '"Download latest (already installed)"' in network_boot
    assert "networkBootEnvironmentHasLatestInstalled(component.getData())" in network_boot
    assert 'label: "Upload release asset"' in network_boot
    assert 'title: "Source"' in network_boot
    assert 'title: "Latest available"' in network_boot
    assert 'field: "available_version"' in network_boot
    assert "/api/v1/network-boot/environments/available-versions" in network_boot
    assert 'field: "source_label"' in network_boot
    assert 'new URL(data.release_page)' in network_boot
    assert 'source.protocol !== "https:"' in network_boot
    assert "toggleEnvironmentFromMenu(row)" in network_boot
    assert 'document.addEventListener("atlaso:tasks-refreshed"' in network_boot
    assert 'networkBootRequest("/api/v1/network-boot/environments")' in network_boot
    assert "row.getData().key === \"inventory\"" not in network_boot
    network_boot_workspace = function_block("initializeNetworkBootWorkspace")
    assert "networkSlot.append(networkSection)" in network_boot_workspace
    assert "networkSlot.append(tasksPanel)" not in network_boot_workspace
    assert "kickstartsSlot.append(kickstartsSection)" in network_boot_workspace
    assert "staticRail.append(bootService)" in network_boot_workspace

    adapter_block = function_block("initializeAtlasoResourceWizard")
    assert adapter_block.count(create_grid) == 1
    assert adapter_block.count('pattern: "wizard-backed"') == 1
    assert "window.AtlasoUiPatterns.createWizard({" in adapter_block
    assert "await table.addRow(resource, true, config.newRow.id)" in adapter_block
    assert "await Promise.resolve(config.onSaved?.({ payload, resource, form, table }))" in adapter_block
    assert "await Promise.resolve(config.onDeleted?.({ data, table }))" in adapter_block
    assert 'toggle.className = "inline-boolean-toggle"' in adapter_block
    assert 'toggle.addEventListener("click", (event) =>' in adapter_block
    assert "const previousValue = Boolean(cell.getValue())" in adapter_block
    assert "cell.setValue(!previousValue)" in adapter_block
    assert "void saveInlineEnabled(cell, previousValue)" in adapter_block
    assert "cell.setValue(previousValue)" in adapter_block
    assert adapter_block.count("await refreshNetworkSideStack();") == 3
    for name in (
        "initializeApiTokensTable",
        "initializeCaProfilesTable",
        "initializeCaCertificatesTable",
        "initializeFirewallRulesTable",
        "initializeVsphereKeyProviderTables",
        "initializeDhcpScopesTable",
        "initializeDhcpOptionsTable",
        "initializeUsersTable",
        "initializeVcfRegistryBundlesTable",
        "initializeVcfDepotProfilesTable",
        "initializeEsxiCustomVariablesTable",
    ):
        block = function_block(name)
        assert "initializeAtlasoResourceWizard({" in block, name
        assert 'editor:' not in block, name
        assert "cellEdited:" not in block, name

    ldap_block = function_block("initializeLdapDirectoryTables")
    assert ldap_block.count(create_grid) == 0
    assert ldap_block.count("initializeAtlasoResourceWizard({") == 2
    assert ldap_block.count("inlineEnabled: false") == 1
    assert ldap_block.count('editor: "tickCross"') == 1
    assert ldap_block.count("autoSaveLdapGroup(cell, csrf, organizationId)") == 1

    automation_block = function_block("initializeAutomationTables")
    assert automation_block.count(create_grid) == 3
    assert automation_block.count('pattern: "direct-edit"') == 0
    assert automation_block.count('pattern: "read-only"') == 1
    assert automation_block.count('pattern: "wizard-backed"') == 2

    storage_block = function_block("initializeEsxStorageTables")
    assert storage_block.count(create_grid) == 2
    assert storage_block.count('pattern: "wizard-backed"') == 2

    kickstart_block = function_block("initializeKickstartCollection")
    assert kickstart_block.count(create_grid) == 1
    assert kickstart_block.count('pattern: "read-only"') == 1
    assert "initializeAtlasoResourceWizard({" in kickstart_block

    custom_variables_block = function_block("initializeEsxiCustomVariablesTable")
    assert custom_variables_block.count(create_grid) == 1
    assert custom_variables_block.count('pattern: "read-only"') == 1
    assert "initializeAtlasoResourceWizard({" in custom_variables_block
    assert "includeNewRow: false" not in custom_variables_block
    assert "addLauncherSelector:" not in custom_variables_block
    assert "data-atlaso-wizard-add" in custom_variables_block
    assert "+ Add custom variable here" in custom_variables_block
    assert 'rowFormatter: (row) => markNewRecordRow(row, "name")' in custom_variables_block
    assert 'editLabel: "Edit"' in custom_variables_block
    assert 'deleteLabel: "Remove"' in custom_variables_block
    assert 'confirmLabel: "Remove custom variable"' in custom_variables_block
    assert "autoSaveEsxiCustomVariable" not in custom_variables_block

    tasks_block = function_block("initializeTasksPage")
    assert "atlasoTasksReopenSelected = shouldOpenSelected;" in tasks_block
    assert "if (!atlasoTasksTable) {" in tasks_block


def test_primary_resource_table_templates_use_shared_read_only_grids():
    """Verify that primary resource table templates use shared read only grids."""
    from pathlib import Path

    templates = Path("atlaso/app/templates")
    expected = {
        "ca_requests.html": (("ca-requests-table", "ca-requests-fallback"),),
        "ca_request_portal.html": (("ca-requests-table", "ca-requests-fallback"),),
        "monitor.html": (
            ("monitor-network-table", "monitor-network-fallback"),
            ("monitor-disk-activity-table", "monitor-disk-activity-fallback"),
        ),
        "depot_browser.html": (("depot-browser-table", "depot-browser-fallback"),),
    }
    for template_name, grids in expected.items():
        source = (templates / template_name).read_text(encoding="utf-8")
        for grid_id, fallback_id in grids:
            assert f'id="{grid_id}"' in source
            assert f'data-fallback-id="{fallback_id}"' in source
            assert f'id="{fallback_id}"' in source

    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    for initializer in ("initializeCaRequestsTable", "initializeDepotBrowserTable", "initializeMonitorDetailTables"):
        assert f"function {initializer}(" in app_js
    assert 'link.textContent = data.name;' in app_js
    assert 'placeholder: "No depot content is available in this directory."' in app_js
    assert 'placeholder: "No interfaces sampled."' in app_js
    assert 'placeholder: "No devices sampled."' in app_js
    assert 'monitorNetworkTable.replaceData(monitorNetworkRows(payload.networks))' in app_js
    assert 'monitorDiskActivityTable.replaceData(Array.isArray(payload.disk_devices)' in app_js

    reviewed_semantic_summaries = {
        ("backup_restore.html", '<table class="data-table compact">'),
        ("dhcp.html", '<table class="data-table compact generated-options-table">'),
        ("dns.html", '<table class="data-table compact">'),
        ("vcf_helper.html", '<table class="data-table compact vcf-fqdn-table">'),
    }
    remaining_native_tables = set()
    for path in templates.rglob("*.html"):
        relative = path.relative_to(templates).as_posix()
        for table_tag in re.findall(r"<table\b[^>]*>", path.read_text(encoding="utf-8")):
            if "fallback" in table_tag:
                continue
            remaining_native_tables.add((relative, table_tag))
    assert remaining_native_tables == reviewed_semantic_summaries

    for migrated_template in ("authentication.html", "esxi_pxe.html"):
        table_tags = re.findall(
            r"<table\b[^>]*>",
            (templates / migrated_template).read_text(encoding="utf-8"),
        )
        assert table_tags
        assert all("fallback" in table_tag for table_tag in table_tags)


def test_complex_resource_wizard_grid_contracts_return_saved_rows_and_delete_without_reload(client):
    """Verify that complex resource wizard grid contracts return saved rows and delete without reload.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/authentication")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    headers = {"X-Atlaso-Grid": "1"}

    token_response = client.post(
        "/authentication/api-tokens",
        data={"name": "wizard-token", "description": "issue 118", "scopes": "read:dashboard", "csrf": csrf},
        headers=headers,
    )
    assert token_response.status_code == 200
    token_payload = token_response.json()
    assert token_payload["token"]["name"] == "wizard-token"
    assert token_payload["raw_token"]

    profile_data = {
        "name": "Wizard server profile",
        "certificate_type": "server",
        "validity_days": "365",
        "key_algorithm": "RSA",
        "key_size": "2048",
        "key_usage": "digitalSignature,keyEncipherment",
        "extended_key_usage": "serverAuth",
        "san_required": "on",
        "description": "issue 118",
        "enabled": "on",
        "csrf": csrf,
    }
    profile_response = client.post("/certificate-authority/profiles", data=profile_data, headers=headers)
    assert profile_response.status_code == 200
    profile = profile_response.json()["profile"]
    assert profile["name"] == "Wizard server profile"

    certificate_data = {
        "common_name": "wizard.atlaso.internal",
        "profile_id": str(profile["id"]),
        "subject_alt_names": "wizard.atlaso.internal",
        "ip_addresses": "",
        "description": "issue 118",
        "enabled": "on",
        "csrf": csrf,
    }
    certificate_response = client.post(
        "/certificate-authority/certificates",
        data=certificate_data,
        headers=headers,
    )
    assert certificate_response.status_code == 200
    certificate = certificate_response.json()["certificate"]
    assert certificate["common_name"] == "wizard.atlaso.internal"

    firewall_data = {
        "name": "wizard-firewall",
        "direction": "input",
        "action": "accept",
        "protocol": "tcp",
        "source": "any",
        "destination": "any",
        "destination_port": "9443",
        "interface_name": "eth2",
        "priority": "118",
        "enabled": "on",
        "description": "issue 118",
        "csrf": csrf,
    }
    firewall_response = client.post("/firewall/rules", data=firewall_data, headers=headers)
    assert firewall_response.status_code == 200
    firewall_rule = firewall_response.json()["rule"]
    assert firewall_rule["name"] == "wizard-firewall"

    provider_data = {
        "name": "Wizard vSphere provider",
        "description": "issue 118",
        "csrf": csrf,
    }
    provider_response = client.post(
        "/vsphere-key-providers/providers",
        data=provider_data,
        headers=headers,
    )
    assert provider_response.status_code == 200
    provider = provider_response.json()["provider"]
    assert provider["name"] == "Wizard vSphere provider"
    duplicate_provider = client.post(
        "/vsphere-key-providers/providers",
        data=provider_data,
        headers=headers,
    )
    assert duplicate_provider.status_code == 409
    assert duplicate_provider.json()["detail"] == "Provider name already exists."

    vcenter_data = {
        "provider_id": provider["id"],
        "name": "Wizard vCenter",
        "hostname": "vcsa-wizard.atlaso.internal",
        "description": "issue 118",
        "certificate_pem": "",
        "csrf": csrf,
    }
    vcenter_response = client.post(
        "/vsphere-key-providers/trusted-vcenters",
        data=vcenter_data,
        headers=headers,
    )
    assert vcenter_response.status_code == 200
    trusted_vcenter = vcenter_response.json()["trusted_vcenter"]
    assert trusted_vcenter["provider_id"] == provider["id"]

    invalid_vcenter = client.post(
        "/vsphere-key-providers/trusted-vcenters",
        data={
            **vcenter_data,
            "name": "Invalid wizard vCenter",
            "hostname": "https://vcsa-wizard.atlaso.internal",
        },
        headers=headers,
    )
    assert invalid_vcenter.status_code == 400
    assert invalid_vcenter.json()["detail"] == "The trusted vCenter details or public certificate are invalid."

    invalid_certificate = client.post(
        f"/vsphere-key-providers/trusted-vcenters/{trusted_vcenter['id']}/certificates",
        data={
            "provider_id": provider["id"],
            "certificate_pem": "-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----",
            "csrf": csrf,
        },
        headers=headers,
    )
    assert invalid_certificate.status_code == 400
    assert invalid_certificate.json()["detail"] == "The public certificate is invalid."
    assert "forbidden" not in invalid_certificate.text

    scope_data = {
        "name": "WizardZone",
        "address_family": "ipv4",
        "interface_name": "eth2",
        "site_address": "192.168.50.1",
        "prefix_length": "24",
        "range_expression": "192.168.50.150-192.168.50.175",
        "lease_time": "8h",
        "domain_name": "atlaso.internal",
        "dns_server": "192.168.50.1",
        "ntp_server": "192.168.50.1",
        "description": "issue 118",
        "enabled": "on",
        "csrf": csrf,
    }
    scope_response = client.post("/dhcp/scopes", data=scope_data, headers=headers)
    assert scope_response.status_code == 200
    scope = scope_response.json()["scope"]
    assert scope["name"] == "WizardZone"

    bundle_data = {
        "name": "wizard-supervisor-service",
        "source_reference": "docker.io/example/service:1.0",
        "target_reference": "",
        "status": "planned",
        "notes": "issue 118",
        "enabled": "on",
        "csrf": csrf,
    }
    bundle_response = client.post("/vcf-private-registry/bundles", data=bundle_data, headers=headers)
    assert bundle_response.status_code == 200
    bundle = bundle_response.json()["bundle"]
    assert bundle["target_reference"].endswith("/vcf-supervisor-services/service")

    depot_data = {
        "name": "wizard-vcfdt-profile",
        "profile_type": "binaries",
        "sku": "VCF",
        "vcf_version": "9.1.0",
        "binary_type": "INSTALL",
        "automated_install": "on",
        "component": "",
        "component_version": "",
        "disabled_platforms": "",
        "status": "planned",
        "notes": "issue 118",
        "csrf": csrf,
    }
    depot_response = client.post("/vcf-offline-depot/profiles", data=depot_data, headers=headers)
    assert depot_response.status_code == 200
    depot_profile = depot_response.json()["profile"]
    assert depot_profile["name"] == "wizard-vcfdt-profile"
    assert depot_profile["enabled"] is False

    edit_scope = client.post(
        f"/dhcp/scopes/{scope['id']}/edit",
        data={**scope_data, "description": "edited in the open wizard"},
        headers=headers,
    )
    assert edit_scope.status_code == 200
    assert edit_scope.json()["scope"]["description"] == "edited in the open wizard"

    for url in (
        f"/vcf-offline-depot/profiles/{depot_profile['id']}/delete",
        f"/vcf-private-registry/bundles/{bundle['id']}/delete",
        f"/dhcp/scopes/{scope['id']}/delete",
        f"/vsphere-key-providers/trusted-vcenters/{trusted_vcenter['id']}/delete",
        f"/firewall/rules/{firewall_rule['id']}/delete",
        f"/certificate-authority/certificates/{certificate['id']}/delete",
        f"/certificate-authority/profiles/{profile['id']}/delete",
    ):
        deleted = client.post(url, data={"csrf": csrf}, headers=headers)
        assert deleted.status_code == 204, url

    revoked = client.post(
        f"/authentication/api-tokens/{token_payload['token']['id']}/revoke",
        data={"csrf": csrf},
        headers=headers,
    )
    assert revoked.status_code == 200
    assert revoked.json()["token"]["status"] == "revoked"


def test_reported_template_accessibility_contracts():
    """Verify that reported template accessibility contracts."""
    from pathlib import Path

    templates = Path("atlaso/app/templates")
    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    appliance_update = (templates / "appliance_update.html").read_text(encoding="utf-8")
    logs = (templates / "logs.html").read_text(encoding="utf-8")
    ldap = (templates / "ldap.html").read_text(encoding="utf-8")
    esxi_pxe = (templates / "esxi_pxe.html").read_text(encoding="utf-8")
    vcf_depot = (templates / "vcf_offline_depot.html").read_text(encoding="utf-8")
    dns = (templates / "dns.html").read_text(encoding="utf-8")
    authentication = (templates / "authentication.html").read_text(encoding="utf-8")
    firewall = (templates / "firewall.html").read_text(encoding="utf-8")
    resource_wizard = (templates / "partials" / "resource_wizard.html").read_text(encoding="utf-8")

    assert 'aria-selected="{{' not in appliance_update
    assert "Recorded release, compatibility, and recovery evidence" in appliance_update
    assert '{% set preview_label = "Appliance update evidence" %}' in appliance_update
    assert '{% set preview_title = "Appliance Update evidence" %}' in appliance_update
    assert '<pre><code class="language-json">{{ update_info_file.content }}</code></pre>' not in appliance_update
    assert 'aria-selected="{{' not in logs
    assert 'aria-disabled="{{' not in logs
    assert 'aria-selected="{{' not in ldap
    assert 'aria-label="ESXi PXE hostname"' in esxi_pxe
    assert 'aria-label="Installer ISO for ESXi PXE host"' in esxi_pxe
    assert 'aria-label="Enable ESXi PXE host"' in esxi_pxe
    assert '"vcf-depot-tool-package-form"' in vcf_depot
    assert '<span class="file-upload-control"><input class="file-upload-input" type="file" name="tool_archive_file"' in vcf_depot
    assert '<div class="dns-authority-records" role="list">' in dns
    assert '<dl class="dns-authority-records">' not in dns
    assert '<div class="error-list" role="list" data-oidc-provider-validation-errors>' in authentication
    assert '<ul class="error-list">' not in authentication
    state_step = firewall[
        firewall.index('data-atlaso-wizard-step="state"'):
        firewall.index('data-atlaso-wizard-step="enablement"')
    ]
    enablement_step = firewall[
        firewall.index('data-atlaso-wizard-step="enablement"'):
        firewall.index('data-atlaso-wizard-step="review"')
    ]
    assert 'name="priority"' in state_step
    assert 'name="description"' in state_step
    assert 'name="enabled"' not in state_step
    assert 'name="enabled"' in enablement_step
    assert "Enforcement waits for the global Firewall appliance-apply unit." in enablement_step
    assert 'aria-describedby="{{ dialog_id }}-description"' in resource_wizard
    assert "data-atlaso-wizard-error" in resource_wizard
    assert "data-atlaso-wizard-submit" in resource_wizard
    assert 'class="confirm-modal wide-modal vcf-sddc-wizard-modal resource-wizard-dialog"' in resource_wizard
    assert '<div class="vcf-sddc-wizard-main">' in resource_wizard
    assert '<div class="confirm-modal-body vcf-sddc-wizard-body">' in resource_wizard
    assert "vcf-sddc-wizard-layout" not in resource_wizard
    assert "vcf-sddc-wizard-content" not in resource_wizard
    assert '"dhcp-option-form"' in (templates / "dhcp.html").read_text(encoding="utf-8")
    assert 'data-atlaso-wizard-step="enablement"' in (templates / "dhcp.html").read_text(encoding="utf-8")
    assert 'name="scope_choices"' in authentication
    assert "<textarea name=\"scopes\"" not in authentication
    users_template = (templates / "users.html").read_text(encoding="utf-8")
    assert 'data-atlaso-wizard-step="password"' not in users_template
    assert 'data-atlaso-wizard-step="enablement"' not in users_template
    assert '<input type="checkbox" name="enabled" hidden>' in users_template
    assert "Set Photon OS password and enable user" in app_js
    assert "Reset Photon OS password" in app_js
    assert "cell.setValue(previousValue);" in app_js
    for template_name, form_marker in {
        "authentication.html": '"api-token-form"',
        "certificate_authority.html": '"ca-certificate-form"',
        "firewall.html": '"firewall-rule-form"',
        "kms.html": '"vsphere-provider-form"',
        "dhcp.html": '"dhcp-scope-form"',
        "users.html": '"user-account-form"',
        "ldap.html": '"ldap-organization-form"',
        "vcf_offline_depot.html": '"vcf-depot-profile-form"',
        "vcf_private_registry.html": '"vcf-registry-bundle-form"',
        "appliance_update.html": '"appliance-update-source-form"',
        "automation.html": '"automation-script-create-form"',
        "dns.html": '"dns-domain-form"',
        "routes_wan.html": '"routes-wan-wizard"',
    }.items():
        source = (templates / template_name).read_text(encoding="utf-8")
        assert "resource_wizard(" in source
        assert form_marker in source


def test_monitor_page_renders_template_and_browser_assets(client):
    """Verify that the Monitor template and browser assets retain their behavior.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)

    page = client.get("/monitor")
    assert page.status_code == 200
    assert "Monitor" in page.text
    assert "Virtual Machine" in page.text
    assert "CPU Utilization" in page.text
    assert "Network Throughput" in page.text
    assert "monitor-network-panel" in page.text
    assert "monitor-disk-activity-panel" in page.text
    assert "monitor-disk-usage-panel" not in page.text
    assert "Disk Usage" not in page.text
    assert "data-monitor-disk-current" not in page.text
    assert "data-monitor-disk-detail" not in page.text
    assert "Unprivileged control plane" not in page.text
    assert page.text.count("has-monitor-table") == 2
    assert 'data-monitor-page' in page.text
    assert page.text.count("data-monitor-chart-expand=") == 4
    assert page.text.count("data-monitor-range=") == 5
    assert 'data-monitor-range="12"' in page.text
    assert 'data-monitor-range="24"' in page.text
    assert "data-monitor-chart-modal" in page.text
    assert "data-monitor-expanded-chart" in page.text
    assert "data-monitor-chart-zoom-in" in page.text
    assert "data-monitor-chart-zoom-out" in page.text
    assert "data-monitor-chart-zoom-percent" in page.text
    assert "monitor-chart-zoom-field" in page.text
    assert "Changes the visible time-window magnification for this expanded chart only" in page.text
    assert "data-monitor-chart-zoom-reset" not in page.text
    assert 'id="monitor-network-table"' in page.text
    assert 'data-fallback-id="monitor-network-fallback"' in page.text
    assert 'id="monitor-network-fallback"' in page.text
    assert 'id="monitor-disk-activity-table"' in page.text
    assert 'data-fallback-id="monitor-disk-activity-fallback"' in page.text
    assert 'id="monitor-disk-activity-fallback"' in page.text
    assert "Loading interfaces" not in page.text
    assert "Loading devices" not in page.text
    assert "<th>Device</th><th>Read/s</th><th>Write/s</th>" in page.text
    assert "swagger-link-icon" in page.text
    assert "/static/app.css?v=network-boot-lifecycle-430-432-20260820-1" in page.text
    assert "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-8" in page.text
    assert "/static/app.js?v=network-boot-lifecycle-430-432-20260820-1" in page.text
    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200
    assert ".split-workspace > .wide-panel" in app_css.text
    assert "min-height: calc(100vh - 144px);" in app_css.text
    assert "padding: 22px 22px 41px;" in app_css.text
    assert ".swagger-link-icon" in app_css.text
    assert ".validation-preview-action" in app_css.text
    assert ".validation-preview-source" in app_css.text
    assert ".monitor-chart-panel.has-monitor-table" in app_css.text
    assert "grid-template-rows: auto auto minmax(0, auto);" in app_css.text
    assert ".monitor-network-panel,\n.monitor-disk-activity-panel" in app_css.text
    assert "align-self: stretch;" in app_css.text
    assert ".monitor-disk-usage-panel" not in app_css.text
    assert ".monitor-chart-zoom-controls" in app_css.text
    assert ".monitor-chart-zoom-field .help-icon::after" in app_css.text
    assert "position: absolute;" in app_css.text
    app_js = client.get("/static/app.js").text
    assert '{ name: "Total", points: payload.cpu, aggregate: true' in app_js
    assert '{ name: "Total", points: payload.network_totals, aggregate: true' in app_js
    assert '{ name: "Total", points: payload.disk_io, aggregate: true' in app_js
    assert "payload.disk_devices" in app_js
    assert 'diskUsage: "Disk Usage"' not in app_js
    assert "function renderMonitorDiskTable" not in app_js
    assert "disk.highest_used_percent" not in app_js
    assert "disk.highest_used_mount" not in app_js
    assert "disk.mount_count" not in app_js
    assert "(aggregate ? 3 : 1)" in app_js
    assert "(aggregate ? 0.45 : 1)" in app_js
    assert "Number(right.aggregate) - Number(left.aggregate)" in app_js
    assert "context.globalAlpha = highlighted ? 1 : Number(line.alpha || 1);" in app_js
    assert "function drawMonitorChartType(canvas, type, payload, chartOptions = {})" in app_js
    assert "modal.showModal();" in app_js
    assert "window.requestAnimationFrame(renderExpandedChart);" in app_js
    assert "if (event.target === modal) modal.close();" in app_js
    assert "const MONITOR_CHART_INTERACTIONS = new WeakMap();" in app_js
    assert 'canvas.addEventListener("pointermove"' in app_js
    assert 'canvas.addEventListener("pointerout", clearHighlight);' in app_js
    assert "distance <= 196" in app_js
    assert "Math.max(Number(line.lineWidth || 2) + 2, 4)" in app_js
    assert 'context.arc(highlightedPoint.x, highlightedPoint.y, 5' in app_js
    assert '`${highlighted ? "700 " : ""}11px system-ui, sans-serif`' in app_js
    assert "const viewSpan = fullSpan / Number(options.zoom);" in app_js
    assert "expandedZoomPercent = Math.min(800, expandedZoomPercent + 25);" in app_js
    assert "expandedZoomCenterTime = highlightedTime;" in app_js
    assert "expandedZoomPercent = Math.max(100, expandedZoomPercent - 25);" in app_js
    assert "Math.round((fullSpan / selectedSpan) * 100)" in app_js
    assert 'canvas.addEventListener("pointerdown"' in app_js
    assert 'canvas.addEventListener("pointerup", finishAreaSelection);' in app_js
    assert 'context.fillStyle = "rgba(37, 99, 235, 0.14)";' in app_js
    assert "function initializeMonitorDetailTables(root)" in app_js
    assert "function refreshMonitorDetailTables(payload)" in app_js
    assert "monitorNetworkTable.replaceData(monitorNetworkRows(payload.networks))" in app_js
    assert "monitorDiskActivityTable.replaceData" in app_js
    assert "payload.disk_devices" in app_js
    assert 'zoomPercentInput?.addEventListener("input"' in app_js
    assert 'if (event.key === "Enter") event.currentTarget.blur();' in app_js
    assert "function monitorNearestChartTarget(interaction, pointerX, pointerY)" in app_js
    assert "interaction.hitSegments.forEach" in app_js
    assert 'canvas.addEventListener("click"' in app_js
    assert "interaction.pinned = Boolean(target);" in app_js
    assert "interaction.legendTargets.find" in app_js
    assert "interaction.highlightedField !== legendTarget.line.field" in app_js

def test_login_page_includes_pwa_metadata(client):
    """Verify that login page includes pwa metadata.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    response = client.get("/login")
    assert response.status_code == 200
    assert '<link rel="manifest" href="/manifest.webmanifest">' in response.text
    assert '<meta name="mobile-web-app-capable" content="yes">' in response.text
    assert '<meta name="apple-mobile-web-app-capable" content="yes">' in response.text
    assert '<form class="form-stack" action="/ui/management/login" method="post" target="_self">' in response.text
    assert '<meta name="theme-color"' not in response.text
    assert "/static/pwa.js?v=issue-287-2" in response.text
    assert response.text.count("/static/brand/atlaso-logo-horizontal-transparent-1200x300.png") == 1
    assert 'alt="Atlaso — Infrastructure • Connectivity • Automation"' in response.text
    assert "Infrastructure appliance" not in response.text
    assert "Everything your virtualization lab needs." not in response.text
    assert "Infrastructure • Storage • Identity • Networking • Lifecycle" not in response.text


def test_shared_shells_use_current_mobile_web_app_metadata(client):
    """Verify that shared shells use current mobile web app metadata.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.ip_cidr = "192.168.87.32/24"
        db.commit()

    login(client)

    management = client.get("/dashboard")
    public = client.get("/ui/public", headers={"host": "192.168.87.32"})

    assert management.status_code == 200
    assert public.status_code == 200
    for response in (management, public):
        assert '<meta name="mobile-web-app-capable" content="yes">' in response.text
    assert '<link rel="manifest"' not in public.text
    assert "/static/pwa.js" not in public.text


def test_flagged_access_interface_cohosts_management_and_public_ui(client):
    """Verify access routing remains public while its optional management namespace is available.

    Args:
        client: Application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        eth2.admin_state = "up"
        eth2.oper_state = "up"
        eth2.access_management_ui_enabled = True
        db.commit()

    headers = {"host": "192.168.87.32"}
    root = client.get("/", headers=headers, follow_redirects=False)
    login_page = client.get("/ui/management/login", headers=headers)
    public = client.get("/ui/public", headers=headers)

    assert root.status_code == 303
    assert root.headers["location"] == "/ui/management"
    assert login_page.status_code == 200
    assert 'href="/ui/public"' in login_page.text
    assert public.status_code == 200


def test_unflagged_access_interface_hides_management_namespace(client):
    """Verify an ordinary access listener still returns not found for management UI routes.

    Args:
        client: Application test client fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        eth2.access_management_ui_enabled = False
        db.commit()

    response = client.get("/ui/management/login", headers={"host": "192.168.87.32"})

    assert response.status_code == 404


def test_unauthenticated_ui_request_redirects_to_login(client):
    """Verify that unauthenticated ui request redirects to login.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    response = client.get("/ui/management/certificate-authority", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/ui/management/login?next=/ui/management/certificate-authority"


def test_ui_session_is_rejected_after_appliance_instance_changes(client):
    """Verify that ui session is rejected after appliance instance changes.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.security import SESSION_APPLIANCE_INSTANCE_SETTING_KEY

    login(client)
    assert client.get("/dashboard").status_code == 200

    with SessionLocal() as db:
        setting = db.query(Setting).filter(Setting.key == SESSION_APPLIANCE_INSTANCE_SETTING_KEY).one()
        setting.value = "redeployed-appliance-instance"
        db.commit()

    response = client.get("/ui/management/vlan-interfaces", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/ui/management/login?next=/ui/management/vlan-interfaces"
    assert client.get("/", follow_redirects=False).headers["location"] == "/ui/management"


def test_sidebar_appliance_apply_uses_bottom_pending_cta(client):
    """Verify that sidebar appliance apply uses bottom pending cta.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    response = client.get("/certificate-authority")

    assert response.status_code == 200
    assert 'class="sidebar-apply-link pending' in response.text
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in response.text
    assert "data-appliance-apply-sidebar" in response.text
    assert "data-appliance-apply-open" in response.text
    assert "data-appliance-apply-sidebar-title" in response.text
    assert "data-appliance-apply-sidebar-detail" in response.text
    assert "data-appliance-apply-sidebar-badge" in response.text
    assert "Review appliance changes" in response.text
    assert "pending unit" in response.text
    assert 'class="nav-link " href="/appliance-apply"' not in response.text
    assert response.text.index("</nav>") < response.text.index("data-appliance-apply-sidebar")


def test_primary_navigation_omits_empty_permission_filtered_groups(client):
    """Verify that empty navigation groups expose no markup or browser-local state key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    login(client)
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.CERTIFICATE_OPERATOR.value
        admin.roles_json = roles_to_json([Role.CERTIFICATE_OPERATOR.value])
        db.commit()

    response = client.get("/ui/management/dashboard")
    assert response.status_code == 200
    nav = response.text.split('<nav class="nav-stack"', 1)[1].split("</nav>", 1)[0]
    assert 'data-nav-group-key="overview"' in nav
    assert 'data-nav-group-key="identity-trust"' in nav
    assert 'data-nav-group-key="vcf-workflows"' in nav
    assert 'data-nav-group-key="operations"' in nav
    assert 'data-nav-group-key="appliance-setup"' not in nav
    assert 'primary-nav-appliance-setup' not in nav
    assert 'data-nav-group-key="core-services"' not in nav
    assert 'primary-nav-core-services' not in nav


def test_primary_navigation_maps_secondary_routes_to_their_parent_link(client):
    """Verify that secondary management routes reveal their owning navigation group.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)

    ca_response = client.get("/ui/management/ca/requests")
    assert ca_response.status_code == 200
    ca_nav = ca_response.text.split('<nav class="nav-stack"', 1)[1].split("</nav>", 1)[0]
    assert '<section class="nav-section active" data-primary-nav-group data-nav-group-key="identity-trust">' in ca_nav
    assert 'href="/ui/management/certificate-authority" aria-current="page"' in ca_nav

    service_response = client.get("/ui/management/services/routing/logs")
    assert service_response.status_code == 200
    service_nav = service_response.text.split('<nav class="nav-stack"', 1)[1].split("</nav>", 1)[0]
    assert '<section class="nav-section active" data-primary-nav-group data-nav-group-key="operations">' in service_nav
    assert 'href="/ui/management/services" aria-current="page"' in service_nav


def test_primary_navigation_activates_ca_group_for_certificate_operator(client):
    """Verify that certificate operators see CA Requests in its active navigation group.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    login(client)
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.CERTIFICATE_OPERATOR.value
        admin.roles_json = roles_to_json([Role.CERTIFICATE_OPERATOR.value])
        db.commit()

    response = client.get("/ui/management/ca/requests")
    assert response.status_code == 200
    nav = response.text.split('<nav class="nav-stack"', 1)[1].split("</nav>", 1)[0]
    assert '<section class="nav-section active" data-primary-nav-group data-nav-group-key="identity-trust">' in nav
    assert 'href="/ui/management/certificate-authority"' not in nav






def test_service_dns_target_naming_converts_owned_records_between_ip_and_interface(client):
    """Verify that service dns target naming converts owned records between ip and interface.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsRecord, PhysicalInterface
    from atlaso.app.ui import (
        ensure_dns_for_vcf_registry,
        get_vcf_private_registry_settings_row,
    )

    login(client)
    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="eth9",
                mac_address="00:50:56:00:00:19",
                role="access",
                mode="access",
                ip_cidr="192.168.90.1/24",
                ipv6_cidr="2001:db8::1/64",
                admin_state="up",
                oper_state="up",
            )
        )
        db.flush()
        settings = get_vcf_private_registry_settings_row(db)
        settings.enabled = True
        settings.hostname = "registry.atlaso.internal"
        settings.listen_interface = "eth9"
        settings.listen_address = "192.168.90.1\n2001:db8::1"
        ensure_dns_for_vcf_registry(db, settings, "admin")
        db.commit()

        canonical = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry.atlaso.internal", DnsRecord.record_type == "CNAME")
        ).scalar_one()
        assert canonical.address == "registry-192-168-90-1.atlaso.internal"
        ipv4_target = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry-192-168-90-1.atlaso.internal", DnsRecord.record_type == "A")
        ).scalar_one()
        assert ipv4_target.address == "192.168.90.1"
        ipv6_target = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry-2001-db8-0-0-0-0-0-1.atlaso.internal", DnsRecord.record_type == "AAAA")
        ).scalar_one()
        assert ipv6_target.address == "2001:db8::1"
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "registry-eth9.atlaso.internal")).scalar_one_or_none() is None

        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.service_dns_target_naming = "interface"
        ensure_dns_for_vcf_registry(db, settings, "admin")
        db.commit()

        canonical = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry.atlaso.internal", DnsRecord.record_type == "CNAME")
        ).scalar_one()
        assert canonical.address == "registry-eth9.atlaso.internal"
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "registry-192-168-90-1.atlaso.internal")).scalar_one_or_none() is None
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "registry-2001-db8-0-0-0-0-0-1.atlaso.internal")).scalar_one_or_none() is None
        interface_targets = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry-eth9.atlaso.internal").order_by(DnsRecord.record_type)
        ).scalars().all()
        assert [(record.record_type, record.address) for record in interface_targets] == [("A", "192.168.90.1"), ("AAAA", "2001:db8::1")]

        appliance_settings.service_dns_target_naming = "ip"
        ensure_dns_for_vcf_registry(db, settings, "admin")
        db.commit()

        canonical = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry.atlaso.internal", DnsRecord.record_type == "CNAME")
        ).scalar_one()
        assert canonical.address == "registry-192-168-90-1.atlaso.internal"
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "registry-eth9.atlaso.internal")).scalar_one_or_none() is None
        assert db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry-2001-db8-0-0-0-0-0-1.atlaso.internal", DnsRecord.record_type == "AAAA")
        ).scalar_one().address == "2001:db8::1"


def test_stage_appliance_apply_config_repairs_staging_permission(monkeypatch, tmp_path):
    """Verify that stage appliance apply config repairs staging permission.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from types import SimpleNamespace

    from atlaso.app import ui

    attempts = {"count": 0}
    repairs: list[str] = []

    def fake_write(path, config_preview):
        """Handle fake write.

        Args:
            path: Filesystem or URL path to read, validate, or update.
            config_preview: Rendered configuration text approved for staging.

        Raises:
            PermissionError: If the operation lacks the required permission.
        """
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise PermissionError("blocked")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config_preview, encoding="utf-8")

    class FakeAdapter:
        """Represent fake adapter."""
        def prepare_apply_staging_path(self, path):
            """Return prepare apply staging path.

            Args:
                path: Filesystem or URL path to read, validate, or update.
            """
            repairs.append(path)
            return SimpleNamespace(returncode=0, stdout="prepared", stderr="")

    monkeypatch.setattr(ui, "_write_staged_config_file", fake_write)
    monkeypatch.setattr(ui, "SystemAdapter", FakeAdapter)

    config_path = tmp_path / "apply" / "wan" / "atlaso-wan.conf"
    result = ui.stage_appliance_apply_config(str(config_path), "config")

    assert result == str(config_path)
    assert repairs == [str(config_path)]
    assert attempts["count"] == 2
    assert config_path.read_text(encoding="utf-8") == "config"


def test_secret_staging_is_mode_0600_and_removed_after_adapter_failures(monkeypatch, tmp_path):
    """Verify that secret staging is mode 0600 and removed after adapter failures.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import json
    import stat
    from pathlib import Path
    from types import SimpleNamespace

    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult

    cases = [
        (
            "local_users",
            "LOCAL_USERS_STAGED_CONFIG_PATH",
            "validate_local_users_config",
            "apply_local_users_config",
            {"local_users": []},
        ),
        (
            "ca",
            "CA_STAGED_CONFIG_PATH",
            "validate_ca_config",
            "apply_ca_config",
            {"ca_settings": object(), "ca_certificates": []},
        ),
        (
            "ldap",
            "LDAP_STAGED_CONFIG_PATH",
            "validate_ldap_config",
            "apply_ldap_config",
            {"ldap_settings": SimpleNamespace(enabled=False), "ldap_organizations": []},
        ),
    ]

    for unit_id, path_attribute, validate_name, apply_name, context in cases:
        for failure_phase in ("validate", "apply"):
            staged_path = tmp_path / unit_id / failure_phase / f"atlaso-{unit_id}.json"
            secret = f"{unit_id}-{failure_phase}-Secret1!"
            calls: list[str] = []

            def run_step(phase: str, path: str) -> AdapterResult:
                """Run step.

                Args:
                    phase: Phase supplied by the caller.
                    path: Filesystem or URL path to read, validate, or update.

                Returns:
                    The run step result.
                """
                path_value = Path(path)
                calls.append(phase)  # noqa: B023 - the helper runs before this loop iteration advances.
                assert path_value == staged_path  # noqa: B023 - the helper runs before this loop iteration advances.
                if os.name != "nt":
                    assert stat.S_IMODE(path_value.stat().st_mode) == 0o600
                assert secret in path_value.read_text(encoding="utf-8")  # noqa: B023 - the helper runs before this loop iteration advances.
                failed = phase == failure_phase  # noqa: B023 - the helper runs before this loop iteration advances.
                return AdapterResult(
                    command=["atlaso-helper", unit_id, phase, path],  # noqa: B023 - the helper runs before this loop iteration advances.
                    dry_run=False,
                    stderr="sanitized failure" if failed else "",
                    returncode=1 if failed else 0,
                )

            adapter = SimpleNamespace(dry_run=False)
            setattr(adapter, validate_name, lambda path, phase="validate": run_step(phase, path))
            setattr(adapter, apply_name, lambda path, phase="apply": run_step(phase, path))
            monkeypatch.setattr(ui, path_attribute, str(staged_path))
            if unit_id == "ca":
                monkeypatch.setattr(
                    ui,
                    "render_ca_apply_payload",
                    lambda *_args, **_kwargs: json.dumps({"private_key_pem": secret}),  # noqa: B023 - invoked before the loop advances.
                )

            unit = {
                "id": unit_id,
                "label": unit_id,
                "context": context,
                "raw_config_preview": json.dumps({"password": secret}),
                "summary": ["test"],
                "validation_errors": [],
                "validation_warnings": [],
                "config_path": str(staged_path),
                "config_preview": '{"password":"[redacted]"}',
                "config_diff": "",
            }

            result = ui.execute_appliance_apply_unit(unit, adapter=adapter)

            assert result["success"] is False
            assert calls == (["validate"] if failure_phase == "validate" else ["validate", "apply"])
            assert not staged_path.exists()
            assert secret not in json.dumps(result)


def test_local_user_status_uses_isolated_short_lived_staging(monkeypatch, tmp_path):
    """Verify that local user status uses isolated short lived staging.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import stat
    from pathlib import Path

    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult

    active_apply_path = tmp_path / "local-users" / "atlaso-users.json"
    active_apply_path.parent.mkdir(parents=True)
    active_apply_path.write_text('{"password":"ActiveApplySecret1!"}', encoding="utf-8")
    active_apply_path.chmod(0o600)
    seen_status_paths: list[Path] = []

    class StatusAdapter:
        """Represent status adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        def local_users_status(self, config_path: str) -> AdapterResult:
            """Return local users status.

            Args:
                config_path: Filesystem path containing the operation configuration.
            """
            status_path = Path(config_path)
            seen_status_paths.append(status_path)
            assert status_path != active_apply_path
            assert status_path.is_file()
            if os.name != "nt":
                assert stat.S_IMODE(status_path.stat().st_mode) == 0o600
            assert "ActiveApplySecret1!" not in status_path.read_text(encoding="utf-8")
            return AdapterResult(
                command=["atlaso-helper", "local-users", "status", config_path],
                dry_run=False,
                stdout='{"local_users":"status ok","users":[]}',
            )

    monkeypatch.setattr(ui, "LOCAL_USERS_STAGED_CONFIG_PATH", str(active_apply_path))
    monkeypatch.setattr(ui, "SystemAdapter", StatusAdapter)

    assert ui.local_user_os_statuses([], {}) == {}
    assert len(seen_status_paths) == 1
    assert not seen_status_paths[0].exists()
    assert active_apply_path.read_text(encoding="utf-8") == '{"password":"ActiveApplySecret1!"}'


def test_appliance_apply_job_invalidates_projection_before_and_after_execution(client, monkeypatch):
    """Verify Apply invalidates sidebar state at both execution boundaries.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        settings = db.query(ApplianceSettings).one()
        settings.vmware_ceip_enabled = not settings.vmware_ceip_enabled
        db.commit()

    invalidations = []
    monkeypatch.setattr(ui, "invalidate_appliance_apply_status_projection", lambda: invalidations.append(True))
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "appliance_settings"},
    )

    assert_apply_redirect(response)
    assert len(invalidations) == 2


def test_appliance_apply_status_api_tracks_autosaved_desired_state(client):
    """Verify that appliance apply status api tracks autosaved desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()

    current = client.get("/appliance-apply/status")
    assert current.status_code == 200
    current_payload = current.json()
    assert {key: value for key, value in current_payload.items() if key != "units"} == {
        "pending_count": 0,
        "label": "Appliance Apply",
        "detail": "Desired state current",
        "badge": "current",
        "locked": False,
        "active_task": None,
    }
    assert current_payload["units"]
    assert all(not unit["changed"] for unit in current_payload["units"])

    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/settings",
        data={
            "enabled": "on",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2"],
            "listen_addresses": ["192.168.50.1"],
            "upstream_servers": "8.8.8.8",
            "cache_size": "500",
            "expand_hosts": "on",
            "authoritative": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    pending = client.get("/appliance-apply/status")
    assert pending.status_code == 200
    assert pending.json()["pending_count"] > 0
    assert pending.json()["label"] == "Review appliance changes"
    assert "pending unit" in pending.json()["detail"]
    assert pending.json()["badge"] == "pending"
    pending_count = pending.json()["pending_count"]
    pending_dns = next(unit for unit in pending.json()["units"] if unit["id"] == "dnsmasq")
    assert pending_dns["changed"] is True

    import inspect

    from atlaso.app import ui

    render_source = inspect.getsource(ui.render)
    assert "appliance_apply_units" not in render_source
    assert "context.get(\"appliance_apply_status\")" in render_source

    monitor = client.get("/monitor")
    assert monitor.status_code == 200
    assert "data-appliance-apply-sidebar" in monitor.text
    assert 'data-pending-count="0"' in monitor.text
    assert 'class="page-apply-notice' not in monitor.text
    assert "pending appliance units need review" not in monitor.text

    users = client.get("/users")
    assert users.status_code == 200
    assert "data-appliance-apply-sidebar" in users.text
    assert f'data-pending-count="{pending_count}"' in users.text
    assert 'class="page-apply-notice' not in users.text
    assert "pending appliance units need review" not in users.text

    dns_page = client.get("/dns")
    assert dns_page.status_code == 200
    assert "data-appliance-apply-sidebar" in dns_page.text
    assert 'data-pending-count="1"' in dns_page.text
    assert 'data-page-apply-unit="dnsmasq"' in dns_page.text
    assert "DNS/DHCP (dnsmasq) has pending appliance changes" in dns_page.text
    assert "Review and submit them from the global apply workflow." in dns_page.text

    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"dnsmasq"})
        db.commit()

    applied = client.get("/appliance-apply/status?refresh=true")
    assert applied.status_code == 200
    applied_dns = next(unit for unit in applied.json()["units"] if unit["id"] == "dnsmasq")
    assert applied_dns["changed"] is False

    apply_page = client.get("/ui/management/appliance-apply", follow_redirects=False)
    assert apply_page.status_code == 303
    assert apply_page.headers["location"] == "/ui/management/dashboard#appliance-apply-review"






def test_settings_autosave_enables_passwordless_terminal_on_management_interface(client):
    """Verify that settings autosave enables passwordless terminal on management interface.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings

    login(client)
    page = client.get("/settings")
    assert "Web terminal access" in page.text
    assert 'name="web_terminal_interfaces_present"' in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings",
        data={
            "fqdn": "core.atlaso.internal",
            "management_https_enabled": "on",
            "web_terminal_enabled": "on",
            "web_terminal_interfaces_present": "1",
            "web_terminal_interfaces": "eth0",
            "service_dns_target_naming": "ip",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["web_terminal_enabled"] is True
    assert payload["web_terminal_interfaces"] == ["eth0"]
    assert payload["web_terminal_addresses"] == ["192.168.49.1"]
    assert '"web_terminal_enabled": true' in payload["config_preview"]
    assert '"web_terminal_interfaces": [' in payload["config_preview"]

    refreshed = client.get("/settings")
    assert 'class="tag-token" data-value="eth0" data-tag-locked' in refreshed.text
    assert 'list="web-terminal-interface-options"' in refreshed.text
    assert 'class="tag-chip" data-tag-value=' not in refreshed.text
    app_js = client.get("/static/app.js")
    assert '.tag-token:not([data-tag-locked])' in app_js.text

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.web_terminal_enabled is True
        assert settings.web_terminal_interfaces_json == '["eth0"]'


def test_web_terminal_autosave_preserves_nts_state_and_apply_selection(client):
    """Verify that web terminal autosave preserves nts state and apply selection.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, NtpSettings
    from atlaso.app.services.ntp import ntp_settings_to_dict, render_ntp_config

    login(client)
    before_status = client.get("/appliance-apply/status").json()
    before_ntpd_status = next(unit for unit in before_status["units"] if unit["id"] == "ntpd")
    with SessionLocal() as db:
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        before_ntp_state = ntp_settings_to_dict(ntp_settings)
        before_rendered_config = render_ntp_config(ntp_settings)
        before_certificate_owners = [
            (row.id, row.managed_owner, row.common_name, row.enabled)
            for row in db.execute(
                select(CaCertificate)
                .where(CaCertificate.managed_owner == "ntp:nts")
                .order_by(CaCertificate.id)
            ).scalars()
        ]

    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings",
        data={
            "fqdn": "core.atlaso.internal",
            "management_https_enabled": "on",
            "web_terminal_enabled": "on",
            "web_terminal_interfaces_present": "1",
            "web_terminal_interfaces": "eth0",
            "service_dns_target_naming": "ip",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["web_terminal_enabled"] is True
    assert not any(key.startswith("ntp") or key.startswith("nts") for key in payload)

    with SessionLocal() as db:
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        assert ntp_settings_to_dict(ntp_settings) == before_ntp_state
        assert render_ntp_config(ntp_settings) == before_rendered_config
        after_certificate_owners = [
            (row.id, row.managed_owner, row.common_name, row.enabled)
            for row in db.execute(
                select(CaCertificate)
                .where(CaCertificate.managed_owner == "ntp:nts")
                .order_by(CaCertificate.id)
            ).scalars()
        ]
        assert after_certificate_owners == before_certificate_owners

    after_status = client.get("/appliance-apply/status").json()
    after_ntpd_status = next(unit for unit in after_status["units"] if unit["id"] == "ntpd")
    for key in ("id", "label", "state", "pill", "changed", "validation_errors"):
        assert after_ntpd_status[key] == before_ntpd_status[key]


def test_validation_rails_use_modal_config_previews(client):
    """Verify that validation rails use modal config previews.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    pages = {
        "/settings": ["data-appliance-settings-preview"],
        "/physical-interfaces": [],
        "/vlan-interfaces": [],
        "/routes-wan": [],
        "/firewall": ["data-firewall-config-preview"],
        "/dns": ["data-dns-config-preview"],
        "/dhcp": [],
        "/ntp": ["data-ntp-config-preview"],
        "/certificate-authority": ["data-ca-config-preview"],
        "/vsphere-key-providers": ["data-kms-config-preview"],
        "/esxi-pxe": ["data-esxi-pxe-preview"],
        "/vcf-offline-depot": ["data-vcf-depot-https-preview"],
        "/vcf-private-registry": ["data-vcf-registry-harbor-preview", "data-vcf-registry-relocation-preview"],
        "/vcf-backups": ["data-vcf-config-preview"],
    }

    for path, preview_hooks in pages.items():
        response = client.get(path)
        assert response.status_code == 200, path
        assert 'class="validation-preview-action"' in response.text, path
        assert "data-config-preview-open" in response.text, path
        assert "data-config-preview-source" in response.text, path
        for hook in preview_hooks:
            assert hook in response.text, path

        validation_markup = response.text.split("<h2>Validation</h2>", 1)[1].split("</aside>", 1)[0]
        assert 'class="terminal-note"' not in validation_markup, path
        assert 'class="config-preview"' not in validation_markup, path










def test_settings_autosave_updates_appliance_identity_dns_without_ntp(client):
    """Verify that settings autosave updates appliance identity dns without ntp.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsRecord, DnsSettings, NtpSettings

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = True
        db.commit()

    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings",
        data={
            "fqdn": "console.atlaso.internal",
            "root_ssh_enabled": "on",
            "service_dns_target_naming": "interface",
            "external_dns_servers": "8.8.8.8\n1.1.1.1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["fqdn"] == "console.atlaso.internal"
    assert payload["root_ssh_enabled"] is True
    assert payload["service_dns_target_naming"] == "interface"
    assert payload["external_dns_servers"] == ["8.8.8.8", "1.1.1.1"]
    assert "ntp_servers" not in payload
    assert payload["dns_record_action"] in {"created", "updated", "unchanged", "created+removed-old", "updated+removed-old"}
    assert payload["valid"] is True
    assert '"resolver_mode": "local_dns"' in payload["config_preview"]
    assert '"resolver_servers": [' in payload["config_preview"]
    assert '"127.0.0.1"' in payload["config_preview"]
    assert '"root_ssh_enabled": true' in payload["config_preview"]
    assert '"service_dns_target_naming": "interface"' in payload["config_preview"]
    assert "ntp_servers" not in payload["config_preview"]

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.fqdn == "console.atlaso.internal"
        assert settings.root_ssh_enabled is True
        assert settings.service_dns_target_naming == "interface"
        record = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "console.atlaso.internal", DnsRecord.record_type == "A")
        ).scalar_one()
        assert record.address == "192.168.49.1"
    assert "app-owned appliance FQDN" in (record.description or "")


def test_settings_autosave_does_not_update_ntp_servers_when_ntp_is_disabled(client):
    """Verify that settings autosave does not update ntp servers when ntp is disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, NtpSettings
    from atlaso.app.ui import appliance_apply_status

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = False
        db.add_all([dns_settings, ntp_settings])
        db.commit()

    page = client.get("/settings")
    assert "External NTP servers" not in page.text
    assert 'textarea name="ntp_servers"' not in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings",
        data={
            "fqdn": "core.atlaso.internal",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "ntp_servers": "time.cloudflare.com\n192.0.2.10",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert "ntp_servers" not in payload
    assert '"time_sync_mode": "systemd-timesyncd"' not in payload["config_preview"]
    assert '"ntp_servers": [' not in payload["config_preview"]
    assert payload["valid"] is True

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert not hasattr(settings, "ntp_servers")

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "appliance_settings"})
    assert_apply_redirect(apply_response)

    with SessionLocal() as db:
        status = appliance_apply_status(db, "appliance_settings", refresh=True)
        assert status["changed"] is False
        assert "ntp_servers" not in status["config_preview"]


def test_ntp_page_autosave_updates_desired_state_and_preview(client, monkeypatch):
    """Verify that ntp page autosave updates desired state and preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaSettings, NtpSettings

    supported = AdapterResult(
        command=["atlaso-helper", "ntpd", "capabilities"],
        dry_run=False,
        stdout=(
            json.dumps(
                {
                    "timestamp": "2026-07-13T18:00:00+00:00",
                    "helper": "atlaso-helper",
                    "group": "ntpd",
                    "action": "capabilities",
                    "args": [],
                    "dry_run": False,
                },
                sort_keys=True,
            )
            + "\n"
            + json.dumps({"nts": True, "version": "ntpd version 4.6 (+NTS)"}, sort_keys=True)
            + "\n"
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: supported,
    )
    login(client)
    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one_or_none()
        if ca_settings is None:
            ca_settings = CaSettings()
            db.add(ca_settings)
        ca_settings.enabled = True
        db.commit()
    page = client.get("/ntp")
    assert page.status_code == 200
    assert "NTP / NTS Settings" in page.text
    assert "ntp-source-health-modal" in page.text
    assert "Check source health" not in page.text
    assert "ntp-upstreams-table" in page.text
    assert 'id="ntp-source-dialog"' in page.text
    assert "data-ntp-source-form" in page.text
    ntp_source_wizard = page.text.split('id="ntp-source-dialog"', 1)[1].split("</dialog>", 1)[0]
    ntp_source_identity = ntp_source_wizard.split('data-atlaso-wizard-step="identity"', 1)[1].split("</section>", 1)[0]
    assert '<textarea name="description" rows="3" maxlength="1000">' in ntp_source_identity
    assert "ntp-main-panel" in page.text
    assert '"source": "0.pool.ntp.org"' in page.text
    assert '"source": "ptbtime1.ptb.de"' in page.text
    assert '"source": "time.google.com"' in page.text
    assert '"source": "time.nist.gov"' in page.text
    assert '"source": "time.facebook.com"' in page.text
    assert "NTS-KE disabled" in page.text or "NTS-KE ntp.atlaso.internal:4460" in page.text
    assert page.text.index('id="ntp-upstreams-table"') < page.text.index('<aside class="side-stack">')
    assert "NTS-KE port" in page.text
    assert 'type="number" value="4460" min="4460" max="4460" readonly aria-label="NTS-KE port"' in page.text
    assert "4460/tcp" not in page.text
    assert "NTP port" in page.text
    assert "NTS key" not in page.text
    assert "/var/lib/atlaso/apply/ntpd/atlaso-ntp.conf" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    upstream_sources = json.dumps(
        [
            {"source": "time.cloudflare.com", "enabled": True, "use_nts": True, "description": "secure"},
            {"source": "time.google.com", "enabled": True, "use_nts": False, "description": "plain"},
            {"source": "disabled.example.com", "enabled": False, "use_nts": True, "description": "kept disabled"},
        ]
    )
    response = client.post(
        "/ntp/settings",
        data={
            "enabled": "on",
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2"],
            "upstream_servers": "time.cloudflare.com\ntime.google.com",
            "upstream_sources_json": upstream_sources,
            "allow_clients": "192.168.50.0/24",
            "port": "123",
            "nts_server_enabled": "on",
            "nts_server_cert_path": "/tmp/operator-input.crt",
            "nts_server_key_path": "/tmp/operator-input.key",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["enabled"] is True
    assert payload["listen_interfaces"] == ["eth2"]
    assert payload["listen_addresses"] == ["192.168.50.1"]
    assert payload["upstream_servers"] == ["time.cloudflare.com", "time.google.com"]
    assert payload["upstream_sources"][0]["use_nts"] is True
    assert payload["upstream_sources"][2]["enabled"] is False
    assert payload["allow_clients"] == "192.168.50.0/24"
    assert payload["nts_server_enabled"] is True
    assert payload["nts_server_cert_path"] == "/etc/atlaso/ntp/certs/ntp.atlaso.internal-chain.pem"
    assert payload["nts_server_key_path"] == "/etc/atlaso/ntp/certs/ntp.atlaso.internal.key"
    assert payload["nts_ke_port"] == 4460
    assert payload["valid"] is True
    assert "nts cookie /var/lib/ntp/nts-keys" in payload["config_preview"]
    assert "server time.cloudflare.com iburst nts" in payload["config_preview"]
    assert "interface ignore wildcard" in payload["config_preview"]
    assert "interface listen 192.168.50.1" in payload["config_preview"]
    assert "restrict 192.168.50.0 mask 255.255.255.0 kod limited nomodify noquery" in payload["config_preview"]
    assert "nts cert /etc/atlaso/ntp/certs/ntp.atlaso.internal-chain.pem" in payload["config_preview"]
    assert "/tmp/operator-input" not in payload["config_preview"]

    duplicate_response = client.post(
        "/ntp/settings",
        data={
            "enabled": "on",
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2"],
            "upstream_sources_json": json.dumps(
                [
                    {"id": "first", "source": "Time.Example.COM.", "enabled": True, "use_nts": False},
                    {"id": "second", "source": "time.example.com", "enabled": True, "use_nts": False},
                ]
            ),
            "allow_clients": "any",
            "port": "123",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert duplicate_response.status_code == 422
    assert duplicate_response.json()["detail"] == (
        "NTP upstream source time.example.com is duplicated. Source names must be unique."
    )

    assert "NTS-KE ntp.atlaso.internal:4460" in client.get("/ntp").text
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "initializeNtpSettings" in js.text
    assert "initializeNTPsecUpstreamsTable" in js.text
    ntp_table_js = js.text.split("function initializeNTPsecUpstreamsTable()", 1)[1].split(
        "function updateNtpSettingsPreview", 1
    )[0]
    assert 'pattern: "wizard-backed"' in ntp_table_js
    assert "window.AtlasoUiPatterns.createWizard({" in ntp_table_js
    assert "await persistNtpUpstreamTableChange(table, hiddenInput)" in ntp_table_js
    assert "table.addRow(payload, true" in ntp_table_js
    assert "id: context?.id || \"\"" in ntp_table_js
    assert "record_id: context?.id" not in ntp_table_js
    assert "findDuplicateNtpUpstreamSource" in ntp_table_js
    assert "onReady: (readyTable) => syncNTPsecUpstreamsHiddenInput(readyTable)" in ntp_table_js
    assert 'const ntsCapabilityKnown = tableElement.dataset.ntpNtsCapabilityKnown !== "false"' in ntp_table_js
    assert "!ntsCapabilityKnown && existingData ? Boolean(existingData.use_nts) : false" in ntp_table_js
    assert "ntpUpstreamRowHasSource" in js.text
    assert "editable: ntpUpstreamRowHasSource" in js.text
    assert "rowContextMenu" in js.text
    assert 'label: "Delete server"' in js.text
    assert "ntpNtsTickFormatter" in js.text
    assert "parseNtpUpstreamSource" in js.text
    assert "widthGrow: 5" in js.text
    assert "function atlasoBooleanFormatter" in js.text
    assert "formatter: atlasoBooleanFormatter" in js.text
    assert "const tone = enabled ? \"good\" : \"bad\"" in js.text
    assert "boolean-glyph ${tone}" in js.text
    assert "initializeNTPsecSourceHealthModal" in js.text
    assert "Check NTPsec source health" in js.text
    assert 'const names = ["peers", "variables", "nts"]' in js.text
    assert "openNTPsecSourceHealthModal" in js.text
    assert "/ntp/source-health" in js.text
    assert "updateNtpValidation" in js.text
    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200
    assert 'tabulator-field="source"' in app_css.text
    assert ".invalid-ntp-source-cell" in app_css.text
    assert ".ntp-main-panel" in app_css.text
    assert "flex: 1 1 0;" in app_css.text
    assert ".side-stack .help-icon::after" in app_css.text
    assert "right: 0;" in app_css.text

    health = client.get("/ntp/source-health")
    assert health.status_code == 200
    assert "status" in health.json()

    assert "External NTP servers" not in client.get("/settings").text

    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        managed_certificate = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "ntp:nts")).scalar_one()
        assert settings.enabled is True
        assert settings.listen_interface == "eth2"
        assert settings.listen_address == "192.168.50.1"
        assert settings.nts_server_cert_path == "/etc/atlaso/ntp/certs/ntp.atlaso.internal-chain.pem"
        assert managed_certificate.status == "issued"
        assert managed_certificate.chain_path == settings.nts_server_cert_path


def test_ntp_disables_and_rejects_nts_when_runtime_does_not_support_it(client, monkeypatch):
    """Verify that ntp disables and rejects nts when runtime does not support it.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, NtpSettings
    from atlaso.app.services.ntp import dump_ntp_upstream_sources, ntp_upstream_sources

    unsupported = AdapterResult(
        command=["atlaso-helper", "ntpd", "capabilities"],
        dry_run=False,
        stdout=json.dumps({"nts": False, "version": "ntpd version 4.3 (-NTS)"}),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: unsupported,
    )
    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        settings.nts_server_enabled = True
        settings.upstream_sources_json = dump_ntp_upstream_sources(
            [
                {
                    "id": "cloudflare-nts",
                    "source": "time.cloudflare.com",
                    "enabled": True,
                    "use_nts": True,
                    "description": "Cloudflare public NTS",
                }
            ]
        )
        db.commit()

    page = client.get("/ntp")

    assert page.status_code == 200
    assert 'data-ntp-nts-supported="false"' in page.text
    assert "Installed ntpd has no NTS support." in page.text
    assert "NTS unavailable" in page.text
    assert "NTS server (disabled)" in page.text
    assert 'class="switch-field disabled-field" aria-disabled="true"' in page.text
    assert 'name="nts_server_enabled" disabled' in page.text
    assert 'name="upstream_use_nts" value="0" disabled' in page.text
    assert 'readonly disabled aria-label="NTS-KE port"' in page.text

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ntp/settings",
        data={
            "enabled": "on",
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2"],
            "upstream_sources_json": json.dumps(
                [
                    {
                        "source": "time.cloudflare.com",
                        "enabled": True,
                        "use_nts": True,
                    }
                ]
            ),
            "allow_clients": "any",
            "port": "123",
            "nts_server_enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["nts_supported"] is False
    assert payload["nts_server_enabled"] is False
    assert payload["upstream_sources"][0]["use_nts"] is False
    assert "nts cookie" not in payload["config_preview"]
    assert "server time.cloudflare.com iburst nts" not in payload["config_preview"]

    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.nts_server_enabled is False
        assert all(source["use_nts"] is False for source in ntp_upstream_sources(settings))
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.action == "disable_unsupported_ntp_nts")
        ).scalar_one()
        assert audit.actor == "system"


def test_ntp_preserves_nts_desired_state_when_capability_check_fails(client, monkeypatch):
    """Verify that ntp preserves nts desired state when capability check fails.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, NtpSettings
    from atlaso.app.services.ntp import dump_ntp_upstream_sources, ntp_upstream_sources

    unavailable = AdapterResult(
        command=["atlaso-helper", "ntpd", "capabilities"],
        dry_run=False,
        returncode=1,
        stderr="capability check unavailable",
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: unavailable,
    )
    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        settings.nts_server_enabled = False
        settings.upstream_sources_json = dump_ntp_upstream_sources(
            [
                {
                    "id": "cloudflare-nts",
                    "source": "time.cloudflare.com",
                    "enabled": True,
                    "use_nts": True,
                    "description": "Cloudflare public NTS",
                }
            ]
        )
        db.commit()

    page = client.get("/ntp")

    assert page.status_code == 200
    assert 'data-ntp-nts-supported="false"' in page.text
    assert 'data-ntp-nts-capability-known="false"' in page.text
    assert "NTS check unavailable" in page.text
    assert "Existing NTS desired state is preserved" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/ntp/settings",
        data={
            "enabled": "on",
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2"],
            "upstream_sources_json": json.dumps(
                [
                    {
                        "id": "cloudflare-nts",
                        "source": "time.cloudflare.com",
                        "enabled": True,
                        "use_nts": True,
                        "description": "Cloudflare public NTS",
                    }
                ]
            ),
            "allow_clients": "any",
            "port": "123",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["nts_supported"] is False
    assert payload["nts_capability_known"] is False
    assert payload["nts_server_enabled"] is False
    assert payload["upstream_sources"][0]["use_nts"] is True
    assert "server time.cloudflare.com iburst nts" in payload["config_preview"]
    assert payload["valid"] is False
    assert any(
        "existing NTS desired state was preserved, but appliance apply is blocked until detection succeeds." in error
        for error in payload["validation_errors"]
    )

    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.nts_server_enabled is False
        assert ntp_upstream_sources(settings)[0]["use_nts"] is True
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.action == "disable_unsupported_ntp_nts")
        ).scalar_one_or_none()
        assert audit is None


def test_disabling_nts_server_removes_certificate_record_but_preserves_nts_client(client, monkeypatch):
    """Verify that disabling nts server removes certificate record but preserves nts client.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, NtpSettings
    from atlaso.app.services.ntp import ntp_upstream_sources

    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_capabilities",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "capabilities"],
            dry_run=False,
            stdout=json.dumps({"nts": True, "version": "ntpd version 4.6 (+NTS)"}),
        ),
    )
    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        settings.nts_server_enabled = True
        settings.nts_server_cert_path = "/etc/atlaso/ntp/certs/ntp.atlaso.internal-chain.pem"
        settings.nts_server_key_path = "/etc/atlaso/ntp/certs/ntp.atlaso.internal.key"
        db.add(settings)
        db.add(
            CaCertificate(
                common_name="ntp.atlaso.internal",
                managed_owner="ntp:nts",
                status="issued",
                cert_path="/etc/atlaso/ntp/certs/ntp.atlaso.internal.crt",
                key_path=settings.nts_server_key_path,
                chain_path=settings.nts_server_cert_path,
            )
        )
        db.commit()

    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ntp/settings",
        data={
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "upstream_sources_json": json.dumps(
                [
                    {
                        "id": "cloudflare-nts",
                        "source": "time.cloudflare.com",
                        "enabled": True,
                        "use_nts": True,
                        "description": "Cloudflare public NTS",
                    }
                ]
            ),
            "allow_clients": "any",
            "port": "123",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["nts_server_enabled"] is False
    assert payload["upstream_sources"][0]["use_nts"] is True
    assert "server time.cloudflare.com iburst nts" in payload["config_preview"]
    assert "nts enable" not in payload["config_preview"]
    assert "nts cookie" not in payload["config_preview"]

    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.nts_server_enabled is False
        assert settings.nts_server_cert_path == ""
        assert settings.nts_server_key_path == ""
        assert ntp_upstream_sources(settings)[0]["use_nts"] is True
        assert db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "ntp:nts")
        ).scalar_one_or_none() is None


def test_ntp_validation_rejects_enabled_service_without_bind_or_upstreams(client):
    """Verify that ntp validation rejects enabled service without bind or upstreams.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ntp/settings",
        data={
            "enabled": "on",
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "upstream_servers": "",
            "allow_clients": "any",
            "port": "123",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is False
    assert "NTP listen interface is required when the service is enabled." in payload["validation_errors"]
    assert "At least one NTP upstream server is required." in payload["validation_errors"]


def test_ntp_validation_allows_disabled_service_without_upstreams(client):
    """Verify that ntp validation allows disabled service without upstreams.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ntp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/ntp/settings",
        data={
            "hostname": "ntp.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": [],
            "upstream_servers": "",
            "allow_clients": "any",
            "port": "123",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is False
    assert payload["valid"] is True
    assert payload["upstream_servers"] == []
    assert "At least one NTP upstream server is required." not in payload["validation_errors"]
    assert "server " not in payload["config_preview"]


def test_dns_defaults_follow_appliance_fqdn_and_management_ip(client):
    """Verify that dns defaults follow appliance fqdn and management ip.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, DnsSettings

    login(client)
    page = client.get("/dns")
    assert page.status_code == 200
    assert 'data-domain="atlaso.internal"' in page.text
    assert "atlaso" in page.text
    assert "192.168.49.1" in page.text

    with SessionLocal() as db:
        settings = db.execute(select(DnsSettings)).scalar_one()
        assert settings.domain == "atlaso.internal"
        record = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "core.atlaso.internal", DnsRecord.record_type == "A")
        ).scalar_one()
        assert record.address == "192.168.49.1"
        assert "app-owned appliance FQDN" in (record.description or "")


def test_seed_reconciles_multiple_management_ui_dns_addresses(client):
    """Verify startup seeding accepts dedicated and flagged-access appliance records.

    Args:
        client: Application test client fixture used to initialize seeded state.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsRecord, PhysicalInterface
    from atlaso.app.seed import _ensure_appliance_dns_record

    with SessionLocal() as db:
        access = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
        access.access_management_ui_enabled = True
        settings = db.execute(select(ApplianceSettings)).scalar_one()

        _ensure_appliance_dns_record(db, settings)
        db.commit()
        _ensure_appliance_dns_record(db, settings)
        db.commit()

        records = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == settings.fqdn,
                DnsRecord.record_type == "A",
            )
        ).scalars().all()
        assert {record.address for record in records} == {"192.168.49.1", "192.168.50.1"}


def test_settings_fqdn_rename_removes_only_old_app_owned_record(client):
    """Verify that settings fqdn rename removes only old app owned record.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, DnsSettings

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        db.add(
            DnsRecord(
                hostname="manual.atlaso.internal",
                record_type="A",
                address="192.168.49.20",
                description="User-owned record",
            )
        )
        db.commit()

    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    first = client.post(
        "/settings",
        data={
            "fqdn": "old-appliance.atlaso.internal",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert first.status_code == 200
    second = client.post(
        "/settings",
        data={
            "fqdn": "new-appliance.atlaso.internal",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert second.status_code == 200
    assert "removed-old" in (second.json()["dns_record_action"] or "")

    with SessionLocal() as db:
        old = db.execute(select(DnsRecord).where(DnsRecord.hostname == "old-appliance.atlaso.internal")).scalars().all()
        new = db.execute(select(DnsRecord).where(DnsRecord.hostname == "new-appliance.atlaso.internal")).scalars().all()
        manual = db.execute(select(DnsRecord).where(DnsRecord.hostname == "manual.atlaso.internal")).scalar_one()
        assert old == []
        assert len(new) == 1
        assert manual.address == "192.168.49.20"


def test_settings_local_dns_disabled_requires_external_dns_without_dns_registration(client):
    """Verify that settings local dns disabled requires external dns without dns registration.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, DnsSettings

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = False
        db.commit()

    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings",
        data={
            "fqdn": "external-only.atlaso.internal",
            "external_dns_servers": "",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is False
    assert "External DNS servers are required when local DNS is disabled." in payload["validation_errors"]
    assert payload["dns_record_action"] is None
    assert '"resolver_mode": "external"' in payload["config_preview"]
    with SessionLocal() as db:
        record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "external-only.atlaso.internal")).scalar_one_or_none()
        assert record is None


def test_parse_resolvectl_dns_servers_handles_systemd_output():
    """Verify that parse resolvectl dns servers handles systemd output."""
    from atlaso.app.services.appliance_settings import parse_resolvectl_dns_servers

    output = """
Global:
Link 2 (eth0): 127.0.0.1 ::1 192.168.167.2 2001:4860:4860::8888 fe80::1%eth0 192.168.167.2
"""

    assert parse_resolvectl_dns_servers(output) == ["192.168.167.2", "2001:4860:4860::8888"]


def test_management_dhcp_dns_falls_back_to_exact_networkd_lease_after_local_dns(monkeypatch):
    """Verify that management dhcp dns falls back to exact networkd lease after local dns.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import subprocess

    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.services.appliance_settings import (
        invalidate_observed_management_dhcp_dns,
        observed_management_dhcp_dns_servers,
        parse_networkd_dhcp_dns_payload,
    )

    monkeypatch.setattr(
        "atlaso.app.services.appliance_settings.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "Link 2 (eth0): 127.0.0.1 ::1\n", ""),
    )
    calls: list[str] = []

    def fake_read_networkd_dhcp_dns(_self, interface_name: str) -> AdapterResult:
        """Return fake read networkd dhcp dns.

        Args:
            _self: Self supplied to the test scenario.
            interface_name: Host network-interface name affected by the operation.
        """
        calls.append(interface_name)
        return AdapterResult(
            command=["atlaso-helper", "network", "dhcp-dns", interface_name],
            dry_run=False,
            stdout=(
                '{"group":"network","action":"dhcp-dns"}\n'
                '{"interface":"eth0","ifindex":2,"servers":["127.0.0.1","fe80::53","192.168.167.2","bad","192.168.167.2"]}\n'
            ),
        )

    monkeypatch.setattr(SystemAdapter, "read_networkd_dhcp_dns", fake_read_networkd_dhcp_dns)

    assert observed_management_dhcp_dns_servers("eth0") == ["192.168.167.2"]
    assert observed_management_dhcp_dns_servers("eth0") == ["192.168.167.2"]
    assert calls == ["eth0"]

    invalidate_observed_management_dhcp_dns("eth0")
    assert observed_management_dhcp_dns_servers("eth0") == ["192.168.167.2"]
    assert calls == ["eth0", "eth0"]
    assert parse_networkd_dhcp_dns_payload(
        '{"interface":"eth1","servers":["192.168.99.99"]}\n',
        "eth0",
    ) == []


def test_settings_management_dhcp_allows_empty_external_dns(client, monkeypatch):
    """Verify that settings management dhcp allows empty external dns.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, PhysicalInterface

    login(client)
    monkeypatch.setattr("atlaso.app.services.appliance_settings.observed_management_dhcp_dns_servers", lambda interface_name: ["127.0.0.1", "::1", "192.168.167.2"])
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = False
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.external_dns_servers = ""
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.host_ip_cidr = "192.168.167.218/24"
        db.commit()

    page = client.get("/settings")
    assert "DHCP DNS" in page.text
    assert "Management DHCP will keep lease-provided resolver servers" in page.text
    assert "from DHCP" in page.text
    assert 'placeholder="DHCP: 192.168.167.2"' in page.text
    assert "<code>192.168.167.2</code>" in page.text
    assert 'placeholder="DHCP: 127.0.0.1' not in page.text
    assert "<code>127.0.0.1</code>" not in page.text
    assert "<code>::1</code>" not in page.text
    assert ">192.168.167.2</textarea>" not in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings",
        data={
            "fqdn": "dhcp-managed.atlaso.internal",
            "external_dns_servers": "",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is True
    assert payload["external_dns_servers"] == []
    assert payload["resolver_mode"] == "dhcp"
    assert payload["observed_dhcp_dns_servers"] == ["192.168.167.2"]
    assert '"resolver_mode": "dhcp"' in payload["config_preview"]
    assert '"resolver_servers": []' in payload["config_preview"]






def test_settings_management_https_requires_ca_managed_certificate(client):
    """Verify that settings management https requires ca managed certificate.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        CaCertificate,
        CaSettings,
        DnsSettings,
    )

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = False
        db.commit()

    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    invalid = client.post(
        "/settings",
        data={
            "fqdn": "secure.atlaso.internal",
            "management_https_enabled": "on",
            "external_dns_servers": "1.1.1.1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
    assert "Management UI HTTPS requires the local Atlaso CA to be enabled." in invalid.json()["validation_errors"]

    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        db.add(
            CaCertificate(
                common_name="secure.atlaso.internal",
                subject_alt_names="secure.atlaso.internal",
                ip_addresses="192.168.49.1",
                status="issued",
                certificate_pem="-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
                private_key_encrypted="fernet:v1:test",
                managed_owner="appliance:https",
                cert_path="/etc/atlaso/https/certs/secure.atlaso.internal.crt",
                key_path="/etc/atlaso/https/certs/secure.atlaso.internal.key",
                chain_path="/etc/atlaso/https/certs/secure.atlaso.internal-chain.pem",
            )
        )
        db.commit()

    valid = client.post(
        "/settings",
        data={
            "fqdn": "secure.atlaso.internal",
            "management_https_enabled": "on",
            "external_dns_servers": "1.1.1.1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert valid.status_code == 200
    payload = valid.json()
    assert payload["valid"] is True
    assert payload["management_https_enabled"] is True
    assert payload["management_https_cert_available"] is True
    assert '"management_https_enabled": true' in payload["config_preview"]
    assert "/etc/atlaso/https/certs/secure.atlaso.internal.crt" in payload["config_preview"]

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.management_https_enabled is True
        certificate = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")).scalar_one()
        assert certificate.common_name == "secure.atlaso.internal"

    rotated = client.post(
        "/settings",
        data={
            "fqdn": "rotated.atlaso.internal",
            "management_https_enabled": "on",
            "external_dns_servers": "1.1.1.1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert rotated.status_code == 200
    rotated_payload = rotated.json()
    assert rotated_payload["valid"] is True
    assert rotated_payload["management_https_cert_available"] is True
    assert "/etc/atlaso/https/certs/rotated.atlaso.internal.crt" in rotated_payload["config_preview"]

    with SessionLocal() as db:
        certificate = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")).scalar_one()
        assert certificate.common_name == "rotated.atlaso.internal"
        assert certificate.status == "issued"


def test_appliance_settings_apply_task_records_redacted_dry_run_command_evidence(client, caplog):
    """Verify appliance apply logs redacted dry-run command evidence.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        caplog: Pytest fixture used to capture emitted log records.
    """
    import logging

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    saved = client.post(
        "/settings",
        data={
            "fqdn": "apply.atlaso.internal",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert saved.status_code == 200

    with caplog.at_level(logging.INFO, logger="atlaso.appliance_apply"):
        apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "appliance_settings"})
    assert_apply_redirect(apply_response)
    apply_logs = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "atlaso.appliance_apply"
    )
    assert "succeeded; desired-state and helper details omitted" in apply_logs
    assert "selected_units" not in apply_logs
    assert "unit=appliance_settings" not in apply_logs
    assert "command_index" not in apply_logs
    assert "returncode" not in apply_logs
    assert "atlaso-helper appliance-settings validate" not in apply_logs
    assert "Appliance Settings" in apply_response.text
    assert "data-apply-progress-modal" not in apply_response.text
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "appliance_settings" in (job.result or "")
        assert "atlaso-helper appliance-settings validate" in (job.result or "")
        assert "atlaso-helper appliance-settings apply" in (job.result or "")
        assert "apply.atlaso.internal" in (job.result or "")


def test_appliance_apply_failure_renders_command_details(client, monkeypatch):
    """Verify that appliance apply failure renders command details.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.ui as ui_module
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    base_system_adapter = ui_module.SystemAdapter
    monkeypatch.setattr(ui_module, "stage_appliance_apply_config", lambda path, _config: path)

    class FailingApplianceSettingsAdapter(base_system_adapter):
        """Represent failing appliance settings adapter."""
        def __init__(self) -> None:
            """Initialize the failing appliance settings adapter."""
            super().__init__(dry_run=False)

        def read_dhcp_leases(self) -> AdapterResult:
            """Return dhcp leases."""
            return AdapterResult(command=["atlaso-helper", "dnsmasq", "leases"], dry_run=True, stdout="")

        def validate_appliance_settings_config(self, config_path: str) -> AdapterResult:
            """Validate appliance settings config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The validate appliance settings config result.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-settings", "validate", config_path],
                dry_run=False,
                stdout="validation ok",
            )

        def apply_appliance_settings_config(self, config_path: str) -> AdapterResult:
            """Update appliance settings config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The apply appliance settings config result.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-settings", "apply", config_path],
                dry_run=False,
                stdout="password=super-secret\nattempted write",
                stderr="OSError: [Errno 30] Read-only file system: '/etc/atlaso/nginx/sites.d/management.conf'",
                returncode=30,
            )

    monkeypatch.setattr(ui_module, "SystemAdapter", FailingApplianceSettingsAdapter)

    login(client)
    page = client.get("/appliance-apply")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "appliance_settings"})

    assert_apply_redirect(response)
    assert "super-secret" not in response.text
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        payload = json.loads(job.result or "{}")
        assert job.status == "failed"
        command = payload["units"][0]["commands"][-1]
        assert "atlaso-helper appliance-settings apply" in command["command_line"]
        assert command["returncode"] == 30
        assert "Read-only file system" in command["stderr"]
        assert "password= [redacted]" in command["stdout"]
        assert "super-secret" not in (job.result or "")


def test_appliance_apply_stops_unit_after_validation_failure(client, monkeypatch):
    """Verify that appliance apply stops unit after validation failure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.ui as ui_module
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    base_system_adapter = ui_module.SystemAdapter
    monkeypatch.setattr(ui_module, "stage_appliance_apply_config", lambda path, _config: path)

    class ValidationFailingApplianceSettingsAdapter(base_system_adapter):
        """Represent validation failing appliance settings adapter."""
        def __init__(self) -> None:
            """Initialize the validation failing appliance settings adapter."""
            super().__init__(dry_run=False)

        def read_dhcp_leases(self) -> AdapterResult:
            """Return dhcp leases."""
            return AdapterResult(command=["atlaso-helper", "dnsmasq", "leases"], dry_run=True, stdout="")

        def validate_appliance_settings_config(self, config_path: str) -> AdapterResult:
            """Validate appliance settings config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The validate appliance settings config result.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-settings", "validate", config_path],
                dry_run=False,
                stderr="hostname validation failed",
                returncode=2,
            )

        def apply_appliance_settings_config(self, config_path: str) -> AdapterResult:
            """Update appliance settings config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The apply appliance settings config result.

            Raises:
                AssertionError: If an expected invariant is not satisfied.
            """
            raise AssertionError("apply should not run after validation failure")

    monkeypatch.setattr(ui_module, "SystemAdapter", ValidationFailingApplianceSettingsAdapter)

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    saved = client.post(
        "/settings",
        data={
            "fqdn": "validate-fail.atlaso.internal",
            "external_dns_servers": "1.1.1.1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert saved.status_code == 200

    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "appliance_settings"})

    assert_apply_redirect(response)
    assert "atlaso-helper appliance-settings apply" not in response.text
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        payload = json.loads(job.result or "{}")
        commands = payload["units"][0]["commands"]
        assert [command["command"][2] for command in commands] == ["validate"]
        assert "atlaso-helper appliance-settings apply" not in (job.result or "")


def test_backup_restore_page_exports_settings_archive(client):
    """Verify that backup restore page exports settings archive.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, LdapOrganization, LdapUser

    with SessionLocal() as db:
        organization = LdapOrganization(
            name="Archive safety test",
            slug="archive-safety-test",
            suffix_dn="dc=archive-safety,dc=test",
        )
        db.add(organization)
        db.flush()
        db.add(
            LdapUser(
                organization_id=organization.id,
                uid="archive-user",
                enabled=True,
                password_status="applied",
            )
        )
        db.commit()

    login(client)
    page = client.get("/backup-restore")
    assert page.status_code == 200
    assert "Download settings backup" in page.text
    assert "Restore settings backup" in page.text
    assert "Factory reset settings" in page.text
    assert "LDAP Directory Recovery" in page.text
    assert "not part of the normal settings backup" in page.text
    assert 'action="/ui/management/backup-restore/ldap/export"' in page.text
    assert 'action="/ui/management/backup-restore/ldap/import"' in page.text
    assert 'accept=".lfldap,application/octet-stream"' in page.text
    assert "Audit events, jobs, API tokens, password hashes, uploaded secret bodies; CA private material stays encrypted" in page.text
    assert "data-confirm-modal" in page.text

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    exported = client.post("/backup-restore/export", data={"csrf": csrf})

    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/json")
    assert "atlaso-settings-" in exported.headers["content-disposition"]
    payload = json.loads(exported.content)
    assert payload["kind"] == "atlaso-settings-archive"
    assert payload["schema_version"] == 2
    assert "appliance_settings" in payload["data"]
    assert "dns_records" in payload["data"]
    assert "users" not in payload["data"]
    assert "api_tokens" not in payload["data"]
    assert "audit_events" not in payload["data"]
    assert "jobs" not in payload["data"]
    archived_ldap_user = next(
        row for row in payload["data"]["ldap_users"] if row["uid"] == "archive-user"
    )
    assert archived_ldap_user["enabled"] is False
    assert archived_ldap_user["password_status"] == "not_staged"

    with SessionLocal() as db:
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "export_settings_backup")).scalar_one()
        assert event.resource_type == "settings_backup"


def test_settings_archive_round_trips_management_ipv6_gateway(client):
    """Verify that settings archive round trips management ipv6 gateway.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.role == "management"))
        assert management is not None
        management.ipv6_enabled = True
        management.ipv6_cidr = "2001:db8:49::10/64"
        management.ipv6_gateway = "fe80::1"
        db.commit()
        management_name = management.name
        archive = export_settings_archive(db, actor="test")
        archived = next(row for row in archive["data"]["physical_interfaces"] if row["name"] == management_name)
        assert archived["ipv6_gateway"] == "fe80::1"

        restore_settings_archive(db, archive)
        db.commit()
        restored = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == management_name))
        assert restored is not None
        assert restored.ipv6_cidr == "2001:db8:49::10/64"
        assert restored.ipv6_gateway == "fe80::1"


def test_settings_archive_maps_only_retired_network_roles_to_access(client):
    """Verify backup export and restore preserve state while canonicalizing retired roles.

    Args:
        client: HTTP test client used to initialize isolated desired state.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule, PhysicalInterface, Route, VlanInterface
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        physical = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        vlan = db.scalar(select(VlanInterface).order_by(VlanInterface.id))
        assert physical is not None
        assert vlan is not None
        physical.role = "services"
        physical.admin_state = "down"
        vlan.role = "storage"
        vlan.enabled = False
        dependent_route = db.scalar(select(Route).where(Route.interface_name == vlan.name))
        if dependent_route is not None:
            dependent_route.enabled = False
        dependent_nat_rule = db.scalar(
            select(NatRule).where(NatRule.outbound_interface == vlan.name)
        )
        if dependent_nat_rule is not None:
            dependent_nat_rule.enabled = False
        physical_name = physical.name
        vlan_name = vlan.name
        db.commit()

        archive = export_settings_archive(db, actor="test")
        archived_physical = next(row for row in archive["data"]["physical_interfaces"] if row["name"] == physical_name)
        archived_vlan = next(row for row in archive["data"]["vlan_interfaces"] if row["name"] == vlan_name)
        assert archived_physical["role"] == "access"
        assert archived_physical["admin_state"] == "down"
        assert archived_vlan["role"] == "access"
        assert archived_vlan["enabled"] is False

        archived_physical["role"] = "services"
        archived_vlan["role"] = "storage"
        restore_settings_archive(db, archive)
        db.commit()

        restored_physical = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == physical_name))
        restored_vlan = db.scalar(select(VlanInterface).where(VlanInterface.name == vlan_name))
        assert restored_physical is not None
        assert restored_vlan is not None
        assert restored_physical.role == "access"
        assert restored_physical.admin_state == "down"
        assert restored_vlan.role == "access"
        assert restored_vlan.enabled is False


@pytest.mark.parametrize("role_state", ["missing", "null"])
def test_settings_archive_rejects_missing_interface_roles_before_clearing_state(client, role_state):
    """Verify invalid archive roles fail before current desired state is removed.

    Args:
        client: HTTP test client used to initialize isolated desired state.
        role_state: Missing-role representation placed in the candidate archive.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.role == "management"))
        assert management is not None
        management_name = management.name
        archive = export_settings_archive(db, actor="test")
        archived_management = next(
            row for row in archive["data"]["physical_interfaces"] if row["name"] == management_name
        )
        if role_state == "missing":
            archived_management.pop("role")
        else:
            archived_management["role"] = None

        with pytest.raises(ValueError, match="missing its required role"):
            restore_settings_archive(db, archive)

        retained = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == management_name))
        assert retained is not None
        assert retained.role == "management"


def test_startup_reconciles_retired_network_roles_once_without_state_drift(client):
    """Verify startup migration is idempotent and changes only the retired role values.

    Args:
        client: HTTP test client used to initialize isolated desired state.
    """
    from sqlalchemy import func, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, PhysicalInterface, Setting, VlanInterface
    from atlaso.app.seed import (
        NETWORK_ROLE_RECONCILIATION_SETTING_KEY,
        seed_initial_data,
    )

    with SessionLocal() as db:
        physical = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        vlan = db.scalar(select(VlanInterface).order_by(VlanInterface.id))
        assert physical is not None
        assert vlan is not None
        marker = db.scalar(select(Setting).where(Setting.key == NETWORK_ROLE_RECONCILIATION_SETTING_KEY))
        assert marker is not None
        db.delete(marker)
        physical.role = "services"
        physical.admin_state = "down"
        vlan.role = "storage"
        vlan.enabled = False
        db.commit()

        seed_initial_data(db)
        db.refresh(physical)
        db.refresh(vlan)
        assert (physical.role, physical.admin_state) == ("access", "down")
        assert (vlan.role, vlan.enabled) == ("access", False)
        audit_count = db.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "reconcile_network_roles")
        )
        assert audit_count == 1

        seed_initial_data(db)
        assert db.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "reconcile_network_roles")
        ) == audit_count


def test_settings_archive_round_trips_authoritative_dns_policy(client):
    """Verify that settings archive round trips authoritative dns policy.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        settings = db.scalar(select(DnsSettings))
        settings.authoritative_server = "ns-primary.atlaso.internal"
        settings.authoritative_contact = "dns-admin.atlaso.internal"
        settings.authoritative_ttl = 7200
        settings.authoritative_serial = 2026072201
        settings.authoritative_refresh = 2400
        settings.authoritative_retry = 300
        settings.authoritative_expire = 2419200
        db.commit()

        archive = export_settings_archive(db, actor="test")
        archived = archive["data"]["dns_settings"][0]
        assert archived["authoritative_server"] == "ns-primary.atlaso.internal"
        archived_serial = archived["authoritative_serial"]
        assert archived_serial > 2026072201

        restore_settings_archive(db, archive)
        db.commit()
        restored = db.scalar(select(DnsSettings))
        assert restored.authoritative_server == "ns-primary.atlaso.internal"
        assert restored.authoritative_contact == "dns-admin.atlaso.internal"
        assert restored.authoritative_ttl == 7200
        assert restored.authoritative_serial >= archived_serial
        assert restored.authoritative_refresh == 2400
        assert restored.authoritative_retry == 300
        assert restored.authoritative_expire == 2419200


def test_settings_archive_round_trips_ca_revocation_timestamp(client):
    """Verify CA revocation timestamps survive settings export and restore.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from datetime import datetime, timezone

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaSettings
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    revoked_at = datetime(2026, 8, 12, 12, 30, tzinfo=timezone.utc)
    with SessionLocal() as db:
        db.query(CaCertificate).delete()
        settings = db.scalar(select(CaSettings))
        assert settings is not None
        settings.enabled = True
        assert ensure_root_ca_material(settings) is True
        expected_root_issued_at = settings.root_issued_at
        expected_root_expires_at = settings.root_expires_at
        assert expected_root_issued_at is not None
        assert expected_root_expires_at is not None
        db.add(
            CaCertificate(
                common_name="revoked-archive.atlaso.internal",
                status="revoked",
                serial_number="2a",
                revoked_at=revoked_at,
                revoked_by="admin",
                revocation_reason="rotation",
                enabled=True,
            )
        )
        db.commit()

        archive = export_settings_archive(db, actor="test")
        archived = archive["data"]["ca_certificates"][0]
        assert archived["revoked_at"] == revoked_at.isoformat()

        restore_settings_archive(db, archive)
        restored = db.scalar(
            select(CaCertificate).where(
                CaCertificate.common_name == "revoked-archive.atlaso.internal"
            )
        )
        assert restored is not None
        restored_settings = db.scalar(select(CaSettings))
        assert restored_settings is not None
        restored_root_issued_at = restored_settings.root_issued_at
        restored_root_expires_at = restored_settings.root_expires_at
        assert restored_root_issued_at is not None
        assert restored_root_expires_at is not None
        restored_revoked_at = restored.revoked_at
        assert restored_revoked_at is not None
        if restored_revoked_at.tzinfo is None:
            restored_revoked_at = restored_revoked_at.replace(tzinfo=timezone.utc)
        if restored_root_issued_at.tzinfo is None:
            restored_root_issued_at = restored_root_issued_at.replace(
                tzinfo=timezone.utc
            )
        if restored_root_expires_at.tzinfo is None:
            restored_root_expires_at = restored_root_expires_at.replace(
                tzinfo=timezone.utc
            )
        if expected_root_issued_at.tzinfo is None:
            expected_root_issued_at = expected_root_issued_at.replace(
                tzinfo=timezone.utc
            )
        if expected_root_expires_at.tzinfo is None:
            expected_root_expires_at = expected_root_expires_at.replace(
                tzinfo=timezone.utc
            )
        assert restored_revoked_at == revoked_at
        assert restored_root_issued_at == expected_root_issued_at
        assert restored_root_expires_at == expected_root_expires_at


def test_settings_archive_round_trips_ca_certificate_validity(client):
    """Verify issued CA certificate validity survives export and restore.

    Args:
        client: HTTP test client used to initialize isolated desired state.
    """
    from copy import deepcopy
    from datetime import datetime, timezone

    import pytest
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaProfile, CaSettings
    from atlaso.app.services.ca import ensure_root_ca_material, issue_certificate
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        db.query(CaCertificate).delete()
        settings = db.scalar(select(CaSettings))
        profile = db.scalar(select(CaProfile).where(CaProfile.enabled.is_(True)))
        assert settings is not None
        assert profile is not None
        settings.enabled = True
        assert ensure_root_ca_material(settings) is True
        certificate = CaCertificate(
            common_name="archive-validity.atlaso.internal",
            profile_id=profile.id,
            subject_alt_names="archive-validity.atlaso.internal",
            enabled=True,
        )
        db.add(certificate)
        db.flush()
        assert issue_certificate(settings, [profile], certificate) is True
        expected_issued_at = certificate.issued_at
        expected_expires_at = certificate.expires_at
        expected_serial_number = certificate.serial_number
        expected_fingerprint = certificate.fingerprint
        expected_root_serial_number = settings.root_serial_number
        expected_root_fingerprint = settings.root_fingerprint
        assert expected_issued_at is not None
        assert expected_expires_at is not None
        assert expected_serial_number
        assert expected_fingerprint
        assert expected_root_serial_number
        assert expected_root_fingerprint
        db.commit()

        archive = export_settings_archive(db, actor="test")
        archived = next(
            row
            for row in archive["data"]["ca_certificates"]
            if row["common_name"] == certificate.common_name
        )
        assert archived["issued_at"]
        assert archived["expires_at"]
        extra_csr_archive = deepcopy(archive)
        extra_csr_certificate = next(
            row
            for row in extra_csr_archive["data"]["ca_certificates"]
            if row["common_name"] == certificate.common_name
        )
        csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        extra_csr_certificate["csr_text"] = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, certificate.common_name)]
                )
            )
            .sign(csr_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode("utf-8")
        ) + (
            "-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----\n"
        )
        with pytest.raises(ValueError, match="request is not usable"):
            restore_settings_archive(db, extra_csr_archive)
        extra_pem_archive = deepcopy(archive)
        extra_pem_certificate = next(
            row
            for row in extra_pem_archive["data"]["ca_certificates"]
            if row["common_name"] == certificate.common_name
        )
        extra_pem_certificate["certificate_pem"] += (
            "-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----\n"
        )
        with pytest.raises(ValueError, match="public certificate is not usable"):
            restore_settings_archive(db, extra_pem_archive)
        extra_chain_archive = deepcopy(archive)
        extra_chain_certificate = next(
            row
            for row in extra_chain_archive["data"]["ca_certificates"]
            if row["common_name"] == certificate.common_name
        )
        extra_chain_certificate["chain_pem"] += (
            "-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----\n"
        )
        with pytest.raises(ValueError, match="chain is not usable"):
            restore_settings_archive(db, extra_chain_archive)
        foreign_settings = CaSettings(
            enabled=True,
            root_common_name="Foreign Archive Root CA",
            organization=settings.organization,
            organizational_unit=settings.organizational_unit,
            country=settings.country,
            state=settings.state,
            locality=settings.locality,
            key_algorithm=settings.key_algorithm,
            key_size=settings.key_size,
            digest_algorithm=settings.digest_algorithm,
            root_valid_days=settings.root_valid_days,
        )
        assert ensure_root_ca_material(foreign_settings) is True
        foreign_certificate = CaCertificate(
            common_name="foreign-archive.atlaso.internal",
            profile_id=profile.id,
            enabled=True,
        )
        assert issue_certificate(
            foreign_settings,
            [profile],
            foreign_certificate,
        ) is True
        foreign_certificate_archive = deepcopy(archive)
        foreign_archived_certificate = next(
            row
            for row in foreign_certificate_archive["data"]["ca_certificates"]
            if row["common_name"] == certificate.common_name
        )
        foreign_archived_certificate.update(
            {
                "enabled": False,
                "status": "issued",
                "certificate_pem": foreign_certificate.certificate_pem,
                "private_key_encrypted": foreign_certificate.private_key_encrypted,
                "chain_pem": foreign_certificate.chain_pem,
            }
        )
        with pytest.raises(ValueError, match="not issued by the restored CA root"):
            restore_settings_archive(db, foreign_certificate_archive)
        foreign_revoked_archive = deepcopy(foreign_certificate_archive)
        foreign_revoked_certificate = next(
            row
            for row in foreign_revoked_archive["data"]["ca_certificates"]
            if row["common_name"] == certificate.common_name
        )
        foreign_revoked_certificate.update(
            {
                "status": "revoked",
                "revoked_at": datetime(
                    2026,
                    8,
                    13,
                    13,
                    30,
                    tzinfo=timezone.utc,
                ).isoformat(),
                "revoked_by": "admin",
                "revocation_reason": "superseded",
            }
        )
        with pytest.raises(ValueError, match="not issued by the restored CA root"):
            restore_settings_archive(db, foreign_revoked_archive)
        archive["data"]["ca_settings"][0]["root_serial_number"] = "1"
        archive["data"]["ca_settings"][0]["root_fingerprint"] = "tampered"
        archived["serial_number"] = "2"
        archived["fingerprint"] = "tampered"
        archived["status"] = "revoked"
        archived["revoked_at"] = datetime(
            2026,
            8,
            13,
            14,
            0,
            tzinfo=timezone.utc,
        ).isoformat()

        restore_settings_archive(db, archive)
        restored = db.scalar(
            select(CaCertificate).where(
                CaCertificate.common_name == "archive-validity.atlaso.internal"
            )
        )
        assert restored is not None
        restored_settings = db.scalar(select(CaSettings))
        assert restored_settings is not None
        restored_issued_at = restored.issued_at
        restored_expires_at = restored.expires_at
        assert restored_issued_at is not None
        assert restored_expires_at is not None
        if restored_issued_at.tzinfo is None:
            restored_issued_at = restored_issued_at.replace(tzinfo=timezone.utc)
        if restored_expires_at.tzinfo is None:
            restored_expires_at = restored_expires_at.replace(tzinfo=timezone.utc)
        if expected_issued_at.tzinfo is None:
            expected_issued_at = expected_issued_at.replace(tzinfo=timezone.utc)
        if expected_expires_at.tzinfo is None:
            expected_expires_at = expected_expires_at.replace(tzinfo=timezone.utc)
        assert restored_issued_at == expected_issued_at
        assert restored_expires_at == expected_expires_at
        assert restored.status == "revoked"
        assert restored.serial_number == expected_serial_number
        assert restored.fingerprint == expected_fingerprint
        assert restored_settings.root_serial_number == expected_root_serial_number
        assert restored_settings.root_fingerprint == expected_root_fingerprint


def test_settings_archive_preserves_oidc_retired_key_overlap(client):
    """Verify OIDC retired-key publication timestamps survive restore.

    Args:
        client: HTTP test client used to initialize isolated desired state.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import OidcSigningKey
    from atlaso.app.services import oidc
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    created_at = datetime(2026, 8, 13, 7, 0, tzinfo=timezone.utc)
    rotated_at = created_at + timedelta(minutes=5)
    with SessionLocal() as db:
        db.query(OidcSigningKey).delete()
        first, _ = oidc.generate_signing_key(db, rotate=False, now=created_at)
        _active, retired = oidc.generate_signing_key(db, rotate=True, now=rotated_at)
        assert retired is first
        expected_retired_at = retired.retired_at
        expected_publish_until = retired.publish_until
        assert expected_retired_at is not None
        assert expected_publish_until is not None
        retired_kid = retired.kid
        db.commit()

        archive = export_settings_archive(db, actor="test")
        archived = next(
            row
            for row in archive["data"]["oidc_signing_keys"]
            if row["kid"] == retired_kid
        )
        assert archived["retired_at"] == expected_retired_at.isoformat()
        assert archived["publish_until"] == expected_publish_until.isoformat()

        restore_settings_archive(db, archive)
        restored = db.scalar(
            select(OidcSigningKey).where(OidcSigningKey.kid == retired_kid)
        )
        assert restored is not None
        restored_retired_at = restored.retired_at
        restored_publish_until = restored.publish_until
        assert restored_retired_at is not None
        assert restored_publish_until is not None
        if restored_retired_at.tzinfo is None:
            restored_retired_at = restored_retired_at.replace(tzinfo=timezone.utc)
        if restored_publish_until.tzinfo is None:
            restored_publish_until = restored_publish_until.replace(tzinfo=timezone.utc)
        assert restored_retired_at == expected_retired_at
        assert restored_publish_until == expected_publish_until


def test_settings_archive_disables_registry_when_uploaded_ca_is_omitted(client):
    """Verify uploaded registry CA bytes become a safe disabled restore handoff.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, Setting, VcfPrivateRegistrySettings
    from atlaso.app.services.settings_archive import (
        archive_summary,
        export_settings_archive,
    )
    from atlaso.app.services.vcf_private_registry import (
        VCF_REGISTRY_UPLOADED_CA_BUNDLE_PATH,
        VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY,
    )

    with SessionLocal() as db:
        ca_settings = db.scalar(select(CaSettings))
        registry_settings = db.scalar(select(VcfPrivateRegistrySettings))
        assert ca_settings is not None
        assert registry_settings is not None
        ca_settings.enabled = False
        registry_settings.enabled = True
        registry_settings.ca_bundle_path = VCF_REGISTRY_UPLOADED_CA_BUNDLE_PATH
        db.add(
            Setting(
                key=VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY,
                value="-----BEGIN CERTIFICATE-----\nomitted\n-----END CERTIFICATE-----\n",
            )
        )
        db.commit()

        archive = export_settings_archive(db, actor="test")
        archived_registry = archive["data"]["vcf_private_registry_settings"][0]
        assert archived_registry["enabled"] is False
        assert all(
            row["key"] != VCF_REGISTRY_UPLOADED_CA_BUNDLE_PEM_KEY
            for row in archive["data"]["settings"]
        )
        assert any(
            "upload the bundle again before re-enabling" in note
            for note in archive["notes"]
        )
        archive_summary(archive)


def test_settings_restore_rejects_disabled_users_for_enabled_vcf_services(client):
    """Verify enabled restored VCF services require enabled retained local users.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from copy import deepcopy

    import pytest
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User, VcfBackupSettings
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        disabled_user = db.scalar(select(User).where(User.username == "vcf-backup"))
        assert disabled_user is not None
        assert disabled_user.enabled is False
        archive = export_settings_archive(db, actor="test")

        backup_archive = deepcopy(archive)
        backup_archive["data"]["vcf_backup_settings"][0]["enabled"] = True
        backup_archive["data"]["vcf_backup_settings"][0]["sftp_username"] = disabled_user.username
        with pytest.raises(ValueError, match="requires an enabled local user"):
            restore_settings_archive(db, backup_archive)

        depot_archive = deepcopy(archive)
        depot_archive["data"]["vcf_offline_depot_settings"][0]["enabled"] = True
        depot_archive["data"]["vcf_offline_depot_settings"][0]["allow_unauthenticated_access"] = False
        depot_archive["data"]["vcf_offline_depot_settings"][0]["http_username"] = disabled_user.username
        depot_archive["data"]["vcf_offline_depot_settings"][0]["listen_interface"] = "eth2"
        depot_archive["data"]["vcf_offline_depot_settings"][0]["listen_address"] = "192.168.50.1"
        with pytest.raises(ValueError, match="requires an enabled local user"):
            restore_settings_archive(db, depot_archive)

        missing_user_archive = deepcopy(archive)
        missing_user_archive["data"]["vcf_backup_settings"][0].update(
            {
                "enabled": True,
                "sftp_username": "vcf-backup",
                "listen_interface": "eth2",
                "listen_address": "192.168.50.1",
            }
        )
        retained_backup_settings = db.scalar(select(VcfBackupSettings))
        assert retained_backup_settings is not None
        retained_backup_settings.sftp_user_id = None
        db.flush()
        db.delete(disabled_user)
        db.commit()
        with pytest.raises(ValueError, match="requires an enabled local user"):
            restore_settings_archive(db, missing_user_archive)
        assert db.get(User, disabled_user.id) is None


def test_settings_restore_preflights_complete_vcf_service_state(client):
    """Verify restored VCF service settings pass their canonical validators.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from copy import deepcopy

    import pytest

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
        candidates = []

        invalid_backup = deepcopy(archive)
        invalid_backup["data"]["vcf_backup_settings"][0]["port"] = 0
        candidates.append(
            (
                invalid_backup,
                "VCF Backup state is invalid: SFTP port must be between 1 and 65535",
            )
        )

        invalid_registry = deepcopy(archive)
        invalid_registry["data"]["vcf_private_registry_settings"][0]["harbor_project"] = "BAD"
        candidates.append(
            (
                invalid_registry,
                "VCF Private Registry state is invalid: Harbor project must use lowercase",
            )
        )

        registry_without_ca = deepcopy(archive)
        registry_without_ca["data"]["ca_settings"][0]["enabled"] = False
        registry_without_ca["data"]["vcf_private_registry_settings"][0].update(
            {
                "enabled": True,
                "listen_interface": "eth2",
                "listen_address": "192.168.50.1",
            }
        )
        candidates.append(
            (
                registry_without_ca,
                "VCF Private Registry state is invalid: Upload a CA bundle or enable the local CA",
            )
        )

        invalid_depot = deepcopy(archive)
        invalid_depot["data"]["vcf_offline_depot_settings"][0]["config_path"] = "relative/path"
        candidates.append(
            (
                invalid_depot,
                "VCF Offline Depot state is invalid: HTTPS config path must be an absolute Linux path",
            )
        )

        for candidate, message in candidates:
            with pytest.raises(ValueError, match=message):
                restore_settings_archive(db, candidate)


def test_settings_restore_and_factory_reset_clear_staged_ldap_recovery(client):
    """Verify that settings restore and factory reset clear staged ldap recovery.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapRecoveryArchive
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        factory_reset_desired_state,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
        staged = LdapRecoveryArchive(
            filename="staged-restore.lfldap",
            path="memory://pending-ldap-recovery",
            sha256="a" * 64,
            state="staged",
            organization_count=1,
            created_by="test",
        )
        db.add(staged)
        db.commit()
        staged_id = staged.id
        LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] = b"restore secret"

        restore_settings_archive(db, archive)

        assert db.get(LdapRecoveryArchive, staged_id) is None
        assert staged_id not in LDAP_PENDING_RECOVERY_PAYLOADS

        reset_staged = LdapRecoveryArchive(
            filename="staged-reset.lfldap",
            path="memory://pending-ldap-recovery",
            sha256="b" * 64,
            state="staged",
            organization_count=1,
            created_by="test",
        )
        db.add(reset_staged)
        db.commit()
        reset_staged_id = reset_staged.id
        LDAP_PENDING_RECOVERY_PAYLOADS[reset_staged_id] = b"reset secret"

        factory_reset_desired_state(db)

        assert db.get(LdapRecoveryArchive, reset_staged_id) is None
        assert reset_staged_id not in LDAP_PENDING_RECOVERY_PAYLOADS


def test_settings_restore_rejects_malformed_archive_without_clearing_staged_ldap_recovery(client):
    """Verify malformed settings archives preserve staged ldap recovery state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json
    from copy import deepcopy

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapRecoveryArchive
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS
    from atlaso.app.services.settings_archive import export_settings_archive

    login(client)
    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
        staged = LdapRecoveryArchive(
            filename="staged-invalid-restore.lfldap",
            path="memory://pending-ldap-recovery",
            sha256="c" * 64,
            state="staged",
            organization_count=1,
            created_by="test",
        )
        db.add(staged)
        db.commit()
        staged_id = staged.id
        LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] = b"pending recovery payload"

    invalid_scalar_archive = deepcopy(archive)
    invalid_scalar_archive["data"]["ldap_settings"][0]["port"] = "636"
    archive["data"]["physical_interfaces"] = {"unexpected": "object"}
    page = client.get("/backup-restore")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    restored = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={
            "archive_file": (
                "atlaso-settings.json",
                json.dumps(archive).encode("utf-8"),
                "application/json",
            )
        },
    )
    invalid_scalar = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={
            "archive_file": (
                "atlaso-settings.json",
                json.dumps(invalid_scalar_archive).encode("utf-8"),
                "application/json",
            )
        },
    )

    try:
        assert restored.status_code == 400
        assert "physical_interfaces" in restored.text
        assert "must be a list" in restored.text
        assert invalid_scalar.status_code == 400
        assert "field &#39;port&#39; must be an integer" in invalid_scalar.text
        with SessionLocal() as db:
            assert db.get(LdapRecoveryArchive, staged_id) is not None
        assert LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] == b"pending recovery payload"
    finally:
        LDAP_PENDING_RECOVERY_PAYLOADS.pop(staged_id, None)


def test_settings_archive_unique_identity_preflight_covers_all_unguarded_constraints():
    """Verify every unguarded database identity rejects duplicate archive rows."""
    import pytest

    from atlaso.app.services.settings_archive import (
        ARCHIVE_UNGUARDED_UNIQUE_IDENTITIES,
        _validate_archive_unique_identities,
    )

    for section_name, duplicate_fields in ARCHIVE_UNGUARDED_UNIQUE_IDENTITIES:
        section_specs = [
            fields
            for candidate_section, fields in ARCHIVE_UNGUARDED_UNIQUE_IDENTITIES
            if candidate_section == section_name
        ]
        section_fields = {field_name for fields in section_specs for field_name in fields}
        rows = [
            {field_name: f"{field_name}-{row_index}" for field_name in section_fields}
            for row_index in (1, 2)
        ]
        for field_name in duplicate_fields:
            rows[1][field_name] = rows[0][field_name]
        with pytest.raises(
            ValueError,
            match=rf"'{section_name}'.*unique {', '.join(duplicate_fields)} identity",
        ):
            _validate_archive_unique_identities({section_name: rows})


@pytest.mark.parametrize(
    "managed_owner",
    ["appliance:https", "ntp:nts", "kms:server", "oidc:https"],
)
def test_settings_archive_managed_certificate_readiness_requires_enabled_row(
    managed_owner,
):
    """Verify disabled managed certificates cannot satisfy service readiness.

    Args:
        managed_owner: Atlaso-managed service certificate owner under test.
    """
    from atlaso.app.services.settings_archive import (
        _archive_managed_certificate_ready,
    )

    certificate = {
        "enabled": False,
        "managed_owner": managed_owner,
        "status": "issued",
        "certificate_pem": "public-certificate",
        "private_key_encrypted": "encrypted-private-key",
    }

    assert not _archive_managed_certificate_ready([certificate], managed_owner)
    certificate["enabled"] = True
    assert _archive_managed_certificate_ready([certificate], managed_owner)


def test_settings_archive_nts_paths_match_managed_certificate():
    """Verify restored NTS settings use the managed certificate deployment paths."""
    from atlaso.app.services.settings_archive import (
        _archive_nts_certificate_paths_match,
    )

    settings = {
        "nts_server_cert_path": "/etc/atlaso/ntp/certs/ntp-chain.pem",
        "nts_server_key_path": "/etc/atlaso/ntp/certs/ntp.key",
    }
    certificate = {
        "chain_path": "/etc/atlaso/ntp/certs/ntp-chain.pem",
        "key_path": "/etc/atlaso/ntp/certs/ntp.key",
    }

    assert _archive_nts_certificate_paths_match(settings, certificate)
    settings["nts_server_cert_path"] = "/tmp/missing-chain.pem"
    assert not _archive_nts_certificate_paths_match(settings, certificate)


def test_settings_archive_preflight_rejects_invalid_collection_row_and_required_field_shapes(client):
    """Verify settings archive preflight rejects malformed structures before restore.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import hashlib
    from copy import deepcopy

    import pytest

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.oidc import hash_client_secret
    from atlaso.app.services.settings_archive import (
        archive_summary,
        export_settings_archive,
    )

    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
    assert archive["data"]["physical_interfaces"]

    invalid_collection = deepcopy(archive)
    invalid_collection["data"]["physical_interfaces"] = {}
    invalid_row = deepcopy(archive)
    invalid_row["data"]["physical_interfaces"] = ["not an object"]
    missing_required_field = deepcopy(archive)
    del missing_required_field["data"]["physical_interfaces"][0]["name"]
    missing_section = deepcopy(archive)
    del missing_section["data"]["physical_interfaces"]
    empty_data = deepcopy(archive)
    empty_data["data"] = {}
    empty_singleton = deepcopy(archive)
    empty_singleton["data"]["appliance_settings"] = []
    duplicate_oidc_singleton = deepcopy(archive)
    duplicate_oidc_singleton["data"]["oidc_provider_settings"] = [{}, {}]
    unsupported_schema = deepcopy(archive)
    unsupported_schema["schema_version"] = 1
    enabled_missing_parent_vlan = deepcopy(archive)
    enabled_missing_parent_vlan["data"]["vlan_interfaces"].append(
        {"name": "missing-parent.123", "parent_interface": "missing-parent", "vlan_id": 123, "enabled": True}
    )
    enabled_non_trunk_vlan = deepcopy(archive)
    enabled_non_trunk_vlan["data"]["physical_interfaces"].append(
        {"name": "archive-access", "mac_address": "02:00:00:00:00:01", "mode": "access"}
    )
    enabled_non_trunk_vlan["data"]["vlan_interfaces"].append(
        {"name": "archive-access.124", "parent_interface": "archive-access", "vlan_id": 124, "enabled": True}
    )
    disabled_missing_parent_vlan = deepcopy(enabled_missing_parent_vlan)
    disabled_missing_parent_vlan["data"]["vlan_interfaces"][-1]["enabled"] = False
    enabled_missing_route_target = deepcopy(archive)
    enabled_missing_route_target["data"]["routes"][0]["interface_name"] = "missing-route-target"
    enabled_ineligible_route_target = deepcopy(archive)
    enabled_ineligible_route_target["data"]["routes"][0]["interface_name"] = "eth1"
    disabled_missing_route_target = deepcopy(enabled_missing_route_target)
    disabled_missing_route_target["data"]["routes"][0]["enabled"] = False
    enabled_missing_nat_target = deepcopy(archive)
    enabled_missing_nat_target["data"]["nat_rules"][0]["outbound_interface"] = "missing-nat-target"
    enabled_ipv6_only_nat_target = deepcopy(archive)
    enabled_ipv6_only_nat_target["data"]["physical_interfaces"].append(
        {
            "name": "ipv6-only",
            "mac_address": "02:00:00:00:00:02",
            "mode": "access",
            "role": "route",
            "ipv6_enabled": True,
            "ipv6_cidr": "fd00:1234::1/64",
        }
    )
    enabled_ipv6_only_nat_target["data"]["nat_rules"][0]["outbound_interface"] = "ipv6-only"
    disabled_missing_nat_target = deepcopy(enabled_missing_nat_target)
    disabled_missing_nat_target["data"]["nat_rules"][0]["enabled"] = False
    enabled_missing_nat_source_group = deepcopy(archive)
    enabled_missing_nat_source_group["data"]["nat_rules"][0]["source"] = "group:missing"
    disabled_missing_nat_source_group = deepcopy(enabled_missing_nat_source_group)
    disabled_missing_nat_source_group["data"]["nat_rules"][0]["enabled"] = False
    missing_firewall_source_group = deepcopy(archive)
    missing_firewall_source_group["data"]["firewall_rules"][0]["source"] = "group:missing"
    enabled_missing_routing_target = deepcopy(archive)
    enabled_missing_routing_target["data"]["routing_rules"].append(
        {
            "name": "missing route permission",
            "source_interface": "missing-routing-target",
            "destination_interface": "eth1.20",
            "enabled": True,
        }
    )
    enabled_identical_routing_targets = deepcopy(enabled_missing_routing_target)
    enabled_identical_routing_targets["data"]["routing_rules"][-1]["source_interface"] = "eth1.20"
    disabled_missing_routing_target = deepcopy(enabled_missing_routing_target)
    disabled_missing_routing_target["data"]["routing_rules"][-1]["enabled"] = False
    enabled_missing_dhcp_target = deepcopy(archive)
    enabled_missing_dhcp_target["data"]["dhcp_settings"][0]["enabled"] = True
    enabled_missing_dhcp_target["data"]["dhcp_scopes"][0]["interface_name"] = "missing-dhcp-target"
    enabled_wrong_family_dhcp_target = deepcopy(archive)
    enabled_wrong_family_dhcp_target["data"]["dhcp_settings"][0]["enabled"] = True
    enabled_wrong_family_dhcp_target["data"]["dhcp_scopes"][0].update(
        {
            "address_family": "ipv6",
            "site_address": "fd00:1234::1",
            "prefix_length": 64,
            "range_expression": "fd00:1234::100-fd00:1234::200",
            "dns_server": "fd00:1234::1",
            "ntp_server": "",
        }
    )
    disabled_missing_dhcp_target = deepcopy(enabled_missing_dhcp_target)
    disabled_missing_dhcp_target["data"]["dhcp_scopes"][0]["enabled"] = False
    disabled_missing_dhcp_target["data"]["dhcp_settings"][0]["enabled"] = False
    enabled_management_dhcp_target = deepcopy(archive)
    enabled_management_dhcp_target["data"]["dhcp_settings"][0]["enabled"] = True
    enabled_management_dhcp_target["data"]["dhcp_scopes"][0][
        "interface_name"
    ] = "eth0"
    enabled_without_enabled_dhcp_scope = deepcopy(archive)
    enabled_without_enabled_dhcp_scope["data"]["dhcp_settings"][0]["enabled"] = True
    for scope in enabled_without_enabled_dhcp_scope["data"]["dhcp_scopes"]:
        scope["enabled"] = False
    enabled_with_invalid_disabled_dhcp_scope = deepcopy(archive)
    enabled_with_invalid_disabled_dhcp_scope["data"]["dhcp_settings"][0]["enabled"] = True
    enabled_with_invalid_disabled_dhcp_scope["data"]["dhcp_scopes"].append(
        {
            "name": "invalid-disabled-scope",
            "address_family": "ipv4",
            "interface_name": "eth2",
            "site_address": "not-an-address",
            "prefix_length": 24,
            "range_expression": "192.168.50.100-192.168.50.200",
            "lease_time": "12h",
            "domain_name": "atlaso.internal",
            "dns_server": "192.168.50.1",
            "ntp_server": "",
            "enabled": False,
        }
    )
    disabled_with_invalid_disabled_dhcp_scope = deepcopy(
        enabled_with_invalid_disabled_dhcp_scope
    )
    disabled_with_invalid_disabled_dhcp_scope["data"]["dhcp_settings"][0][
        "enabled"
    ] = False
    enabled_outside_dhcp_reservation = deepcopy(archive)
    enabled_outside_dhcp_reservation["data"]["dhcp_settings"][0]["enabled"] = True
    enabled_outside_dhcp_reservation["data"]["dhcp_reservations"][0]["enabled"] = True
    enabled_outside_dhcp_reservation["data"]["dhcp_reservations"][0]["ip_address"] = "203.0.113.10"
    disabled_invalid_dhcp_reservation = deepcopy(archive)
    disabled_invalid_dhcp_reservation["data"]["dhcp_settings"][0]["enabled"] = False
    disabled_invalid_dhcp_reservation["data"]["dhcp_reservations"][0].update(
        {"enabled": False, "ip_address": "not-an-address"}
    )
    enabled_missing_service_targets = []
    for section_name in (
        "dns_settings",
        "ntp_settings",
        "ca_settings",
        "kms_settings",
        "ldap_settings",
        "oidc_provider_settings",
        "vcf_backup_settings",
        "vcf_private_registry_settings",
        "vcf_offline_depot_settings",
    ):
        candidate = deepcopy(archive)
        if not candidate["data"][section_name]:
            continue
        candidate["data"][section_name][0]["enabled"] = True
        candidate["data"][section_name][0]["listen_interface"] = "missing-service-target"
        enabled_missing_service_targets.append(candidate)
    disabled_missing_service_target = deepcopy(enabled_missing_service_targets[0])
    disabled_missing_service_target["data"]["dns_settings"][0]["enabled"] = False
    enabled_missing_listen_address = deepcopy(archive)
    enabled_missing_listen_address["data"]["ntp_settings"][0]["enabled"] = True
    enabled_missing_listen_address["data"]["ntp_settings"][0]["listen_interface"] = "eth2"
    enabled_missing_listen_address["data"]["ntp_settings"][0]["listen_address"] = ""
    enabled_invalid_listen_address = deepcopy(archive)
    enabled_invalid_listen_address["data"]["ntp_settings"][0]["enabled"] = True
    enabled_invalid_listen_address["data"]["ntp_settings"][0]["listen_interface"] = "eth2"
    enabled_invalid_listen_address["data"]["ntp_settings"][0]["listen_address"] = "not-an-ip"
    enabled_mismatched_service_addresses = []
    for section_name in (
        "dns_settings",
        "ntp_settings",
        "ca_settings",
        "kms_settings",
        "ldap_settings",
        "oidc_provider_settings",
        "vcf_backup_settings",
        "vcf_private_registry_settings",
        "vcf_offline_depot_settings",
    ):
        candidate = deepcopy(archive)
        if not candidate["data"][section_name]:
            continue
        candidate["data"][section_name][0]["enabled"] = True
        candidate["data"][section_name][0]["listen_interface"] = "eth2"
        candidate["data"][section_name][0]["listen_address"] = "192.0.2.20"
        enabled_mismatched_service_addresses.append(candidate)
    enabled_missing_web_terminal_target = deepcopy(archive)
    enabled_missing_web_terminal_target["data"]["appliance_settings"][0]["web_terminal_enabled"] = True
    enabled_missing_web_terminal_target["data"]["appliance_settings"][0]["management_https_enabled"] = True
    enabled_missing_web_terminal_target["data"]["appliance_settings"][0][
        "web_terminal_interfaces_json"
    ] = '["missing-terminal-target"]'
    invalid_network_state = deepcopy(archive)
    invalid_network_state["data"]["physical_interfaces"][0]["mtu"] = 1
    invalid_scalar_type = deepcopy(archive)
    invalid_scalar_type["data"]["ldap_settings"][0]["port"] = "636"
    invalid_appliance_config_path = deepcopy(archive)
    invalid_appliance_config_path["data"]["appliance_settings"][0]["config_path"] = "relative/path"
    enabled_web_terminal_without_https = deepcopy(archive)
    enabled_web_terminal_without_https["data"]["appliance_settings"][0]["web_terminal_enabled"] = True
    enabled_web_terminal_without_https["data"]["appliance_settings"][0]["management_https_enabled"] = False
    appliance_dns_ownership_conflict = deepcopy(archive)
    appliance_dns_ownership_conflict["data"]["dns_settings"][0]["enabled"] = True
    appliance_dns_ownership_conflict["data"]["dns_records"].append(
        {
            "hostname": appliance_dns_ownership_conflict["data"]["appliance_settings"][0]["fqdn"],
            "record_type": "A",
            "address": "192.0.2.10",
            "description": "Operator-owned record",
            "enabled": True,
        }
    )
    invalid_ntp_port = deepcopy(archive)
    invalid_ntp_port["data"]["ntp_settings"][0]["port"] = 124
    enabled_nts_without_ca = deepcopy(archive)
    enabled_nts_without_ca["data"]["ntp_settings"][0].update(
        {
            "nts_server_enabled": True,
            "nts_server_cert_path": "/etc/atlaso/ntp/nts-chain.pem",
            "nts_server_key_path": "/etc/atlaso/ntp/nts-key.pem",
        }
    )
    enabled_nts_without_ca["data"]["ca_settings"][0]["enabled"] = False
    invalid_dns_domain = deepcopy(archive)
    invalid_dns_domain["data"]["dns_settings"][0]["domain"] = "bad domain"
    invalid_route_destination = deepcopy(archive)
    invalid_route_destination["data"]["routes"][0]["destination_cidr"] = "not-a-cidr"
    invalid_firewall_policy = deepcopy(archive)
    invalid_firewall_policy["data"]["firewall_settings"][0]["default_input_policy"] = "reject"
    invalid_kms_port = deepcopy(archive)
    invalid_kms_port["data"]["kms_settings"][0]["port"] = 0
    invalid_legacy_dhcp = deepcopy(archive)
    invalid_legacy_dhcp["data"]["dhcp_scopes"] = []
    invalid_legacy_dhcp["data"]["dhcp_settings"][0].update(
        {
            "enabled": True,
            "interface_name": "eth2",
            "site_address": "not-an-address",
            "prefix_length": 24,
        }
    )
    empty_required_field = deepcopy(archive)
    empty_required_field["data"]["physical_interfaces"][0]["name"] = "   "
    unresolved_ldap_organization = deepcopy(archive)
    unresolved_ldap_organization["data"]["ldap_users"].append(
        {"organization_slug": "missing-organization", "uid": "orphaned-user"}
    )
    enabled_ldap_without_organization = deepcopy(archive)
    enabled_ldap_without_organization["data"]["ldap_settings"][0]["enabled"] = True
    enabled_ldap_without_organization["data"]["ldap_settings"][0]["listen_interface"] = "eth2"
    enabled_ldap_without_organization["data"]["ldap_settings"][0]["listen_address"] = "192.168.50.1"
    enabled_ldap_without_organization["data"]["ldap_organizations"] = []
    enabled_ldaps_without_ca = deepcopy(archive)
    enabled_ldaps_without_ca["data"]["ldap_settings"][0]["enabled"] = True
    enabled_ldaps_without_ca["data"]["ldap_settings"][0]["ldaps_enabled"] = True
    enabled_ldaps_without_ca["data"]["ldap_settings"][0]["listen_interface"] = "eth2"
    enabled_ldaps_without_ca["data"]["ldap_settings"][0]["listen_address"] = "192.168.50.1"
    enabled_ldaps_without_ca["data"]["ldap_organizations"].append(
        {"name": "LDAPS test", "slug": "ldaps-test", "suffix_dn": "dc=ldaps,dc=test"}
    )
    enabled_ldaps_without_ca["data"]["ca_settings"][0]["enabled"] = False
    enabled_ldap_with_invalid_port = deepcopy(enabled_ldaps_without_ca)
    enabled_ldap_with_invalid_port["data"]["ca_settings"][0]["enabled"] = True
    enabled_ldap_with_invalid_port["data"]["ca_settings"][0]["root_certificate_pem"] = "certificate"
    enabled_ldap_with_invalid_port["data"]["ldap_organizations"][0]["bind_password_encrypted"] = "encrypted"
    enabled_ldap_with_invalid_port["data"]["ldap_settings"][0]["port"] = 0
    enabled_ldap_user_without_password = deepcopy(archive)
    enabled_ldap_user_without_password["data"]["ldap_organizations"].append(
        {
            "name": "Password recovery test",
            "slug": "password-recovery-test",
            "suffix_dn": "dc=password-recovery,dc=test",
            "bind_password_encrypted": "encrypted",
        }
    )
    enabled_ldap_user_without_password["data"]["ldap_users"].append(
        {
            "organization_slug": "password-recovery-test",
            "uid": "missing-password",
            "enabled": True,
            "password_status": "not_staged",
        }
    )
    unresolved_oidc_client = deepcopy(archive)
    unresolved_oidc_client["data"]["oidc_client_redirect_uris"].append(
        {"client_id": "missing-client", "kind": "redirect", "uri": "https://example.invalid/callback"}
    )
    oidc_client_without_redirect = deepcopy(archive)
    valid_client_hash = hash_client_secret("archive-validation-secret")
    oidc_client_without_redirect["data"]["oidc_clients"].append(
        {
            "name": "Missing redirect client",
            "client_id": "missing-redirect-client",
            "client_secret_hash": valid_client_hash,
            "enabled": True,
        }
    )
    oidc_client_with_invalid_lifetime = deepcopy(oidc_client_without_redirect)
    oidc_client_with_invalid_lifetime["data"]["oidc_clients"][-1][
        "authorization_code_lifetime_seconds"
    ] = -1
    oidc_client_with_invalid_lifetime["data"]["oidc_client_redirect_uris"].append(
        {
            "client_id": "missing-redirect-client",
            "kind": "redirect",
            "uri": "https://example.invalid/callback",
        }
    )
    oidc_client_with_invalid_hash = deepcopy(oidc_client_with_invalid_lifetime)
    oidc_client_with_invalid_hash["data"]["oidc_clients"][-1][
        "authorization_code_lifetime_seconds"
    ] = 60
    oidc_client_with_invalid_hash["data"]["oidc_clients"][-1]["client_secret_hash"] = "not-a-hash"
    duplicate_oidc_client = deepcopy(oidc_client_with_invalid_lifetime)
    duplicate_oidc_client["data"]["oidc_clients"].append(
        deepcopy(duplicate_oidc_client["data"]["oidc_clients"][-1])
    )
    duplicate_oidc_subject_uuid = deepcopy(archive)
    duplicate_oidc_subject_uuid["data"]["oidc_subjects"].extend(
        [
            {
                "subject_uuid": "11111111-1111-4111-8111-111111111111",
                "source": "local",
                "username": "subject-source-a",
                "organization_slug": "",
            },
            {
                "subject_uuid": "11111111-1111-4111-8111-111111111111",
                "source": "local",
                "username": "subject-source-b",
                "organization_slug": "",
            },
        ]
    )
    duplicate_oidc_subject_source = deepcopy(duplicate_oidc_subject_uuid)
    duplicate_oidc_subject_source["data"]["oidc_subjects"][1][
        "subject_uuid"
    ] = "22222222-2222-4222-8222-222222222222"
    duplicate_oidc_subject_source["data"]["oidc_subjects"][1][
        "username"
    ] = "subject-source-a"
    invalid_oidc_subject_scalar = deepcopy(archive)
    invalid_oidc_subject_scalar["data"]["oidc_subjects"].append(
        {
            "subject_uuid": 123,
            "source": "local",
            "username": "invalid-scalar-subject",
            "organization_slug": "",
        }
    )
    invalid_oidc_subject_uuid = deepcopy(archive)
    invalid_oidc_subject_uuid["data"]["oidc_subjects"].append(
        {
            "subject_uuid": "not-a-uuid",
            "source": "local",
            "username": "invalid-uuid-subject",
            "organization_slug": "",
        }
    )
    duplicate_oidc_mapping = deepcopy(archive)
    duplicate_oidc_mapping["data"]["oidc_group_mappings"] = [
        {
            "source_type": "local_role",
            "local_role": "admin",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "",
            "external_group_name": "Administrators",
        },
        {
            "source_type": "local_role",
            "local_role": "ADMIN",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "",
            "external_group_name": "Atlaso admins",
        },
    ]
    invalid_oidc_mapping_scalar = deepcopy(archive)
    invalid_oidc_mapping_scalar["data"]["oidc_group_mappings"].append(
        {
            "source_type": "local_role",
            "local_role": "admin",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "",
            "external_group_name": True,
        }
    )
    effective_oidc_mapping_collision = deepcopy(archive)
    effective_oidc_mapping_collision["data"]["oidc_clients"].append(
        {
            "name": "Effective mapping client",
            "client_id": "effective-mapping-client",
            "client_secret_hash": valid_client_hash,
            "organization_slug": "",
            "enabled": True,
        }
    )
    effective_oidc_mapping_collision["data"]["oidc_client_redirect_uris"].append(
        {
            "client_id": "effective-mapping-client",
            "kind": "redirect",
            "uri": "https://effective-mapping.example.test/callback",
        }
    )
    effective_oidc_mapping_collision["data"]["oidc_group_mappings"] = [
        {
            "source_type": "local_role",
            "local_role": "admin",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "",
            "external_group_name": "Shared external group",
        },
        {
            "source_type": "local_role",
            "local_role": "viewer",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "effective-mapping-client",
            "external_group_name": " shared EXTERNAL group ",
        },
    ]
    cross_organization_oidc_mapping = deepcopy(archive)
    cross_organization_oidc_mapping["data"]["ldap_organizations"].extend(
        [
            {
                "name": "Mapping organization A",
                "slug": "mapping-organization-a",
                "suffix_dn": "dc=mapping-a,dc=test",
            },
            {
                "name": "Mapping organization B",
                "slug": "mapping-organization-b",
                "suffix_dn": "dc=mapping-b,dc=test",
            },
        ]
    )
    cross_organization_oidc_mapping["data"]["ldap_groups"].append(
        {
            "organization_slug": "mapping-organization-a",
            "name": "Mapping group A",
            "enabled": False,
        }
    )
    cross_organization_oidc_mapping["data"]["oidc_clients"].append(
        {
            "name": "Mapping client B",
            "client_id": "mapping-client-b",
            "client_secret_hash": valid_client_hash,
            "organization_slug": "mapping-organization-b",
            "enabled": True,
        }
    )
    cross_organization_oidc_mapping["data"]["oidc_client_redirect_uris"].append(
        {
            "client_id": "mapping-client-b",
            "kind": "redirect",
            "uri": "https://mapping.example.test/callback",
        }
    )
    cross_organization_oidc_mapping["data"]["oidc_group_mappings"].append(
        {
            "source_type": "ldap_group",
            "local_role": "",
            "ldap_group_name": "Mapping group A",
            "organization_slug": "mapping-organization-a",
            "client_id": "mapping-client-b",
            "external_group_name": "Mapping group",
        }
    )
    bound_client_local_role_mapping = deepcopy(cross_organization_oidc_mapping)
    bound_client_local_role_mapping["data"]["oidc_group_mappings"] = [
        {
            "source_type": "local_role",
            "local_role": "admin",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "mapping-client-b",
            "external_group_name": "Administrators",
        }
    ]
    unbound_client_ldap_mapping = deepcopy(cross_organization_oidc_mapping)
    unbound_client_ldap_mapping["data"]["oidc_clients"][-1]["organization_slug"] = ""
    unresolved_esx_volume = deepcopy(archive)
    unresolved_esx_volume["data"]["esx_nfs_shares"].append(
        {"datastore_name": "orphaned-datastore", "volume_name": "missing-volume"}
    )
    enabled_missing_esx_share_target = deepcopy(archive)
    enabled_missing_esx_share_target["data"]["esx_storage_volumes"].append(
        {"name": "archive-volume"}
    )
    enabled_missing_esx_share_target["data"]["esx_nfs_shares"].append(
        {
            "datastore_name": "archive-share",
            "volume_name": "archive-volume",
            "interface_name": "missing-storage-target",
            "address_families": "ipv4",
            "enabled": True,
        }
    )
    cyclic_ldap_groups = deepcopy(archive)
    cyclic_ldap_groups["data"]["ldap_organizations"].append(
        {"name": "Cycle test", "slug": "cycle-test", "suffix_dn": "dc=cycle,dc=test"}
    )
    cyclic_ldap_groups["data"]["ldap_groups"].extend(
        [
            {"organization_slug": "cycle-test", "name": "first"},
            {"organization_slug": "cycle-test", "name": "second"},
        ]
    )
    cyclic_ldap_groups["data"]["ldap_group_memberships"].extend(
        [
            {
                "organization_slug": "cycle-test",
                "group_name": "first",
                "member_type": "group",
                "member_name": "second",
            },
            {
                "organization_slug": "cycle-test",
                "group_name": "second",
                "member_type": "group",
                "member_name": "first",
            },
        ]
    )
    invalid_ldap_group = deepcopy(archive)
    invalid_ldap_group["data"]["ldap_organizations"].append(
        {"name": "Group validation", "slug": "group-validation", "suffix_dn": "dc=group,dc=test"}
    )
    invalid_ldap_group["data"]["ldap_groups"].append(
        {"organization_slug": "group-validation", "name": "invalid/group", "enabled": True}
    )
    duplicate_ldap_group = deepcopy(archive)
    duplicate_ldap_group["data"]["ldap_organizations"].append(
        {"name": "Duplicate group", "slug": "duplicate-group", "suffix_dn": "dc=duplicate,dc=test"}
    )
    duplicate_ldap_group["data"]["ldap_groups"].extend(
        [
            {"organization_slug": "duplicate-group", "name": "same", "enabled": False},
            {"organization_slug": "duplicate-group", "name": "same", "enabled": False},
        ]
    )
    invalid_oidc_mapping_role = deepcopy(archive)
    invalid_oidc_mapping_role["data"]["oidc_group_mappings"].append(
        {
            "source_type": "local_role",
            "local_role": "superadmin",
            "ldap_group_name": "",
            "organization_slug": "",
            "client_id": "",
            "external_group_name": "Administrators",
        }
    )
    invalid_oidc_external_group = deepcopy(invalid_oidc_mapping_role)
    invalid_oidc_external_group["data"]["oidc_group_mappings"][-1]["local_role"] = "admin"
    invalid_oidc_external_group["data"]["oidc_group_mappings"][-1]["external_group_name"] = "\x00"
    enabled_certificate_with_disabled_profile = deepcopy(archive)
    certificate_profile_name = enabled_certificate_with_disabled_profile["data"]["ca_certificates"][0][
        "profile_name"
    ]
    certificate_profile = next(
        profile
        for profile in enabled_certificate_with_disabled_profile["data"]["ca_profiles"]
        if profile["name"] == certificate_profile_name
    )
    certificate_profile["enabled"] = False
    enabled_certificate_with_disabled_profile["data"]["ca_certificates"][0]["enabled"] = True
    weak_ca_profile = deepcopy(archive)
    weak_ca_profile["data"]["ca_profiles"][0]["key_algorithm"] = "RSA"
    weak_ca_profile["data"]["ca_profiles"][0]["key_size"] = 1024
    enabled_kms_without_ca = deepcopy(archive)
    enabled_kms_without_ca["data"]["kms_settings"][0]["enabled"] = True
    enabled_kms_without_ca["data"]["kms_settings"][0]["listen_interface"] = "eth2"
    enabled_kms_without_ca["data"]["kms_settings"][0]["listen_address"] = "192.168.50.1"
    enabled_kms_without_ca["data"]["ca_settings"][0]["enabled"] = False
    enabled_kms_without_ca["data"]["vsphere_key_providers"] = [
        {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "CA dependency test provider",
            "enabled": True,
        }
    ]
    enabled_kms_without_provider = deepcopy(archive)
    enabled_kms_without_provider["data"]["kms_settings"][0].update(
        {
            "enabled": True,
            "listen_interface": "eth2",
            "listen_address": "192.168.50.1",
        }
    )
    kms_certificate = deepcopy(enabled_kms_without_provider["data"]["ca_certificates"][0])
    kms_certificate.update(
        {
            "managed_owner": "kms:server",
            "status": "issued",
            "certificate_pem": "certificate",
            "private_key_encrypted": "encrypted-key",
        }
    )
    enabled_kms_without_provider["data"]["ca_certificates"].append(kms_certificate)
    enabled_kms_without_provider["data"]["vsphere_key_providers"] = []
    enabled_kms_without_provider["data"]["vsphere_trusted_vcenters"] = []
    enabled_kms_without_provider["data"]["vsphere_trusted_vcenter_certificates"] = []
    invalid_provider_id = deepcopy(archive)
    invalid_provider_id["data"]["vsphere_key_providers"].append(
        {"id": "not-a-uuid", "name": "Invalid provider ID", "enabled": False}
    )
    invalid_vcenter_id = deepcopy(archive)
    invalid_vcenter_id["data"]["vsphere_key_providers"].append(
        {
            "id": "11111111-1111-4111-8111-111111111111",
            "name": "Invalid vCenter ID provider",
            "enabled": False,
        }
    )
    invalid_vcenter_id["data"]["vsphere_trusted_vcenters"].append(
        {
            "id": "not-a-uuid",
            "provider_id": "11111111-1111-4111-8111-111111111111",
            "name": "Invalid vCenter ID",
            "enabled": False,
        }
    )
    invalid_provider_enabled_type = deepcopy(archive)
    invalid_provider_enabled_type["data"]["vsphere_key_providers"].append(
        {
            "id": "11111111-1111-4111-8111-111111111112",
            "name": "Invalid enabled type",
            "enabled": "false",
        }
    )
    duplicate_provider_name = deepcopy(archive)
    duplicate_provider_name["data"]["vsphere_key_providers"].extend(
        [
            {
                "id": "11111111-1111-4111-8111-111111111121",
                "name": "Duplicate provider name",
                "enabled": False,
            },
            {
                "id": "11111111-1111-4111-8111-111111111122",
                "name": "Duplicate provider name",
                "enabled": False,
            },
        ]
    )
    duplicate_vcenter_name = deepcopy(archive)
    duplicate_vcenter_name["data"]["vsphere_key_providers"].append(
        {
            "id": "11111111-1111-4111-8111-111111111123",
            "name": "Duplicate vCenter provider",
            "enabled": False,
        }
    )
    duplicate_vcenter_name["data"]["vsphere_trusted_vcenters"].extend(
        [
            {
                "id": "22222222-2222-4222-8222-222222222231",
                "provider_id": "11111111-1111-4111-8111-111111111123",
                "name": "Duplicate vCenter name",
                "enabled": False,
            },
            {
                "id": "22222222-2222-4222-8222-222222222232",
                "provider_id": "11111111-1111-4111-8111-111111111123",
                "name": "Duplicate vCenter name",
                "enabled": False,
            },
        ]
    )
    invalid_vcenter_enabled_type = deepcopy(archive)
    invalid_vcenter_enabled_type["data"]["vsphere_key_providers"].append(
        {
            "id": "11111111-1111-4111-8111-111111111113",
            "name": "Enabled type test provider",
            "enabled": False,
        }
    )
    invalid_vcenter_enabled_type["data"]["vsphere_trusted_vcenters"].append(
        {
            "id": "22222222-2222-4222-8222-222222222222",
            "provider_id": "11111111-1111-4111-8111-111111111113",
            "name": "Invalid enabled type",
            "enabled": "false",
        }
    )
    disabled_kms_with_invalid_public_certificate = deepcopy(archive)
    disabled_kms_with_invalid_public_certificate["data"]["vsphere_key_providers"].append(
        {
            "id": "11111111-1111-4111-8111-111111111114",
            "name": "Disabled certificate test provider",
            "enabled": False,
        }
    )
    disabled_kms_with_invalid_public_certificate["data"]["vsphere_trusted_vcenters"].append(
        {
            "id": "22222222-2222-4222-8222-222222222223",
            "provider_id": "11111111-1111-4111-8111-111111111114",
            "name": "Disabled certificate test vCenter",
            "enabled": False,
        }
    )
    disabled_kms_with_invalid_public_certificate["data"][
        "vsphere_trusted_vcenter_certificates"
    ].append(
        {
            "id": "33333333-3333-4333-8333-333333333333",
            "trusted_vcenter_id": "22222222-2222-4222-8222-222222222223",
            "fingerprint_sha256": "0" * 64,
            "certificate_pem": "not-a-certificate",
        }
    )
    invalid_vcenter_certificate_id = deepcopy(disabled_kms_with_invalid_public_certificate)
    invalid_vcenter_certificate_id["data"]["vsphere_trusted_vcenter_certificates"][0][
        "id"
    ] = "invalid/certificate-id"
    enabled_oidc_without_dependencies = deepcopy(archive)
    enabled_oidc_without_dependencies["data"]["oidc_provider_settings"] = [
        {
            "enabled": True,
            "listen_interface": "eth2",
            "listen_address": "192.168.50.1",
        }
    ]
    enabled_oidc_without_dependencies["data"]["oidc_signing_keys"] = []
    enabled_oidc_with_mismatched_address = deepcopy(archive)
    enabled_oidc_with_mismatched_address["data"]["oidc_provider_settings"] = [
        {
            "enabled": True,
            "listen_interface": "eth2",
            "listen_address": "192.0.2.1",
        }
    ]
    enabled_oidc_with_mismatched_address["data"]["oidc_signing_keys"] = [
        {
            "kid": "archive-active-key",
            "private_key_encrypted": "encrypted-key",
            "public_jwk_json": "{}",
            "status": "active",
            "active_slot": 1,
            "created_at": "2026-08-13T06:00:00+00:00",
            "activated_at": "2026-08-13T06:00:00+00:00",
            "retired_at": None,
            "publish_until": None,
        }
    ]
    oidc_certificate = deepcopy(enabled_oidc_with_mismatched_address["data"]["ca_certificates"][0])
    oidc_certificate["managed_owner"] = "oidc:https"
    oidc_certificate["status"] = "issued"
    oidc_certificate["certificate_pem"] = "certificate"
    oidc_certificate["private_key_encrypted"] = "encrypted-key"
    enabled_oidc_with_mismatched_address["data"]["ca_certificates"].append(oidc_certificate)
    enabled_oidc_with_invalid_port = deepcopy(enabled_oidc_with_mismatched_address)
    enabled_oidc_with_invalid_port["data"]["oidc_provider_settings"][0]["listen_address"] = "192.168.50.1"
    enabled_oidc_with_invalid_port["data"]["oidc_provider_settings"][0]["port"] = 0
    enabled_oidc_with_invalid_crypto = deepcopy(enabled_oidc_with_mismatched_address)
    enabled_oidc_with_invalid_crypto["data"]["oidc_provider_settings"][0]["listen_address"] = "192.168.50.1"
    disabled_oidc_with_invalid_retired_key = deepcopy(archive)
    disabled_oidc_with_invalid_retired_key["data"]["oidc_signing_keys"].append(
        {
            "kid": "archive-invalid-retired-key",
            "private_key_encrypted": "not-encrypted",
            "public_jwk_json": '{"d":"private"}',
            "status": "retired",
            "active_slot": None,
            "created_at": "2026-08-13T06:00:00+00:00",
            "activated_at": "2026-08-13T06:00:00+00:00",
            "retired_at": "2026-08-13T06:05:00+00:00",
            "publish_until": "2026-08-13T06:10:00+00:00",
        }
    )
    disabled_oidc_with_non_ascii_key = deepcopy(
        disabled_oidc_with_invalid_retired_key
    )
    disabled_oidc_with_non_ascii_key["data"]["oidc_signing_keys"][0][
        "private_key_encrypted"
    ] = "fernet:v1:\u00e9"
    enabled_oidc_with_extra_active_key = deepcopy(enabled_oidc_with_invalid_crypto)
    enabled_oidc_with_extra_active_key["data"]["oidc_signing_keys"].append(
        {
            "kid": "archive-extra-active-key",
            "private_key_encrypted": "encrypted-key",
            "public_jwk_json": '{"d":"private"}',
            "status": "active",
            "active_slot": None,
            "created_at": "2026-08-13T06:00:00+00:00",
            "activated_at": "2026-08-13T06:00:00+00:00",
            "retired_at": None,
            "publish_until": None,
        }
    )
    invalid_ca_private_key = deepcopy(archive)
    invalid_ca_private_key["data"]["ca_settings"][0]["root_private_key_encrypted"] = "not-encrypted"
    invalid_ca_storage_path = deepcopy(archive)
    invalid_ca_storage_path["data"]["ca_settings"][0]["storage_path"] = "/tmp/archive-ca"
    invalid_ca_certificate_path = deepcopy(archive)
    invalid_ca_certificate_path["data"]["ca_certificates"][0]["enabled"] = False
    invalid_ca_certificate_path["data"]["ca_certificates"][0]["cert_path"] = "/tmp/archive.crt"
    reserved_ca_deployment_path = deepcopy(archive)
    reserved_ca_deployment_path["data"]["ca_certificates"][0][
        "cert_path"
    ] = "/etc/atlaso/ca/root-ca.pem"
    duplicate_ca_deployment_path = deepcopy(archive)
    duplicate_ca_deployment_path["data"]["ca_certificates"][0].update(
        {
            "cert_path": "/etc/atlaso/ca/archive-shared.pem",
            "chain_path": "/etc/atlaso/ca/archive-shared.pem",
        }
    )
    invalid_disabled_ca_certificate_material = deepcopy(archive)
    invalid_disabled_ca_certificate_material["data"]["ca_certificates"][0].update(
        {
            "enabled": False,
            "certificate_pem": "not-a-certificate",
        }
    )
    revoked_without_timestamp = deepcopy(archive)
    revoked_without_timestamp["data"]["ca_settings"][0]["enabled"] = False
    revoked_without_timestamp["data"]["ca_certificates"][0].update(
        {
            "enabled": False,
            "status": "revoked",
            "serial_number": "2a",
            "revoked_at": None,
        }
    )
    revoked_without_serial = deepcopy(revoked_without_timestamp)
    revoked_without_serial["data"]["ca_certificates"][0].update(
        {
            "serial_number": "",
            "revoked_at": "2026-08-13T18:38:09+00:00",
        }
    )
    duplicate_managed_certificate_owner = deepcopy(archive)
    duplicate_certificate = deepcopy(duplicate_managed_certificate_owner["data"]["ca_certificates"][0])
    duplicate_certificate["managed_owner"] = "archive:duplicate-owner"
    duplicate_managed_certificate_owner["data"]["ca_certificates"][0][
        "managed_owner"
    ] = "archive:duplicate-owner"
    duplicate_managed_certificate_owner["data"]["ca_certificates"].append(duplicate_certificate)
    invalid_storage_state = deepcopy(archive)
    invalid_storage_state["data"]["esx_storage_settings"] = [
        {"enabled": False, "hostname": "nfs.atlaso.internal"}
    ]
    invalid_storage_state["data"]["esx_storage_volumes"].append(
        {
            "name": "invalid-volume",
            "stable_device_id": "/dev/disk/by-id/invalid-volume",
            "mount_path": "/mnt/atlaso-esx-storage/invalid-volume",
        }
    )
    invalid_storage_state["data"]["esx_nfs_shares"].append(
        {
            "datastore_name": "invalid-share",
            "volume_name": "invalid-volume",
            "relative_path": "data",
            "preferred_nfs_version": "2",
            "interface_name": "eth2",
            "address_families": "ipv4",
            "ipv4_clients": "0.0.0.0/0",
            "enabled": True,
        }
    )
    missing_storage_settings_validation = deepcopy(archive)
    missing_storage_settings_validation["data"]["esx_storage_settings"] = []
    missing_storage_settings_validation["data"]["esx_storage_volumes"].append(
        {
            "name": "invalid-volume-without-settings",
            "stable_device_id": "/dev/sda",
            "mount_path": "/mnt/atlaso-esx-storage/invalid-volume-without-settings",
        }
    )
    invalid_esxi_host_mac = deepcopy(archive)
    invalid_esxi_host_mac["data"]["esxi_pxe_hosts"].append(
        {"hostname": "invalid-mac-host", "mac_address": "not-a-mac"}
    )
    duplicate_normalized_esxi_host_mac = deepcopy(archive)
    duplicate_normalized_esxi_host_mac["data"]["esxi_pxe_hosts"].extend(
        [
            {"hostname": "duplicate-mac-host-one", "mac_address": "02:11:22:33:44:55"},
            {"hostname": "duplicate-mac-host-two", "mac_address": "0211.2233.4455"},
        ]
    )
    invalid_esxi_installer_iso = deepcopy(archive)
    invalid_esxi_installer_iso["data"]["esxi_pxe_hosts"].append(
        {
            "hostname": "invalid-installer-iso-host",
            "mac_address": "00:50:56:aa:bb:dd",
            "installer_iso_path": "C:\\outside\\missing.iso",
        }
    )
    invalid_vcf_depot_store = deepcopy(archive)
    invalid_vcf_depot_store["data"]["vcf_offline_depot_settings"][0][
        "depot_store_path"
    ] = "/tmp/depot"
    invalid_esxi_kickstart = deepcopy(archive)
    invalid_esxi_kickstart["data"]["esxi_kickstarts"].append(
        {
            "name": "Duplicate install directives",
            "content": "install\nupgrade\nnetwork --bootproto=dhcp\nrootpw Example\nreboot\n%firstboot\n%end\n",
            "content_hash": "0" * 64,
            "enabled": True,
        }
    )
    duplicate_network_boot_environment = deepcopy(archive)
    duplicate_network_boot_environment["data"]["network_boot_environments"].append(
        deepcopy(duplicate_network_boot_environment["data"]["network_boot_environments"][0])
    )
    invalid_update_source = deepcopy(archive)
    powershell_source = next(
        row
        for row in invalid_update_source["data"]["update_sources"]
        if row["kind"] == "powershell"
    )
    powershell_source["enabled"] = True
    powershell_source["url"] = "not-a-url"
    duplicate_update_source = deepcopy(archive)
    duplicate_update_source["data"]["update_sources"].append(
        deepcopy(duplicate_update_source["data"]["update_sources"][0])
    )
    invalid_script_interpreter = deepcopy(archive)
    script_content = "Write-Output 'archive validation'\n"
    script_digest = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
    invalid_script_interpreter["data"]["automation_scripts"].append(
        {
            "name": "Invalid interpreter",
            "created_by": "test",
            "revisions": [
                {
                    "revision": 1,
                    "interpreter": "cmd",
                    "content": script_content,
                    "content_sha256": script_digest,
                    "timeout_seconds": 60,
                    "created_by": "test",
                }
            ],
        }
    )
    invalid_script_digest = deepcopy(invalid_script_interpreter)
    invalid_script_digest["data"]["automation_scripts"][-1]["name"] = "Invalid digest"
    invalid_script_digest["data"]["automation_scripts"][-1]["revisions"][0]["interpreter"] = "powershell"
    invalid_script_digest["data"]["automation_scripts"][-1]["revisions"][0]["content_sha256"] = "0" * 64
    duplicate_script_name = deepcopy(archive)
    duplicate_script_name["data"]["automation_scripts"].extend(
        [
            {"name": "Duplicate script", "created_by": "test", "revisions": []},
            {"name": "Duplicate script", "created_by": "test", "revisions": []},
        ]
    )
    unsupported_schedule = deepcopy(archive)
    unsupported_schedule["data"]["schedules"].append(
        {
            "name": "Unsupported schedule",
            "task_type": "unsupported",
            "task_config_json": "{}",
            "schedule_kind": "cron",
            "cron_expression": "0 2 * * *",
            "run_once_at": None,
            "timezone_name": "UTC",
            "enabled": False,
            "created_by": "test",
        }
    )
    invalid_update_schedule = deepcopy(unsupported_schedule)
    invalid_update_schedule["data"]["schedules"][-1].update(
        {
            "name": "Invalid update stream schedule",
            "task_type": "appliance_update_check",
            "task_config_json": '{"selected_streams":["retired"]}',
        }
    )
    duplicate_schedule = deepcopy(unsupported_schedule)
    duplicate_schedule["data"]["schedules"].append(
        deepcopy(duplicate_schedule["data"]["schedules"][-1])
    )
    invalid_managed_package_source = deepcopy(archive)
    photon_source = next(
        row
        for row in invalid_managed_package_source["data"]["update_sources"]
        if row["kind"] == "photon"
    )
    invalid_managed_package_source["data"]["managed_packages"].append(
        {
            "ecosystem": "powershell",
            "name": "InvalidRepositoryModule",
            "policy": "latest",
            "target_version": "",
            "enabled": True,
            "source_kind": photon_source["kind"],
            "source_name": photon_source["name"],
        }
    )
    duplicate_managed_package = deepcopy(archive)
    duplicate_managed_package["data"]["managed_packages"].append(
        deepcopy(duplicate_managed_package["data"]["managed_packages"][0])
    )
    unsupported_setting = deepcopy(archive)
    unsupported_setting["data"]["settings"].append(
        {"key": "unsupported.setting", "value": "must-not-be-silently-dropped"}
    )
    duplicate_setting = deepcopy(archive)
    duplicate_setting["data"]["settings"] = [
        {"key": "dns.conditional_forwarders", "value": ""},
        {"key": "dns.conditional_forwarders", "value": ""},
    ]
    malformed_password_policy = deepcopy(archive)
    malformed_password_policy["data"]["settings"].append(
        {"key": "local_users.password_policy.v1", "value": "not-json"}
    )
    coerced_password_policy = deepcopy(archive)
    coerced_password_policy["data"]["settings"].append(
        {
            "key": "local_users.password_policy.v1",
            "value": '{"require_uppercase":"false"}',
        }
    )
    invalid_nts_restoration_marker = deepcopy(archive)
    nts_marker = next(
        row
        for row in invalid_nts_restoration_marker["data"]["settings"]
        if row["key"] == "ntp.nts_restoration_v1"
    )
    nts_marker["value"] = "pending"
    invalid_firewall_source_groups = deepcopy(archive)
    invalid_firewall_source_groups["data"]["settings"].append(
        {
            "key": "firewall.managed_source_groups",
            "value": '{"groups":null}',
        }
    )
    duplicate_firewall_source_group = deepcopy(archive)
    duplicate_firewall_source_group["data"]["settings"].append(
        {
            "key": "firewall.managed_source_groups",
            "value": json.dumps(
                {
                    "groups": [
                        {"id": "duplicate", "entries": ["192.0.2.0/24"]},
                        {"id": "duplicate", "entries": ["198.51.100.0/24"]},
                    ],
                    "assignments": {},
                }
            ),
        }
    )
    malformed_firewall_source_group = deepcopy(archive)
    malformed_firewall_source_group["data"]["settings"].append(
        {
            "key": "firewall.managed_source_groups",
            "value": json.dumps(
                {
                    "groups": [
                        {
                            "id": "custom:restricted",
                            "name": "Restricted",
                            "entries": 42,
                        }
                    ],
                    "assignments": {},
                }
            ),
        }
    )
    reserved_firewall_source_group = deepcopy(archive)
    reserved_firewall_source_group["data"]["settings"].append(
        {
            "key": "firewall.managed_source_groups",
            "value": json.dumps(
                {
                    "groups": [
                        {
                            "id": "any",
                            "name": "Restricted Any",
                            "entries": ["192.0.2.0/24"],
                        }
                    ],
                    "assignments": {"management-ui": "any"},
                }
            ),
        }
    )
    unresolved_firewall_source_group_assignment = deepcopy(archive)
    unresolved_firewall_source_group_assignment["data"]["settings"].append(
        {
            "key": "firewall.managed_source_groups",
            "value": json.dumps(
                {
                    "groups": [
                        {
                            "id": "custom:restricted",
                            "name": "Restricted",
                            "entries": ["192.0.2.0/24"],
                        }
                    ],
                    "assignments": {"management-ui": "missing"},
                }
            ),
        }
    )
    malformed_conditional_forwarder = deepcopy(archive)
    malformed_conditional_forwarder["data"]["settings"].append(
        {"key": "dns.conditional_forwarders", "value": "corp.example"}
    )
    oversized_esxi_custom_variables = deepcopy(archive)
    oversized_esxi_custom_variables["data"]["settings"].append(
        {
            "key": "esxi_pxe.custom_variables.v1",
            "value": json.dumps(
                [
                    {
                        "name": f"archive_variable_{item_index}",
                        "description": "",
                        "default_value": "",
                    }
                    for item_index in range(65)
                ]
            ),
        }
    )
    missing_canonical_service_state = deepcopy(archive)
    missing_canonical_service_state["data"]["service_states"] = (
        missing_canonical_service_state["data"]["service_states"][1:]
    )

    for candidate, message in [
        (invalid_collection, "must be a list"),
        (unsupported_schema, "schema is not supported"),
        (invalid_row, "must be an object"),
        (missing_required_field, "missing required field 'name'"),
        (missing_section, "missing a required data section"),
        (empty_data, "missing a required data section"),
        (empty_singleton, "must contain exactly one row"),
        (duplicate_oidc_singleton, "must contain at most one row"),
        (enabled_missing_parent_vlan, "has an ineligible parent interface"),
        (enabled_non_trunk_vlan, "has an ineligible parent interface"),
        (enabled_missing_route_target, "has an ineligible target interface"),
        (enabled_ineligible_route_target, "has an ineligible target interface"),
        (enabled_missing_nat_target, "has an ineligible outbound interface"),
        (enabled_ipv6_only_nat_target, "has an ineligible outbound interface"),
        (enabled_missing_nat_source_group, "has an invalid source"),
        (missing_firewall_source_group, "has an invalid source or destination"),
        (enabled_missing_routing_target, "has an ineligible interface"),
        (enabled_identical_routing_targets, "has identical source and destination interfaces"),
        (enabled_missing_dhcp_target, "has an ineligible bind interface"),
        (enabled_wrong_family_dhcp_target, "has an ineligible bind interface"),
        (enabled_management_dhcp_target, "has an ineligible bind interface"),
        (enabled_without_enabled_dhcp_scope, "enables DHCP without an enabled DHCP scope"),
        (enabled_with_invalid_disabled_dhcp_scope, "DHCP settings are invalid"),
        (disabled_with_invalid_disabled_dhcp_scope, "DHCP settings are invalid"),
        (enabled_outside_dhcp_reservation, "must be inside an enabled DHCP IP zone"),
        (disabled_invalid_dhcp_reservation, "has an invalid IP address"),
        *(
            (candidate, "has an ineligible listen interface")
            for candidate in enabled_missing_service_targets
        ),
        (enabled_missing_listen_address, "has no listen address"),
        (enabled_invalid_listen_address, "has an invalid listen address"),
        *(
            (candidate, "has listener addresses not derived from its interfaces")
            for candidate in enabled_mismatched_service_addresses
        ),
        (enabled_missing_web_terminal_target, "select an ineligible Web Terminal interface"),
        (invalid_network_state, "network state is invalid: .* MTU must be between 576 and 9000"),
        (invalid_scalar_type, "field 'port' must be an integer"),
        (invalid_appliance_config_path, "Appliance Settings are invalid: Appliance settings config path must be absolute"),
        (enabled_web_terminal_without_https, "enables Web Terminal without Management UI HTTPS"),
        (appliance_dns_ownership_conflict, "user-owned DNS A/AAAA record"),
        (invalid_ntp_port, "NTP settings are invalid: NTP port must be UDP 123"),
        (enabled_nts_without_ca, "enables NTPsec NTS server mode without an enabled CA"),
        (invalid_dns_domain, "DNS settings are invalid: DNS domain bad domain must not contain whitespace"),
        (invalid_route_destination, "Routes and WAN state is invalid: Route not-a-cidr is not a valid destination CIDR"),
        (invalid_firewall_policy, "Firewall state is invalid: .*Default input policy"),
        (invalid_kms_port, "KMS state is invalid: KMS port must be between 1 and 65535"),
        (invalid_legacy_dhcp, "DHCP settings are invalid"),
        (empty_required_field, "has empty required field 'name'"),
        (unresolved_ldap_organization, "references an unknown LDAP organization"),
        (enabled_ldap_without_organization, "enables LDAP without an LDAP organization"),
        (enabled_ldaps_without_ca, "enables LDAPS without a ready Certificate Authority"),
        (enabled_ldap_with_invalid_port, "LDAP state is invalid: LDAPS port must be between 1 and 65535"),
        (enabled_ldap_user_without_password, "enabled user needs staged passwords"),
        (unresolved_oidc_client, "references an unknown OIDC client"),
        (oidc_client_without_redirect, "At least one exact redirect URI is required"),
        (oidc_client_with_invalid_lifetime, "fixed 60-second authorization-code lifetime"),
        (oidc_client_with_invalid_hash, "OIDC client secret hash is not valid"),
        (duplicate_oidc_client, "duplicates the unique client_id identity"),
        (duplicate_oidc_subject_uuid, "duplicates a subject UUID"),
        (duplicate_oidc_subject_source, "duplicates an identity source"),
        (invalid_oidc_subject_scalar, "subject_uuid field that must be a string"),
        (invalid_oidc_subject_uuid, "has an invalid subject UUID"),
        (duplicate_oidc_mapping, "duplicates an OIDC group mapping identity"),
        (invalid_oidc_mapping_scalar, "external_group_name field that must be a string"),
        (
            effective_oidc_mapping_collision,
            "Effective external group names must be unique case-insensitively",
        ),
        (cross_organization_oidc_mapping, "outside its OIDC client's organization"),
        (bound_client_local_role_mapping, "assigns a local role to an organization-bound OIDC client"),
        (unresolved_esx_volume, "references an unknown ESX storage volume"),
        (enabled_missing_esx_share_target, "has an ineligible interface or address family"),
        (cyclic_ldap_groups, "contains cyclic LDAP group membership"),
        (invalid_ldap_group, "LDAP state is invalid: .*invalid name"),
        (duplicate_ldap_group, "duplicates an LDAP identity"),
        (invalid_oidc_mapping_role, "Select one supported local Atlaso role"),
        (invalid_oidc_external_group, "External group names must contain"),
        (enabled_certificate_with_disabled_profile, "references a disabled CA profile"),
        (weak_ca_profile, "Certificate Authority state is invalid: .*RSA key size must be at least 2048"),
        (enabled_kms_without_ca, "enables KMS without an enabled CA"),
        (enabled_kms_without_provider, "KMS trust state is invalid: At least one enabled provider"),
        (invalid_provider_id, "invalid provider ID"),
        (invalid_vcenter_id, "invalid trusted vCenter ID"),
        (invalid_provider_enabled_type, "has an invalid enabled value"),
        (duplicate_provider_name, "duplicates a provider name"),
        (duplicate_vcenter_name, "duplicates a trusted vCenter name within its provider"),
        (invalid_vcenter_enabled_type, "has an invalid enabled value"),
        (invalid_vcenter_certificate_id, "invalid public certificate ID"),
        (disabled_kms_with_invalid_public_certificate, "PEM-encoded vCenter public client certificate"),
        (enabled_oidc_without_dependencies, "enables OIDC without an active signing key"),
        (enabled_oidc_with_mismatched_address, "has listener addresses not derived from its interfaces"),
        (enabled_oidc_with_invalid_port, "has an invalid HTTPS port"),
        (enabled_oidc_with_invalid_crypto, "OIDC cryptographic state is invalid"),
        (disabled_oidc_with_invalid_retired_key, "OIDC cryptographic state is invalid"),
        (disabled_oidc_with_non_ascii_key, "OIDC cryptographic state is invalid"),
        (enabled_oidc_with_extra_active_key, "has a noncanonical active slot"),
        (invalid_ca_private_key, "Certificate Authority key state is invalid"),
        (invalid_ca_storage_path, "CA storage path must stay under /etc/atlaso"),
        (invalid_ca_certificate_path, "certificate path must stay under /etc/atlaso"),
        (reserved_ca_deployment_path, "uses a path reserved for CA root publication"),
        (duplicate_ca_deployment_path, "duplicates the deployment path"),
        (invalid_disabled_ca_certificate_material, "public certificate is not usable"),
        (revoked_without_timestamp, "has no revocation timestamp"),
        (revoked_without_serial, "has no serial number"),
        (duplicate_managed_certificate_owner, "duplicates a managed certificate owner"),
        (invalid_storage_state, "ESX Storage state is invalid: Datastore invalid-share must use NFS 3 or NFS 4.1"),
        (missing_storage_settings_validation, "must use a stable /dev/disk/by-id identity"),
        (invalid_esxi_host_mac, "esxi_pxe_hosts' has an invalid MAC address"),
        (duplicate_normalized_esxi_host_mac, "duplicates a normalized MAC address"),
        (invalid_esxi_installer_iso, "has an invalid installer ISO"),
        (invalid_vcf_depot_store, "Depot store path must be /mnt/atlaso-vcf-offline-depot"),
        (invalid_esxi_kickstart, "multiple install/upgrade directives"),
        (duplicate_network_boot_environment, "duplicates an environment key"),
        (invalid_update_source, r"update source state is invalid: .*URL must be an HTTP\(S\) URL"),
        (duplicate_update_source, "duplicates an update source identity"),
        (invalid_script_interpreter, "Interpreter must be bash, python, or powershell"),
        (invalid_script_digest, "Script content digest does not match"),
        (duplicate_script_name, "duplicates a script name"),
        (unsupported_schedule, "Choose a supported scheduled task type"),
        (invalid_update_schedule, "retired or unsupported stream"),
        (duplicate_schedule, "duplicates the unique name identity"),
        (invalid_managed_package_source, "managed package state is invalid: Choose a PowerShell repository"),
        (duplicate_managed_package, "duplicates a managed package identity"),
        (unsupported_setting, "has an unsupported setting key"),
        (duplicate_setting, "duplicates a setting key"),
        (malformed_password_policy, "local user password policy is invalid"),
        (coerced_password_policy, "field require_uppercase must be a Boolean"),
        (invalid_nts_restoration_marker, "NTPsec NTS restoration marker is invalid"),
        (invalid_firewall_source_groups, "firewall source groups state is invalid"),
        (duplicate_firewall_source_group, "firewall source groups state is invalid"),
        (malformed_firewall_source_group, "firewall source groups state is invalid"),
        (reserved_firewall_source_group, "firewall source groups state is invalid"),
        (
            unresolved_firewall_source_group_assignment,
            "firewall source groups state is invalid",
        ),
        (malformed_conditional_forwarder, "DNS conditional forwarders state is invalid"),
        (oversized_esxi_custom_variables, "limited to 64 entries"),
        (missing_canonical_service_state, "complete canonical service status set"),
    ]:
        with pytest.raises(ValueError, match=message):
            archive_summary(candidate)
    assert archive_summary(disabled_missing_parent_vlan)["table_counts"]["vlan_interfaces"] == len(
        disabled_missing_parent_vlan["data"]["vlan_interfaces"]
    )
    assert archive_summary(disabled_missing_route_target)["table_counts"]["routes"] == len(
        disabled_missing_route_target["data"]["routes"]
    )
    archive_summary(disabled_missing_nat_target)
    archive_summary(disabled_missing_nat_source_group)
    archive_summary(disabled_missing_routing_target)
    archive_summary(disabled_missing_dhcp_target)
    archive_summary(disabled_missing_service_target)
    archive_summary(unbound_client_ldap_mapping)


def test_settings_restore_rolls_back_late_failure_without_clearing_staged_ldap_recovery(client, monkeypatch):
    """Verify late settings restore failures roll back database and process state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest
    from sqlalchemy import select

    import atlaso.app.services.settings_archive as settings_archive
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, LdapRecoveryArchive
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        original_fqdn = settings.fqdn
        archive = settings_archive.export_settings_archive(db, actor="test")
        archive["data"]["appliance_settings"][0]["fqdn"] = "uncommitted-restore.atlaso.internal"
        staged = LdapRecoveryArchive(
            filename="staged-late-restore.lfldap",
            path="memory://pending-ldap-recovery",
            sha256="d" * 64,
            state="staged",
            organization_count=1,
            created_by="test",
        )
        db.add(staged)
        db.commit()
        staged_id = staged.id
        LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] = b"pending recovery payload"

        def fail_after_restore_mutation(*_args, **_kwargs):
            """Raise after archive mutation to exercise transaction rollback.

            Args:
                *_args: Additional positional arguments accepted by the callable.
                **_kwargs: Additional keyword arguments accepted by the callable.
            """
            raise RuntimeError("injected late restore failure")

        monkeypatch.setattr(settings_archive, "_restore_schedules", fail_after_restore_mutation)
        try:
            with pytest.raises(RuntimeError, match="injected late restore failure"):
                settings_archive.restore_settings_archive(db, archive)
            assert db.execute(select(ApplianceSettings)).scalar_one().fqdn == original_fqdn
            assert db.get(LdapRecoveryArchive, staged_id) is not None
            assert LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] == b"pending recovery payload"
        finally:
            LDAP_PENDING_RECOVERY_PAYLOADS.pop(staged_id, None)


def test_factory_reset_rolls_back_late_failure_without_clearing_staged_ldap_recovery(client, monkeypatch):
    """Verify late factory-reset failures roll back database and process state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import pytest
    from sqlalchemy import select

    import atlaso.app.services.settings_archive as settings_archive
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, LdapRecoveryArchive
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        original_fqdn = settings.fqdn
        staged = LdapRecoveryArchive(
            filename="staged-late-reset.lfldap",
            path="memory://pending-ldap-recovery",
            sha256="e" * 64,
            state="staged",
            organization_count=1,
            created_by="test",
        )
        db.add(staged)
        db.commit()
        staged_id = staged.id
        LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] = b"pending reset recovery payload"

        def fail_after_reset_seed(*_args, **_kwargs):
            """Raise after reset seeding to exercise transaction rollback.

            Args:
                *_args: Additional positional arguments accepted by the callable.
                **_kwargs: Additional keyword arguments accepted by the callable.
            """
            raise RuntimeError("injected late factory reset failure")

        monkeypatch.setattr(settings_archive, "_force_services_stopped_unconfigured", fail_after_reset_seed)
        try:
            with pytest.raises(RuntimeError, match="injected late factory reset failure"):
                settings_archive.factory_reset_desired_state(db)
            assert db.execute(select(ApplianceSettings)).scalar_one().fqdn == original_fqdn
            assert db.get(LdapRecoveryArchive, staged_id) is not None
            assert LDAP_PENDING_RECOVERY_PAYLOADS[staged_id] == b"pending reset recovery payload"
        finally:
            LDAP_PENDING_RECOVERY_PAYLOADS.pop(staged_id, None)


def test_esxi_pxe_ui_create_apply_and_job_redaction(client):
    """Verify that esxi pxe ui create apply and job redaction.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, EsxiKickstart, Job

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    assert "ESXi Kickstarts" in page.text
    assert 'id="esxi-kickstarts-table"' in page.text
    assert 'data-fallback-id="esxi-kickstarts-fallback"' in page.text
    assert "+ Add Kickstart" in page.text
    assert 'data-atlaso-wizard-nav="identity"' in page.text
    assert 'data-atlaso-wizard-nav="source"' in page.text
    assert 'data-atlaso-wizard-nav="state"' in page.text
    assert 'data-atlaso-wizard-nav="review"' in page.text
    assert 'accept=".cfg,.ks"' in page.text
    assert 'name="vault_id"' not in page.text
    assert 'data-monaco-language="atlaso-kickstart"' in page.text
    assert '<textarea name="description" rows="3" maxlength="500"></textarea>' in page.text
    assert 'class="kickstart-description-field"' in page.text
    kickstart_wizard = page.text.split('id="kickstart-wizard-dialog"', 1)[1].split("</dialog>", 1)[0]
    kickstart_state = kickstart_wizard.split('data-atlaso-wizard-step="state"', 1)[1].split("</section>", 1)[0]
    assert 'type="checkbox" name="enabled" checked' in kickstart_state
    assert "Boot media tasks" in page.text
    assert 'data-task-type="pxe-media-sync"' in page.text
    assert 'data-task-lock-component-filter="true"' in page.text
    assert 'data-task-grid-height="100%"' in page.text
    assert "Media operations only" in page.text
    assert "downloads, uploads, and inactive-media deletion" in page.text
    assert "Media ready" in page.text
    assert 'data-tab-target="network-boot-settings-panel"' not in page.text
    assert 'id="network-boot-settings-panel"' not in page.text
    assert 'id="network-boot-environments-panel" class="tab-panel network-boot-environments-panel"' in page.text
    assert 'id="network-boot-environments-table" class="tabulator-shell"' in page.text
    boot_environments_panel = page.text.index('id="network-boot-environments-panel"')
    boot_media_tasks = page.text.index('data-network-boot-tasks-panel')
    network_boot_dialog = page.text.index('id="network-boot-host-dialog"')
    assert boot_environments_panel < boot_media_tasks < network_boot_dialog
    assert "Delete newest inactive media" in Path("atlaso/app/static/app.js").read_text()
    app_css = Path("atlaso/app/static/app.css").read_text()
    environments_css = app_css.split(".network-boot-overview > .tab-panels > .tab-panel.active {", 1)[1].split("}", 1)[0]
    assert "height: 100%;" in environments_css
    assert "overflow-y: auto;" in environments_css
    environment_grid_css = app_css.split(".network-boot-environments-panel > .tabulator-shell {", 1)[1].split("}", 1)[0]
    assert "flex: 0 0 auto;" in environment_grid_css
    task_history_css = app_css.split(".network-boot-environments-panel > .network-boot-task-history-container {", 1)[1].split("}", 1)[0]
    assert "flex: 0 0 max(420px, calc(100vh - 240px));" in task_history_css
    kickstart_description_css = app_css.split(".kickstart-description-field {", 1)[1].split("}", 1)[0]
    assert "grid-column: 1;" in kickstart_description_css
    host_tab = page.text.index('data-tab-target="esxi-pxe-hosts-panel"')
    kickstart_tab = page.text.index('data-tab-target="esxi-pxe-editor-panel"')
    custom_variables_tab = page.text.index('data-tab-target="esxi-pxe-custom-variables-panel"')
    iso_tab = page.text.index('data-tab-target="esxi-pxe-isos-panel"')
    preview_tab = page.text.index('data-tab-target="esxi-pxe-preview-panel"')
    assert host_tab < kickstart_tab < custom_variables_tab < iso_tab < preview_tab
    tablist = page.text.split('aria-label="ESXi PXE views"', 1)[1].split("</div>", 1)[0]
    assert "+ Add custom variable" not in tablist
    custom_variables_panel = page.text.index('id="esxi-pxe-custom-variables-panel"')
    add_custom_variable = page.text.index('placeholder="+ Add custom variable"')
    isos_panel = page.text.index('id="esxi-pxe-isos-panel"')
    assert custom_variables_panel < add_custom_variable < isos_panel
    assert 'id="esxi-custom-variables-table"' in page.text
    assert "Custom variable name" in page.text
    assert "Default value, if any" in page.text
    assert 'id="esxi-custom-variable-wizard-dialog"' in page.text
    assert "data-esxi-custom-variable-wizard data-atlaso-wizard" in page.text
    assert 'data-atlaso-wizard-nav="definition"' in page.text
    assert 'data-atlaso-wizard-nav="review"' in page.text
    assert 'data-atlaso-wizard-step="definition"' in page.text
    assert 'data-atlaso-wizard-step="review"' in page.text
    assert "data-atlaso-resource-review" in page.text
    custom_variable_definition = page.text.split('data-atlaso-wizard-step="definition"', 1)[1].split("</section>", 1)[0]
    assert '<label class="full"><span class="field-label"><span>Description</span>' in custom_variable_definition
    assert ".form-grid > .full {\n  grid-column: 1 / -1;" in app_css
    kickstart_collection_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8").split(
        "function initializeKickstartCollection()", 1
    )[1].split(
        "function initializeZoneEditors()", 1
    )[0]
    assert 'newRow: { id: "__new__", is_new: true, name: "", enabled: true }' in kickstart_collection_js
    assert "defaults: { enabled: true }" in kickstart_collection_js
    assert '<button class="tab-button active" type="button" role="tab" data-tab-target="esxi-pxe-hosts-panel"' in page.text
    assert 'id="esxi-pxe-hosts-panel" class="tab-panel active" role="tabpanel">' in page.text
    assert 'id="esxi-pxe-editor-panel" class="tab-panel" role="tabpanel" hidden' in page.text
    assert 'aria-label="Kickstart for default ESXi PXE host"' in page.text
    assert 'aria-label="Installer ISO for default ESXi PXE host"' in page.text
    assert 'aria-label="Enable default ESXi PXE host"' in page.text
    assert "# Sample scripted installation file" in page.text
    assert "vmaccepteula" in page.text
    assert "rootpw --iscrypted $6$REPLACE_WITH_SHA512_CRYPT_HASH" in page.text
    assert "rootpw vmware01!" not in page.text
    assert "install --firstdisk --overwritevmfs" in page.text
    assert "# install --firstdisk --overwritevmfs --dpupcislots=&lt;PCIeSlotID&gt;" in page.text
    assert "network --bootproto=dhcp --device=vmnic0" in page.text
    assert "%post --interpreter=python --ignorefailure=true" in page.text
    assert "stampFile.write(time.asctime())" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    invalid_mac = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esxi-invalid-mac",
            "mac_address": "prefix-00:50:56:01:02:03",
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert invalid_mac.status_code == 400
    assert invalid_mac.json()["detail"] == "ESXi PXE host MAC address is invalid."

    multicast_mac = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esxi-multicast-mac",
            "mac_address": "01:50:56:01:02:03",
        },
        headers={"X-Atlaso-Grid": "1", "Accept": "application/json"},
    )
    assert multicast_mac.status_code == 400
    assert multicast_mac.json()["detail"] == "ESXi PXE host MAC address is invalid."

    created = client.post(
        "/esxi-pxe/kickstarts",
        data={
            "csrf": csrf,
            "name": "Lab ESXi",
            "description": "install",
            "content": "install --firstdisk\nnetwork --bootproto=dhcp\nrootpw SuperSecret!\nreboot\n%firstboot\n%end\n",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    kickstart_id = int(created.headers["location"].rsplit("=", 1)[1])
    with SessionLocal() as db:
        kickstart = db.execute(select(EsxiKickstart).where(EsxiKickstart.id == kickstart_id)).scalar_one()
        assert "SuperSecret!" in kickstart.content
        assert kickstart.http_path == f"/pxe/esxi/ks/{kickstart.content_hash[:12]}.cfg"

    login(client)
    apply_page = client.get("/appliance-apply")
    review = client.get("/appliance-apply/review")
    assert any(unit["id"] == "esxi_pxe" for unit in review.json()["units"])
    apply_csrf = apply_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    applied = client.post("/appliance-apply", data={"csrf": apply_csrf, "selected_units": "esxi_pxe"})

    assert applied.status_code == 200
    assert "ESXi PXE" in applied.text
    assert "SuperSecret!" not in applied.text
    assert "[redacted]" in applied.text
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply").order_by(Job.created_at.desc())).scalars().first()
        assert job is not None
        payload = json.loads(job.result or "{}")
        assert payload["selected_units"] == ["esxi_pxe"]
        assert "SuperSecret!" not in (job.result or "")
        assert "atlaso-helper esxi-pxe apply" in (job.result or "")
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "create_esxi_kickstart")).scalar_one()
        assert "SuperSecret!" not in (event.detail or "")


def test_monaco_is_the_only_bundled_editor_and_kickstart_uses_shared_collection():
    """Verify that monaco is the only bundled editor and kickstart uses shared collection."""
    package = Path("package.json").read_text(encoding="utf-8")
    lock = Path("package-lock.json").read_text(encoding="utf-8")
    base = Path("atlaso/app/templates/base.html").read_text(encoding="utf-8")
    app_css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    monaco_source = Path("scripts/monaco-entry.js").read_text(encoding="utf-8")
    templates = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "atlaso/app/templates/automation.html",
            "atlaso/app/templates/dns.html",
            "atlaso/app/templates/esxi_pxe.html",
            "atlaso/app/templates/vcf_offline_depot.html",
        )
    )

    assert '"monaco-editor": "0.52.2"' in package
    assert "build:monaco" in package
    assert "codemirror" not in package.lower()
    assert "codemirror" not in lock.lower()
    assert "codemirror" not in app_js.lower()
    assert "codemirror" not in templates.lower()
    assert not Path("atlaso/app/static/vendor/codemirror").exists()
    assert not Path("scripts/build_codemirror.mjs").exists()
    assert "/static/vendor/monaco/atlaso-monaco.min.js" in base
    monaco_bundle = Path("atlaso/app/static/vendor/monaco/atlaso-monaco.min.js").read_text(encoding="utf-8")
    assert "editor.contrib.suggestController" in monaco_bundle
    assert Path("atlaso/app/static/vendor/monaco/editor.worker.js").is_file()
    assert "initializeAtlasoResourceWizard" in app_js
    kickstart_js = app_js.split("function initializeKickstartCollection()", 1)[1].split("function initializeZoneEditors()", 1)[0]
    assert 'resourceName: "kickstart"' in kickstart_js
    assert 'label: "Duplicate Kickstart"' in kickstart_js
    assert 'label: "Validate Kickstart"' in kickstart_js
    assert 'label: "Download Kickstart"' in kickstart_js
    assert "deleteResource: true" in kickstart_js
    assert 'document.querySelector("[data-esxi-pxe-summary]")' in kickstart_js
    assert "onSaved: ({ table }) => updateSummary(table)" in kickstart_js
    assert "onDeleted: ({ table }) => updateSummary(table)" in kickstart_js
    assert "atlaso-kickstart" in monaco_source
    assert "vs/editor/editor.all.js" in monaco_source
    assert 'triggerCharacters: ["{"]' in monaco_source
    assert 'linePrefix.endsWith("{{")' in monaco_source
    assert "requestAnimationFrame(() => editor.trigger" in monaco_source
    assert '"editor.action.triggerSuggest"' in monaco_source
    assert 'ariaLabel: textarea.getAttribute("aria-label") || "Editor content"' in monaco_source
    assert "readOnly: false" in monaco_source
    assert "domReadOnly: false" in monaco_source
    assert "function layout(textarea)" in monaco_source
    assert "{ enhanceTextarea, focus, getValue, layout, setLanguage, setValue }" in monaco_source
    assert "modelCompletions" in monaco_source
    assert 'headers: { Accept: "application/json", "X-Atlaso-Grid": "1" }' in app_js
    assert '"atlaso-monaco-expand-button"' in monaco_source
    assert '"has-expanded-monaco"' in monaco_source
    assert 'event.key === "Escape"' in monaco_source
    assert ".atlaso-monaco-shell.is-expanded" in app_css
    assert "python.contribution" in monaco_source
    assert "shell.contribution" in monaco_source
    assert "powershell.contribution" in monaco_source


def test_esxi_custom_variable_collection_drives_kickstart_completion_and_validation(client):
    """Verify that esxi custom variable collection drives kickstart completion and validation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/esxi-pxe")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    created = client.post(
        "/esxi-pxe/custom-variables",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "install_disk",
            "description": "Preferred ESXi installation disk",
            "default_value": "firstdisk",
        },
    )

    assert created.status_code == 200, created.text
    assert created.json()["variable"] == {
        "id": "install_disk",
        "name": "install_disk",
        "description": "Preferred ESXi installation disk",
        "default_value": "firstdisk",
    }
    refreshed = client.get("/esxi-pxe")
    assert "custom.install_disk" in refreshed.text
    assert "Preferred ESXi installation disk" in refreshed.text
    host_wizard = refreshed.text.split('id="network-boot-promote-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert '"name": "install_disk"' in host_wizard
    assert '"default_value": "firstdisk"' in host_wizard
    assert "<code>custom.install_disk</code>" in host_wizard
    assert "<td>firstdisk</td><td>Uses default</td>" in host_wizard

    kickstart = client.post(
        "/esxi-pxe/kickstarts",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "Catalog variable",
            "description": "",
            "content": "install --firstdisk={{custom.install_disk}}\nnetwork --bootproto=dhcp\nrootpw --iscrypted placeholder\n",
            "enabled": "on",
        },
    )
    assert kickstart.status_code == 200, kickstart.text

    deleted = client.post(
        "/esxi-pxe/custom-variables/install_disk/delete",
        headers={"Accept": "application/json"},
        data={"csrf": csrf},
    )
    assert deleted.status_code == 200
    rejected = client.post(
        "/esxi-pxe/kickstarts",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "Undefined catalog variable",
            "description": "",
            "content": "install --firstdisk={{custom.install_disk}}\nnetwork --bootproto=dhcp\nrootpw --iscrypted placeholder\n",
        },
    )
    assert rejected.status_code == 400


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("VMware-VMvisor-Installer-9.1.0.0100.25433460.x86_64.iso", ("9.1.0.0100", "25433460")),
        ("VMware-VMvisor-Installer-8.0U3-24022510.x86_64.iso", ("8.0U3", "24022510")),
        ("VMware-VMvisor-Installer-8.0U3.iso", ("8.0U3", "")),
        ("Nested-ESXi.iso", ("", "")),
    ],
)
def test_esx_installer_identity_from_filename(filename, expected):
    """Verify that esx installer identity from filename.

    Args:
        filename: Source filename associated with the parsed or reported content.
        expected: Expected value used to verify the tested behavior.
    """
    from atlaso.app.services.esxi_pxe import esx_installer_identity_from_filename

    assert esx_installer_identity_from_filename(filename) == expected


def test_network_boot_host_management_report_and_print_contract(client):
    """Verify that network boot host management report and print contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/network-boot")
    assert page.status_code == 200
    assert 'class="tab-panel active network-boot-discovered-panel"' in page.text
    assert 'data-network-boot-report-history' in page.text
    assert 'data-network-boot-report' in page.text
    assert "Print / Save as PDF" in page.text
    assert "Download JSON" in page.text
    report_dialog = page.text.split('id="network-boot-host-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert "Promote to ESXi" not in report_dialog
    assert "Wake host" not in report_dialog
    assert ">Reboot<" not in report_dialog
    assert "Remove discovered host" not in report_dialog
    assert "View inventory report" in page.text
    assert 'id="network-boot-discovered-fallback"' in page.text

    app_js = client.get("/static/app.js").text
    renderer = app_js.split("function renderNetworkBootReport", 1)[1].split(
        "function initializeNetworkBootPage", 1
    )[0]
    assert ".innerHTML" not in renderer
    assert "textContent" in renderer
    assert "host?." not in renderer
    assert 'system.product_name || "Product not reported"' in renderer
    assert 'system.manufacturer || "Manufacturer not reported"' in renderer
    assert renderer.count('legacyReport ? "Not reported"') >= 4
    assert '<input name="hostname" required maxlength="120">' in page.text
    for section in (
        "Report and boot identity",
        "System",
        "Firmware",
        "Baseboard",
        "Chassis",
        "CPU",
        "Memory",
        "DIMMs",
        "Network interfaces",
        "Storage controllers",
        "Disks",
        "PCI devices",
        "USB devices",
    ):
        assert f'"{section}"' in renderer
    page_initializer = app_js.split("function initializeNetworkBootPage", 1)[1].split(
        'document.addEventListener("DOMContentLoaded", initializeDashboard)', 1
    )[0]
    host_refresh = app_js.split("function initializeNetworkBootDiscoveredHostRefresh", 1)[1].split(
        "function initializeNetworkBootPage", 1
    )[0]
    for label in (
        'label: "Reboot"',
        'label: "Wake host"',
        'label: "Remove discovered host"',
    ):
        assert label in page_initializer
    assert '"Promote to ESXi (already assigned)"' in page_initializer
    assert "Boolean(component.getData().assigned_to_esxi)" in page_initializer
    assert 'height: "100%"' in page_initializer
    assert 'label: "View inventory report"' in page_initializer
    assert "onOpenRow: openHost" not in page_initializer
    assert 'action: (_event, row) => promoteHost(row, row.getElement())' in page_initializer
    assert 'querySelector("[data-network-boot-promote-open]")' not in page_initializer
    assert 'querySelector("[data-network-boot-wake]")' not in page_initializer
    assert 'querySelector("[data-network-boot-reboot]")' not in page_initializer
    assert 'querySelector("[data-network-boot-remove]")' not in page_initializer
    assert "renderNetworkBootReport(reportArticle, historyItem);" in page_initializer
    assert "atlasoNewTaskId = queued.job_id" in page_initializer
    assert "await refreshTasksPage()" in page_initializer
    assert "requestConfirmation({" in page_initializer
    assert "/reports/${historyItem.id}/download" in page_initializer
    assert 'reportPrintClass = "network-boot-report-printing"' in page_initializer
    assert 'window.addEventListener("afterprint", clearReportPrintState)' in page_initializer
    assert 'hostDialog?.addEventListener("close", clearReportPrintState)' in page_initializer
    assert "document.body.classList.add(reportPrintClass)" in page_initializer
    assert "window.print()" in page_initializer
    assert 'data-network-boot-discovered-status role="status" aria-live="polite" hidden' in page.text
    assert "New Inventory Linux reports appear automatically while this page is visible." in page.text
    assert "Open the row menu" in page.text
    assert "initializeNetworkBootDiscoveredHostRefresh(hostsTable, discoveredStatus);" in page_initializer
    assert 'request("/api/v1/network-boot/hosts")' in host_refresh
    assert "await reconcileNetworkBootDiscoveredHosts(hostsTable, hosts);" in host_refresh
    assert "networkBootChangedRowValues(current, updated)" in app_js
    assert "if (Object.keys(changed).length) await row.update(changed);" in app_js
    assert 'document.addEventListener("visibilitychange", handleVisibilityChange);' in host_refresh

    host_reference = app_js.split("function initializeEsxiPxeHostsTable", 1)[1].split(
        "async function deleteEsxiInstallerIso", 1
    )[0]
    assert 'label: "Wake host"' in host_reference
    assert "esxiHostHasValidWakeMac" in host_reference
    host_wizard = app_js.split("function initializeEsxiHostReferenceWizard", 1)[1].split(
        "async function postEsxiHostAction", 1
    )[0]
    assert "kickstart_id: form.elements.kickstart_id.value ? Number(form.elements.kickstart_id.value) : null" in host_wizard
    assert 'mode: "promote"' in page_initializer

    app_css = client.get("/static/app.css").text
    assert ".network-boot-discovered-panel.active" in app_css
    assert "overflow: hidden !important;" in app_css
    assert ".network-boot-discovered-panel .tabulator-shell" in app_css
    assert "flex: 1 1 auto;" in app_css
    assert "min-height: 0;" in app_css
    assert "height: 240px !important;" in app_css
    assert ".host-reference-enable-step" in app_css
    assert "justify-items: center;" in app_css
    print_css = app_css.split("@media print", 1)[1]
    assert "@page atlaso-network-boot-report" in print_css
    assert "page: atlaso-network-boot-report;" in print_css
    assert "body.network-boot-report-printing #network-boot-host-dialog .network-boot-report" in print_css
    assert "body.network-boot-report-printing *" in print_css
    assert "\n  body * {" not in print_css
    assert ".network-boot-report-history" in print_css


def test_esxi_kickstart_validation_rejects_duplicate_install_directives(client):
    """Verify that esxi kickstart validation rejects duplicate install directives.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.services.esxi_pxe import kickstart_validation

    content = "\n".join(
        [
            "vmaccepteula",
            "rootpw vmware01!",
            "install --firstdisk --overwritevmfs",
            "install --firstdisk --overwritevmfs --dpupcislots=<PCIeSlotID>",
            "network --bootproto=dhcp --device=vmnic0",
            "reboot",
            "",
        ]
    )

    errors, warnings = kickstart_validation(content, strict=False, max_bytes=8192)

    assert "multiple install/upgrade directives on lines 3, 4; ESXi allows only one." in errors
    assert "missing install or upgrade directive" not in warnings


def test_esxi_kickstart_legacy_retrieval_is_unavailable(client):
    """Verify that reusable ID and revision retrieval paths stay unavailable.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, EsxiKickstart, EsxiPxeHost
    from atlaso.app.services.esxi_pxe import (
        assign_kickstart_content,
        canonical_http_path,
        content_hash,
        esxi_pxe_boot_settings,
        esxi_pxe_host_artifacts,
        host_variables_json,
        save_custom_variable_definition,
        save_esxi_pxe_boot_settings,
    )

    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.ntp_server = "192.168.50.1"
        kickstart = EsxiKickstart(name="Templated ESXi", content="", content_hash="", enabled=True)
        db.add(kickstart)
        db.flush()
        assign_kickstart_content(
            kickstart,
            "install --firstdisk={{custom.disk}}\nnetwork --bootproto=static --ip={{host.ip_address}} --gateway={{dhcp.gateway}} --netmask={{dhcp.netmask}} --hostname={{host.hostname}} --nameserver={{dhcp.dns_servers}}\nntpserver {{dhcp.ntp_servers}}\nrootpw VMware01!\nreboot\n%firstboot\n%end\n",
            max_bytes=262_144,
        )
        kickstart.http_path = canonical_http_path(kickstart.id, kickstart.content_hash)
        host = EsxiPxeHost(
            hostname="esx-vars",
            mac_address="00:50:56:aa:bb:cc",
            ip_address="192.168.50.150",
            kickstart_id=kickstart.id,
            variables_json=host_variables_json({"custom.disk": "mpx.vmhba0:C0:T0:L0"}),
            enabled=True,
        )
        db.add(host)
        save_custom_variable_definition(
            db,
            name="disk",
            description="Installation disk",
            default_value="fallbackdisk",
        )
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="esxi-pxe.atlaso.internal",
            dhcp_scope_ids=[scope.id],
            listen_interface="eth2",
            listen_address="192.168.50.1",
            tftp_root="/var/lib/atlaso/pxe/tftp",
            http_port="8080",
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
        )
        db.commit()
        kickstart_file = f"{content_hash(kickstart.content)[:12]}.cfg"
        static_kickstart = EsxiKickstart(name="Static ESXi", content="", content_hash="", enabled=True)
        db.add(static_kickstart)
        db.flush()
        assign_kickstart_content(
            static_kickstart,
            "install --firstdisk --overwritevmfs\nnetwork --bootproto=dhcp\nrootpw VMware01!\nreboot\n",
            max_bytes=262_144,
        )
        static_kickstart.http_path = canonical_http_path(static_kickstart.id, static_kickstart.content_hash)
        static_host = EsxiPxeHost(
            hostname="esx-static",
            mac_address="00:50:56:aa:bb:dd",
            ip_address="192.168.50.151",
            kickstart_id=static_kickstart.id,
            kickstart=static_kickstart,
            installer_iso_path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/esxi.iso",
            enabled=True,
        )
        db.add(static_host)
        static_kickstart_file = f"{content_hash(static_kickstart.content)[:12]}.cfg"
        static_artifacts = esxi_pxe_host_artifacts(
            [static_host],
            esxi_pxe_boot_settings(db),
            kickstart_paths={static_kickstart.id: static_kickstart.http_path},
        )
        static_artifact_url = static_artifacts[0]["kickstart_url"]
        db.commit()

    for path in (
        f"/pxe/esxi/ks/{kickstart.id}.cfg?mac=01-00-50-56-aa-bb-cc",
        f"/pxe/esxi/ks/{kickstart_file}?mac=01-00-50-56-aa-bb-cc",
        f"/pxe/esxi/ks/{static_kickstart_file}",
    ):
        response = client.get(path)
        assert response.status_code == 404
        assert "VMware01!" not in response.text
    assert static_artifact_url == ""


def test_esxi_pxe_host_variables_api_and_manifest(client):
    """Verify that esxi pxe host variables api and manifest.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, EsxiPxeHost
    from atlaso.app.services.esxi_pxe import content_hash, render_esxi_pxe_manifest

    token = create_api_token(client, ["read:esxi-pxe", "write:esxi-pxe"])
    created = client.post(
        "/api/v1/esxi-pxe/hosts",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "hostname": "api-esx",
            "mac_address": "01-00-50-56-aa-bb-ee",
            "variables": {"rack": "r12", "custom.install_disk": "firstdisk"},
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["mac_address"] == "00:50:56:aa:bb:ee"
    assert created.json()["variables"] == {"install_disk": "firstdisk", "rack": "r12"}
    invalid = client.post(
        "/api/v1/esxi-pxe/hosts",
        headers={"Authorization": f"Bearer {token}"},
        json={"hostname": "bad-esx", "mac_address": "00:50:56:aa:bb:ef", "variables": {"host.hostname": "override"}},
    )
    assert invalid.status_code == 400

    with SessionLocal() as db:
        host = db.execute(select(EsxiPxeHost).where(EsxiPxeHost.hostname == "api-esx")).scalar_one()
        assert host.mac_address == "00:50:56:aa:bb:ee"
        assert json.loads(host.variables_json) == {"install_disk": "firstdisk", "rack": "r12"}
        kickstart = EsxiKickstart(name="Vars", content="{{custom.install_disk}}\n", content_hash=content_hash("{{custom.install_disk}}\n"), enabled=True)
        db.add(kickstart)
        db.flush()
        host.kickstart_id = kickstart.id
        db.add(host)
        manifest = json.loads(render_esxi_pxe_manifest([kickstart], [host]))
    assert manifest["hosts"][0]["variables"] == {"install_disk": "firstdisk", "rack": "r12"}


def test_esxi_pxe_boot_settings_update_dnsmasq_and_apply_manifest(client):
    """Verify that esxi pxe boot settings update dnsmasq and apply manifest.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, DnsRecord
    from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings
    from atlaso.app.ui import dnsmasq_context, esxi_pxe_context

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    assert "Boot Service" in page.text
    assert "Hostname" in page.text
    assert "DHCP IP Zone" in page.text
    assert "Listen interfaces" not in page.text
    assert "Listen addresses" not in page.text
    assert 'type="hidden" name="tftp_root"' in page.text
    assert 'type="hidden" name="bios_bootfile"' in page.text
    assert 'type="hidden" name="uefi_bootfile"' in page.text
    assert 'field-label"><span>TFTP root' not in page.text
    assert 'field-label"><span>BIOS bootfile' not in page.text
    assert 'field-label"><span>UEFI bootfile' not in page.text
    assert "<span>BIOS bootfile</span><strong>undionly.kpxe</strong>" in page.text
    assert "<span>UEFI bootfile</span><strong>snponly.efi</strong>" in page.text
    assert "PXE HTTP port" in page.text
    assert "HTTP endpoint" in page.text
    host_tab = 'data-tab-target="esxi-pxe-hosts-panel" aria-controls="esxi-pxe-hosts-panel" aria-selected="true">Host References</button>'
    kickstart_tab = 'data-tab-target="esxi-pxe-editor-panel" aria-controls="esxi-pxe-editor-panel" aria-selected="false">Kickstarts</button>'
    iso_tab = 'data-tab-target="esxi-pxe-isos-panel" aria-controls="esxi-pxe-isos-panel" aria-selected="false">Installer ISOs</button>'
    assert page.text.index(host_tab) < page.text.index(kickstart_tab) < page.text.index(iso_tab)
    assert 'id="esxi-pxe-hosts-panel" class="tab-panel active" role="tabpanel"' in page.text
    assert 'id="esxi-pxe-editor-panel" class="tab-panel" role="tabpanel" hidden' in page.text
    assert "Type two opening braces for Atlaso variable suggestions." in page.text
    monaco_source = Path("scripts/monaco-entry.js").read_text()
    assert '"host.hostname"' in monaco_source
    assert '"dhcp.ntp_servers"' in monaco_source
    assert '"custom.<variable>"' in monaco_source
    assert '"custom.${1:variable}}}"' in monaco_source
    assert "modelCompletions" in monaco_source
    assert 'class="left-stack"' in page.text
    assert page.text.index("<h2>Boot Service</h2>") < page.text.index("<h2>ESXi Kickstarts</h2>")
    css = client.get("/static/app.css").text
    assert ".esxi-pxe-workspace .esxi-boot-service-panel" in css
    assert ".esxi-pxe-workspace > .side-stack" in css
    assert "grid-column: 2;" in css
    assert ".generated-options-panel" in css
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        pxe_scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        pxe_scope_id = str(pxe_scope.id)

    response = client.post(
        "/esxi-pxe/boot-settings",
        data={
            "csrf": csrf,
            "enabled": "on",
            "hostname": "esxi-pxe.atlaso.internal",
            "dhcp_scope_id": pxe_scope_id,
            "listen_addresses_present": "1",
            "listen_interfaces_present": "1",
            "tftp_root": "/var/lib/atlaso/pxe/tftp",
            "http_port": "8080",
            "bios_bootfile": "undionly.kpxe",
            "uefi_bootfile": "snponly.efi",
            "native_uefi_http_enabled": "on",
            "native_uefi_http_url": "",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        boot = esxi_pxe_boot_settings(db)
        assert boot["enabled"] is True
        assert boot["hostname"] == "esxi-pxe.atlaso.internal"
        assert boot["dhcp_scope_id"] == int(pxe_scope_id)
        assert boot["dhcp_scope_name"] == "SiteA"
        assert boot["listen_interface"] == "eth2"
        assert boot["listen_address"] == "192.168.50.1"
        assert boot["http_port"] == 8080
        assert boot["effective_native_uefi_http_url"] == "http://192.168.50.1:8080/pxe/esxi/snponly.efi"
        assert boot["native_uefi_http_enabled"] is True
        record = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "esxi-pxe.atlaso.internal", DnsRecord.record_type == "CNAME")
        ).scalar_one()
        assert record.address == "esxi-pxe-192-168-50-1.atlaso.internal"
        interface_record = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "esxi-pxe-192-168-50-1.atlaso.internal", DnsRecord.record_type == "A")
        ).scalar_one()
        assert interface_record.address == "192.168.50.1"
        dhcp = db.execute(select(DhcpSettings)).scalar_one()
        dhcp.enabled = True
        db.add(dhcp)
        db.commit()
        dns_preview = dnsmasq_context(db)["config_preview"]
        assert "enable-tftp" in dns_preview
        assert "dhcp-option=tag:sitea,66,esxi-pxe.atlaso.internal" in dns_preview
        assert (
            "dhcp-boot=tag:sitea,tag:ipxe,"
            "http://192.168.50.1:8080/pxe/boot.ipxe?mac=${net0/mac}"
            "&firmware=${platform}"
        ) in dns_preview
        assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:efi-x86_64,snponly.efi,esxi-pxe.atlaso.internal,192.168.50.1" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:!efi-x86_64,undionly.kpxe,esxi-pxe.atlaso.internal,192.168.50.1" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/snponly.efi" in dns_preview
        manifest = json.loads(esxi_pxe_context(db)["esxi_pxe_manifest"])
        assert manifest["schema_version"] == 2
        assert manifest["boot"]["enabled"] is True
        assert manifest["boot"]["hostname"] == "esxi-pxe.atlaso.internal"
        assert manifest["boot"]["dhcp_scope_id"] == int(pxe_scope_id)
        assert manifest["boot"]["http_port"] == 8080
        assert manifest["boot"]["bios_second_stage_bootfile"] == "pxelinux.0"
    dhcp_page = client.get("/dhcp")
    assert dhcp_page.status_code == 200
    assert dhcp_page.text.index("Desired State") < dhcp_page.text.index("Generated PXE") < dhcp_page.text.index("Actual Leases")
    assert 'id="dhcp-generated-pxe" class="tab-panel" role="tabpanel" hidden' in dhcp_page.text
    assert "Generated PXE Boot Options" in dhcp_page.text
    assert "SiteA" in dhcp_page.text
    assert "dhcp-userclass=set:ipxe,iPXE" in dhcp_page.text
    assert "dhcp-match=set:ipxe,175" in dhcp_page.text
    assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:!efi-x86_64,undionly.kpxe,esxi-pxe.atlaso.internal,192.168.50.1" in dhcp_page.text
    assert (
        "dhcp-boot=tag:sitea,tag:ipxe,"
        "http://192.168.50.1:8080/pxe/boot.ipxe?mac=${net0/mac}"
        "&amp;firmware=${platform}"
    ) in dhcp_page.text
    assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:efi-x86_64,snponly.efi,esxi-pxe.atlaso.internal,192.168.50.1" in dhcp_page.text
    assert "dhcp-boot=tag:sitea,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/snponly.efi" in dhcp_page.text
def test_esxi_pxe_multi_zone_host_reservations_and_grid_menu(client):
    """Verify that esxi pxe multi zone host reservations and grid menu.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpReservation, DhcpScope, DhcpSettings, DnsRecord
    from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings
    from atlaso.app.ui import dnsmasq_context, esxi_pxe_context

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    with SessionLocal() as db:
        sitea = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        siteb = DhcpScope(
            name="SiteB",
            interface_name="eth3",
            site_address="10.1.1.1",
            prefix_length=24,
            range_expression="10.1.1.100-200",
            lease_time="12h",
            domain_name="atlaso.internal",
            dns_server="10.1.1.1",
            ntp_server="10.1.1.1",
            enabled=True,
        )
        db.add(siteb)
        db.commit()
        sitea_id = sitea.id
        siteb_id = siteb.id

    response = client.post(
        "/esxi-pxe/boot-settings",
        data={
            "csrf": csrf,
            "enabled": "on",
            "hostname": "esxi-pxe.atlaso.internal",
            "dhcp_scope_ids": [str(sitea_id), str(siteb_id)],
            "listen_addresses_present": "1",
            "listen_interfaces_present": "1",
            "tftp_root": "/var/lib/atlaso/pxe/tftp",
            "http_port": "8080",
            "bios_bootfile": "undionly.kpxe",
            "uefi_bootfile": "snponly.efi",
            "native_uefi_http_enabled": "on",
            "native_uefi_http_url": "",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    with SessionLocal() as db:
        boot = esxi_pxe_boot_settings(db)
        assert boot["dhcp_scope_id"] == sitea_id
        assert boot["dhcp_scope_ids"] == [sitea_id, siteb_id]
        assert boot["dhcp_scope_names"] == ["SiteA", "SiteB"]
        assert boot["listen_interface"] == "eth2\neth3"
        assert boot["listen_address"] == "192.168.50.1\n10.1.1.1"
        assert boot["http_base_url"] == "http://192.168.50.1:8080/pxe/esxi"
        manifest = json.loads(esxi_pxe_context(db)["esxi_pxe_manifest"])
        assert manifest["boot"]["dhcp_scope_id"] == sitea_id
        assert manifest["boot"]["dhcp_scope_ids"] == [sitea_id, siteb_id]
        dhcp = db.execute(select(DhcpSettings)).scalar_one()
        dhcp.enabled = True
        db.add(dhcp)
        db.commit()
        dns_preview = dnsmasq_context(db)["config_preview"]
        assert "dhcp-option=tag:sitea,66,esxi-pxe.atlaso.internal" in dns_preview
        assert "dhcp-option=tag:siteb,66,esxi-pxe.atlaso.internal" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/snponly.efi" in dns_preview
        assert "dhcp-boot=tag:siteb,tag:uefi-http,tag:uefi-http-x64,http://10.1.1.1:8080/pxe/esxi/snponly.efi" in dns_preview

    create_host = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esx02",
            "mac_address": "01-00-50-56-aa-bb-cd",
            "ip_address": "10.1.1.150",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert create_host.status_code == 303, create_host.text

    with SessionLocal() as db:
        reservation = db.execute(select(DhcpReservation).where(DhcpReservation.mac_address == "00:50:56:aa:bb:cd")).scalar_one()
        assert reservation.hostname == "esx02.atlaso.internal"
        assert reservation.ip_address == "10.1.1.150"
        assert reservation.description == "Managed by ESXi PXE host 1."
        record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "esx02.atlaso.internal")).scalar_one()
        assert record.record_type == "A"
        assert record.address == "10.1.1.150"
        assert record.description == "Managed by ESXi PXE host 1."

    out_of_zone = client.post(
        "/esxi-pxe/hosts/1",
        data={
            "csrf": csrf,
            "hostname": "esx02",
            "mac_address": "01-00-50-56-aa-bb-cd",
            "ip_address": "172.16.1.50",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert out_of_zone.status_code == 400
    assert "inside a selected ESXi PXE DHCP zone" in out_of_zone.text

    remove_reservation = client.post(
        "/esxi-pxe/hosts/1",
        data={
            "csrf": csrf,
            "hostname": "esx02",
            "mac_address": "00:50:56:aa:bb:cd",
            "ip_address": "",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert remove_reservation.status_code == 303
    with SessionLocal() as db:
        assert db.execute(select(DhcpReservation).where(DhcpReservation.mac_address == "00:50:56:aa:bb:cd")).scalar_one_or_none() is None
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "esx02.atlaso.internal")).scalar_one_or_none() is None

    refreshed = client.get("/esxi-pxe")
    assert 'data-tag-name="dhcp_scope_ids"' in refreshed.text
    assert "SiteB - eth3 / 10.1.1.1/24" in refreshed.text
    app_js = client.get("/static/app.js").text
    host_grid_js = app_js.split("function initializeEsxiPxeHostsTable()", 1)[1].split(
        "function initializeEsxiInstallerIsosTable()", 1
    )[0]
    assert 'pattern: "wizard-backed"' in host_grid_js
    assert "rowActions" in host_grid_js
    assert "Edit host reference" in host_grid_js
    assert 'target.closest(\'[tabulator-field="enabled"]\')' in host_grid_js
    assert "Delete host reference" in host_grid_js
    delete_host_js = app_js.split("async function deleteEsxiHost(", 1)[1].split(
        "function initializeEsxiPxeHostsTable()", 1
    )[0]
    assert "Also remove" in delete_host_js
    assert "remove_discovered_host" in delete_host_js
    assert 'field: "ip_address"' in host_grid_js
    assert 'field: "variables_json"' in host_grid_js
    assert "data-esxi-host-wizard-add" in host_grid_js
    assert 'editable: (cell) => canWrite && cell.getRow().getData().is_default' in host_grid_js
    assert 'editable: (cell) => canWrite && !cell.getRow().getData().is_new' in host_grid_js


def test_esxi_host_delete_can_retain_or_remove_associated_discovery(client):
    """Verify that Host Reference deletion owns the optional discovery cleanup.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from tests.test_network_boot import inventory_report

    login(client)
    inventory_session = client.post("/pxe/inventory/sessions").json()
    submitted = client.post(
        "/pxe/inventory/report",
        json=inventory_report(),
        headers={"Authorization": f"Bearer {inventory_session['access_token']}"},
    )
    discovered_host_id = submitted.json()["host_id"]

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        EsxiPxeHost,
        NetworkBootDiscoveredHost,
        NetworkBootInventoryReport,
        NetworkBootInventorySession,
    )

    with SessionLocal() as db:
        reference = EsxiPxeHost(
            hostname="discovered-esxi",
            mac_address="52:54:00:12:34:56",
            enabled=False,
        )
        db.add(reference)
        db.commit()
        reference_id = reference.id

    page = client.get("/network-boot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert "Also remove discovered host" in page.text
    assert f'"discovered_host_ids": [{discovered_host_id}]' in page.text

    retained = client.post(
        f"/esxi-pxe/hosts/{reference_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert retained.status_code == 303, retained.text
    with SessionLocal() as db:
        assert db.get(EsxiPxeHost, reference_id) is None
        assert db.get(NetworkBootDiscoveredHost, discovered_host_id) is not None

        replacement = EsxiPxeHost(
            hostname="discovered-esxi-again",
            mac_address="52:54:00:12:34:56",
            enabled=False,
        )
        db.add(replacement)
        db.commit()
        replacement_id = replacement.id

    removed = client.post(
        f"/esxi-pxe/hosts/{replacement_id}/delete",
        data={"csrf": csrf, "remove_discovered_host": "on"},
        follow_redirects=False,
    )
    assert removed.status_code == 303, removed.text
    with SessionLocal() as db:
        assert db.get(EsxiPxeHost, replacement_id) is None
        assert db.get(NetworkBootDiscoveredHost, discovered_host_id) is None
        assert db.get(NetworkBootInventorySession, inventory_session["session_id"]) is None
        assert db.get(NetworkBootInventoryReport, submitted.json()["report_id"]) is None


def test_esxi_pxe_boot_settings_migrate_legacy_first_stage_defaults(client):
    """Verify that esxi pxe boot settings migrate legacy first stage defaults.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings

    login(client)
    with SessionLocal() as db:
        db.add(Setting(key="esxi_pxe.boot.bios_bootfile", value="pxelinux.0"))
        db.add(Setting(key="esxi_pxe.boot.uefi_bootfile", value="bootx64.efi"))
        db.commit()

    with SessionLocal() as db:
        boot = esxi_pxe_boot_settings(db)
        assert boot["bios_bootfile"] == "undionly.kpxe"
        assert boot["uefi_bootfile"] == "snponly.efi"
        saved_bios = db.execute(select(Setting).where(Setting.key == "esxi_pxe.boot.bios_bootfile")).scalar_one()
        assert saved_bios.value == "pxelinux.0"


def test_esxi_kickstarts_round_trip_in_settings_archive(client, monkeypatch, tmp_path):
    """Verify that esxi kickstarts round trip in settings archive.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.services.esxi_pxe as esxi_pxe
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, EsxiPxeHost, Setting
    from atlaso.app.seed import NTP_NTS_RESTORATION_SETTING_KEY
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_CUSTOM_VARIABLES_KEY,
        custom_variable_definitions,
        save_custom_variable_definition,
    )

    iso_root = tmp_path / "installer-isos"
    iso_root.mkdir()
    archive_iso_path = iso_root / "archive.iso"
    archive_iso_path.touch()
    monkeypatch.setattr(esxi_pxe, "ESXI_INSTALLER_ISO_ROOT", iso_root)

    login(client)
    with SessionLocal() as db:
        save_custom_variable_definition(
            db,
            name="install_disk",
            description="Preferred installation disk",
            default_value="firstdisk",
        )
        kickstart = EsxiKickstart(
            name="Archive ESXi",
            content="install --firstdisk={{custom.install_disk}}\nnetwork --bootproto=dhcp\nrootpw ArchiveSecret\nreboot\n%firstboot\n%end\n",
            content_hash="",
            rendered_content="install --firstdisk={{custom.install_disk}}\nnetwork --bootproto=dhcp\nrootpw ArchiveSecret\nreboot\n%firstboot\n%end\n",
            enabled=True,
        )
        db.add(kickstart)
        db.flush()
        from atlaso.app.services.esxi_pxe import (
            assign_kickstart_content,
            canonical_http_path,
        )

        assign_kickstart_content(kickstart, kickstart.content, max_bytes=262_144)
        kickstart.http_path = canonical_http_path(kickstart.id, kickstart.content_hash)
        db.add(
            EsxiPxeHost(
                hostname="esxi-archive",
                mac_address="00:50:56:aa:bb:cc",
                ip_address="192.168.50.150",
                kickstart_id=kickstart.id,
                installer_iso_path=str(archive_iso_path),
                variables_json='{"rack":"r42"}',
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/backup-restore")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    exported = client.post("/backup-restore/export", data={"csrf": csrf})
    payload = json.loads(exported.content)

    assert payload["data"]["esxi_kickstarts"][0]["name"] == "Archive ESXi"
    assert payload["data"]["esxi_pxe_hosts"][0]["kickstart_name"] == "Archive ESXi"
    assert payload["data"]["esxi_pxe_hosts"][0]["ip_address"] == "192.168.50.150"
    assert payload["data"]["esxi_pxe_hosts"][0]["installer_iso_path"] == str(
        archive_iso_path
    )
    assert payload["data"]["esxi_pxe_hosts"][0]["variables"] == {"rack": "r42"}
    assert payload["data"]["settings"] == [
        {
            "key": ESXI_PXE_CUSTOM_VARIABLES_KEY,
            "value": '[{"default_value":"firstdisk","description":"Preferred installation disk","id":"install_disk","name":"install_disk"}]',
        },
        {"key": NTP_NTS_RESTORATION_SETTING_KEY, "value": "complete"},
    ]

    with SessionLocal() as db:
        db.query(EsxiPxeHost).delete()
        db.query(EsxiKickstart).delete()
        db.query(Setting).filter(Setting.key == ESXI_PXE_CUSTOM_VARIABLES_KEY).delete()
        db.commit()

    payload["data"]["esxi_pxe_hosts"][0]["installer_iso_path"] = archive_iso_path.name
    restore_content = json.dumps(payload).encode("utf-8")
    restored = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={"archive_file": ("atlaso-settings.json", restore_content, "application/json")},
    )

    assert restored.status_code == 200
    with SessionLocal() as db:
        restored_kickstart = db.execute(select(EsxiKickstart).where(EsxiKickstart.name == "Archive ESXi")).scalar_one()
        restored_host = db.execute(select(EsxiPxeHost).where(EsxiPxeHost.hostname == "esxi-archive")).scalar_one()
        assert restored_host.kickstart_id == restored_kickstart.id
        assert restored_host.ip_address == "192.168.50.150"
        assert restored_host.installer_iso_path == str(archive_iso_path)
        assert restored_host.variables_json == '{"rack": "r42"}'
        assert custom_variable_definitions(db) == [
            {
                "id": "install_disk",
                "name": "install_disk",
                "description": "Preferred installation disk",
                "default_value": "firstdisk",
            }
        ]


def test_esxi_pxe_drift_detection_uses_generated_filesystem_copy(client, monkeypatch, tmp_path):
    """Verify that esxi pxe drift detection uses generated filesystem copy.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """

    import atlaso.app.services.esxi_pxe as esxi_pxe
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart

    monkeypatch.setattr(esxi_pxe, "ESXI_KICKSTART_HTTP_ROOT", tmp_path)
    login(client)
    content = "install\nnetwork --bootproto=dhcp\nrootpw DriftSecret\nreboot\n%firstboot\n%end\n"
    with SessionLocal() as db:
        kickstart = EsxiKickstart(name="Drift ESXi", content=content, content_hash=esxi_pxe.content_hash(content), rendered_content=content, rendered_hash=esxi_pxe.content_hash(content), enabled=True)
        db.add(kickstart)
        db.flush()
        kickstart.http_path = esxi_pxe.canonical_http_path(kickstart.id, kickstart.content_hash)
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / f"{kickstart.content_hash[:12]}.cfg").write_text(content.replace("DriftSecret", "ChangedOnDisk"), encoding="utf-8")
        db.commit()
        kickstart_id = kickstart.id

    page = client.get(f"/esxi-pxe?kickstart_id={kickstart_id}")
    assert page.status_code == 200
    assert "filesystem modified" in page.text
    assert "Filesystem copy differs from database source. The next ESXi PXE apply will overwrite the filesystem copy from the database." in page.text


def test_backup_restore_restore_replaces_settings_and_stops_services(client):
    """Verify that backup restore restore replaces settings and stops services.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, AuditEvent, ServiceState

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.fqdn = "restore-target.atlaso.internal"
        service = db.execute(select(ServiceState).where(ServiceState.service == "dns")).scalar_one()
        service.running = True
        service.enabled = True
        service.health = "healthy"
        db.commit()

    page = client.get("/backup-restore")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    exported = client.post("/backup-restore/export", data={"csrf": csrf})
    archive_bytes = exported.content

    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.fqdn = "temporary-change.atlaso.internal"
        db.commit()

    restored = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={"archive_file": ("atlaso-settings.json", archive_bytes, "application/json")},
    )

    assert restored.status_code == 200
    assert "Settings restored" in restored.text
    assert "Services are stopped and unconfigured" in restored.text
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.fqdn == "restore-target.atlaso.internal"
        services = db.execute(select(ServiceState)).scalars().all()
        assert services
        assert all(not service.running and not service.enabled and service.health == "unconfigured" for service in services)
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "restore_settings_backup")).scalar_one()
        assert "services forced stopped/unconfigured" in (event.detail or "")
    payload = json.loads(archive_bytes)
    assert payload["data"]["service_states"]


def test_backup_restore_rejects_enabled_settings_archive_without_vcf_backup_user(client):
    """Verify enabled VCF backup restore requires a retained enabled user.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User, VcfBackupSettings

    login(client)
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "vcf-backup")).scalar_one_or_none()
        if user is None:
            user = User(username="vcf-backup", role="viewer", roles_json='["viewer"]', shell="/sbin/nologin", enabled=False)
            db.add(user)
            db.flush()
        settings = db.execute(select(VcfBackupSettings)).scalar_one()
        settings.enabled = True
        settings.sftp_user_id = user.id
        db.commit()

    page = client.get("/backup-restore")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    exported = client.post("/backup-restore/export", data={"csrf": csrf})
    archive_bytes = exported.content

    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "vcf-backup")).scalar_one()
        settings = db.execute(select(VcfBackupSettings)).scalar_one()
        settings.sftp_user_id = None
        db.flush()
        db.delete(user)
        db.commit()

    restored = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={"archive_file": ("atlaso-settings.json", archive_bytes, "application/json")},
    )

    assert restored.status_code == 400
    assert "requires an enabled local user" in restored.text
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "vcf-backup")).scalar_one_or_none()
        settings = db.execute(select(VcfBackupSettings)).scalar_one()
        assert user is None
        assert settings.sftp_user_id is None


def test_backup_restore_factory_reset_resets_desired_state_and_stops_services(client):
    """Verify that backup restore factory reset resets desired state and stops services.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        AuditEvent,
        CaCertificate,
        CaProfile,
        DhcpReservation,
        DhcpScope,
        DhcpSettings,
        DnsRecord,
        DnsSettings,
        FirewallRule,
        KmsSettings,
        NatRule,
        PhysicalInterface,
        Route,
        RoutingRule,
        ServiceState,
        Setting,
        VcfBackupSettings,
        VcfDepotDownloadProfile,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
        VlanInterface,
        WanPolicy,
    )
    from atlaso.app.seed import SEED_EXAMPLES_SETTING_KEY, seed_initial_data

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.fqdn = "custom.atlaso.internal"
        db.add(DnsRecord(hostname="remove-me.atlaso.internal", record_type="A", address="192.168.50.250"))
        service = db.execute(select(ServiceState).where(ServiceState.service == "vcf-backups")).scalar_one()
        service.running = True
        service.enabled = True
        service.health = "healthy"
        db.commit()

    page = client.get("/backup-restore")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    reset = client.post("/backup-restore/factory-reset", data={"csrf": csrf})

    assert reset.status_code == 200
    assert "Factory reset complete" in reset.text
    assert "without demo resources" in reset.text
    assert "Non-management NICs are desired admin down" in reset.text
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        assert settings.fqdn == "core.atlaso.internal"
        interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        assert [interface.name for interface in interfaces] == ["eth0"]
        assert interfaces[0].role == "management"
        assert interfaces[0].admin_state == "up"
        assert interfaces[0].ip_cidr == "192.168.49.1/24"
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert dns_settings.listen_interface == ""
        assert dns_settings.listen_address in ("", None)
        assert dns_settings.authoritative_server == "ns1.atlaso.internal"
        assert dns_settings.authoritative_contact == "hostmaster.atlaso.internal"
        assert dns_settings.authoritative_ttl == 3600
        assert dns_settings.authoritative_refresh == 1200
        assert dns_settings.authoritative_retry == 180
        assert dns_settings.authoritative_expire == 1209600
        assert dns_settings.authoritative_serial > 0
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        assert dhcp_settings.interface_name == ""
        assert dhcp_settings.site_address == ""
        kms_settings = db.execute(select(KmsSettings)).scalar_one()
        assert kms_settings.listen_interface == ""
        assert kms_settings.listen_address == ""
        vcf_backup_settings = db.execute(select(VcfBackupSettings)).scalar_one()
        assert vcf_backup_settings.listen_interface == ""
        assert vcf_backup_settings.listen_address == ""
        vcf_depot_settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert vcf_depot_settings.listen_interface == ""
        assert vcf_depot_settings.listen_address == ""
        vcf_registry_settings = db.execute(select(VcfPrivateRegistrySettings)).scalar_one()
        assert vcf_registry_settings.listen_interface == ""
        assert vcf_registry_settings.listen_address == ""
        removed = db.execute(select(DnsRecord).where(DnsRecord.hostname == "remove-me.atlaso.internal")).scalar_one_or_none()
        assert removed is None
        assert db.execute(select(VlanInterface)).scalars().all() == []
        assert db.execute(select(WanPolicy)).scalars().all() == []
        assert db.execute(select(NatRule)).scalars().all() == []
        assert db.execute(select(Route)).scalars().all() == []
        assert db.execute(select(RoutingRule)).scalars().all() == []
        dns_records = db.execute(select(DnsRecord)).scalars().all()
        assert len(dns_records) == 1
        assert dns_records[0].hostname == "core.atlaso.internal"
        assert dns_records[0].record_type == "A"
        assert dns_records[0].address == "192.168.49.1"
        assert "app-owned appliance FQDN" in (dns_records[0].description or "")
        assert db.execute(select(DhcpScope)).scalars().all() == []
        assert db.execute(select(DhcpReservation)).scalars().all() == []
        assert db.execute(select(FirewallRule)).scalars().all() == []
        assert db.execute(select(CaProfile)).scalars().all() == []
        assert db.execute(select(CaCertificate)).scalars().all() == []
        depot_profiles = db.execute(
            select(VcfDepotDownloadProfile).order_by(VcfDepotDownloadProfile.name)
        ).scalars().all()
        assert [(profile.name, profile.profile_type, profile.enabled) for profile in depot_profiles] == [
            ("Binaries", "binaries", False),
            ("Esx", "esx", False),
            ("Metadata", "metadata", False),
        ]
        marker = db.execute(select(Setting).where(Setting.key == SEED_EXAMPLES_SETTING_KEY)).scalar_one()
        assert marker.value == "false"
        seed_initial_data(db)
        assert db.execute(select(VlanInterface)).scalars().all() == []
        dns_records = db.execute(select(DnsRecord)).scalars().all()
        assert len(dns_records) == 1
        assert dns_records[0].hostname == "core.atlaso.internal"
        depot_profiles = db.execute(
            select(VcfDepotDownloadProfile).order_by(VcfDepotDownloadProfile.name)
        ).scalars().all()
        assert [(profile.name, profile.profile_type, profile.enabled) for profile in depot_profiles] == [
            ("Binaries", "binaries", False),
            ("Esx", "esx", False),
            ("Metadata", "metadata", False),
        ]
        services = db.execute(select(ServiceState)).scalars().all()
        assert services
        assert all(not service.running and not service.enabled and service.health == "unconfigured" for service in services)
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "factory_reset_settings")).scalar_one()
        assert "services forced stopped/unconfigured" in (event.detail or "")


def test_real_local_users_apply_preserves_pending_password_for_disabled_user():
    """Verify that real local users apply preserves pending password for disabled user."""
    from atlaso.app.models import User
    from atlaso.app.services.local_users import (
        clear_pending_os_password,
        has_pending_os_password,
        mark_local_users_applied,
        stage_user_os_password,
    )

    user = User(username="disabled-staged", role="viewer", shell="/sbin/nologin", enabled=False)
    stage_user_os_password(user, "Disabled-Bridge1!")
    try:
        mark_local_users_applied([user])
        assert has_pending_os_password(user)
        assert user.os_password_applied_at is None
        assert user.os_sync_status == "pending"
    finally:
        clear_pending_os_password(user)


def test_apply_status_reads_preserve_multiple_staged_service_user_passwords(client):
    """Verify that apply status reads preserve multiple staged service user passwords.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User
    from atlaso.app.services.local_users import (
        clear_pending_os_password,
        has_pending_os_password,
    )
    from atlaso.app.ui import appliance_apply_units

    login(client)
    users_page = client.get("/users")
    csrf = users_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        service_users = db.execute(select(User).where(User.username.in_(["vcf-backup", "vcf-depot"]))).scalars().all()
        assert {user.username for user in service_users} == {"vcf-backup", "vcf-depot"}
        for user in service_users:
            clear_pending_os_password(user)
        user_ids = {user.username: user.id for user in service_users}

    for username, password in {
        "vcf-backup": "Backup-Bridge1!",
        "vcf-depot": "Depot-Bridge1!",
    }.items():
        reset = client.post(
            f"/users/{user_ids[username]}/password",
            data={"password": password, "confirm_password": password, "csrf": csrf},
            follow_redirects=False,
        )
        assert reset.status_code == 303

    for _ in range(2):
        status = client.get("/appliance-apply/status")
        assert status.status_code == 200

    with SessionLocal() as db:
        service_users = db.execute(select(User).where(User.username.in_(["vcf-backup", "vcf-depot"]))).scalars().all()
        assert all(user.enabled for user in service_users)
        assert all(has_pending_os_password(user) for user in service_users)
        local_users_unit = next(unit for unit in appliance_apply_units(db) if unit["id"] == "local_users")
        payload = json.loads(local_users_unit["raw_config_preview"])
        service_rows = {
            row["username"]: row
            for row in payload["users"]
            if row["username"] in {"vcf-backup", "vcf-depot"}
        }
        assert set(service_rows) == {"vcf-backup", "vcf-depot"}
        assert all(row["enabled"] for row in service_rows.values())
        assert all(bool(row.get("password")) for row in service_rows.values())
        for user in service_users:
            clear_pending_os_password(user)


def test_real_local_users_apply_clears_pending_passwords_and_baselines_post_apply(client, monkeypatch, tmp_path):
    """Verify that real local users apply clears pending passwords and baselines post apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui_module
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, User

    base_system_adapter = ui_module.SystemAdapter

    class SuccessfulLocalUsersAdapter(base_system_adapter):
        """Represent successful local users adapter."""
        def __init__(self) -> None:
            """Initialize the successful local users adapter."""
            super().__init__(dry_run=False)

        def read_dhcp_leases(self) -> AdapterResult:
            """Return dhcp leases."""
            return AdapterResult(command=["atlaso-helper", "dnsmasq", "leases"], dry_run=True, stdout="")

        def validate_local_users_config(self, config_path: str) -> AdapterResult:
            """Validate local users config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The validate local users config result.
            """
            return AdapterResult(command=["atlaso-helper", "local-users", "validate", config_path], dry_run=False, stdout="validation ok")

        def apply_local_users_config(self, config_path: str) -> AdapterResult:
            """Update local users config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The apply local users config result.
            """
            return AdapterResult(command=["atlaso-helper", "local-users", "apply", config_path], dry_run=False, stdout="apply complete")

    staged_path = tmp_path / "apply" / "local-users" / "atlaso-users.json"
    monkeypatch.setattr(ui_module, "LOCAL_USERS_STAGED_CONFIG_PATH", str(staged_path))
    monkeypatch.setattr(ui_module, "SystemAdapter", SuccessfulLocalUsersAdapter)

    login(client)
    users = client.get("/users")
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/users",
        data={"username": "real-sync", "role": "viewer", "csrf": csrf},
        follow_redirects=False,
    )
    assert created.status_code == 303
    users = client.get("/users")
    import html
    import json

    rows = json.loads(html.unescape(users.text.split("data-users='", 1)[1].split("'", 1)[0]))
    user_id = next(row["id"] for row in rows if row["username"] == "real-sync")
    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": "BridgeStrong1!", "confirm_password": "BridgeStrong1!", "csrf": csrf},
        follow_redirects=False,
    )
    assert reset.status_code == 303

    apply_page = client.get("/appliance-apply")
    csrf = apply_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    applied = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "local_users"})
    assert applied.status_code == 200
    assert not staged_path.exists()
    assert "BridgeStrong1!" not in applied.text

    with SessionLocal() as db:
        users = db.execute(select(User)).scalars().all()
        assert all(user.os_sync_status == "applied" for user in users)
        baseline = db.execute(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).scalar_one()
        assert "BridgeStrong1!" not in baseline.value
        assert '"password_pending": true' not in baseline.value


def test_audit_log_renders(client):
    """Verify that audit log renders.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    response = client.get("/audit-log")

    assert response.status_code == 200
    assert "Audit Events" in response.text
    assert "ui_login" in response.text
    assert 'id="audit-events-table"' in response.text
    assert "data-audit-events=" in response.text
    assert 'id="audit-events-fallback"' in response.text
    assert 'id="audit-events-table" class="tabulator-shell audit-events-grid hidden"' in response.text
    assert 'id="audit-events-fallback" class="audit-events-fallback-shell"' in response.text
    assert 'id="audit-events-fallback" class="audit-events-fallback-shell hidden"' not in response.text
    audit_js = client.get("/static/app.js").text.split("function initializeAuditEventsTable", 1)[1].split("function ", 1)[0]
    assert "window.AtlasoUiPatterns.createGrid({" in audit_js
    assert 'pattern: "read-only"' in audit_js
    assert "if (!table) return" in audit_js
    assert 'tableElement.classList.add("hidden")' in audit_js
    assert 'renderVertical: "virtual"' in audit_js
    assert "pagination: true" in audit_js
    assert 'paginationMode: "local"' in audit_js
    assert "const rowHeight = 30" in audit_js
    assert "paginationSize: pageSizeForHeight()" in audit_js
    assert "new ResizeObserver" in audit_js
    assert "table.setPageSize(nextPageSize)" in audit_js
    assert 'formatter: "plaintext", tooltip: true' in audit_js
    assert "paginationSize: 100" not in audit_js
    audit_css = client.get("/static/app.css").text
    assert ".audit-events-panel" in audit_css
    assert "height: calc(100vh - 120px);" in audit_css
    assert "flex: 1 1 0;" in audit_css
    assert "min-height: min(480px, calc(100vh - 200px));" in audit_css
    assert ".audit-events-fallback-shell" in audit_css
    assert "overflow: auto;" in audit_css


def test_logs_page_shows_unavailable_state_when_every_source_is_unavailable(client, monkeypatch):
    """Verify that logs page shows unavailable state when every source is unavailable.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    unavailable_sources = [
        {
            "id": "app",
            "label": "Atlaso App",
            "path": "/var/log/atlaso/atlaso.log",
            "available": False,
            "lines": [],
            "size_bytes": 0,
            "updated_at": "",
            "truncated": False,
            "error": "Log file has not been written yet.",
        },
        {
            "id": "kms",
            "label": "KMS",
            "path": "/var/log/atlaso/kms.log",
            "available": False,
            "lines": [],
            "size_bytes": 0,
            "updated_at": "",
            "truncated": False,
            "error": "Log file has not been written yet.",
        },
    ]
    monkeypatch.setattr(
        "atlaso.app.ui.log_sources_context",
        lambda *, max_lines=100: unavailable_sources,
    )

    login(client)
    response = client.get("/logs")

    assert response.status_code == 200
    app_tab = response.text.split('data-log-source-tab="app"', 1)[1].split("</button>", 1)[0]
    assert 'class="tab-button active"' in response.text.split('data-log-source-tab="app"', 1)[0].rsplit("<button", 1)[1]
    assert 'aria-selected="true"' in app_tab
    assert 'aria-disabled="true"' in app_tab
    app_panel = response.text.split('id="logs-app-panel"', 1)[1].split('id="logs-kms-panel"', 1)[0]
    assert 'id="logs-app-panel" class="tab-panel active"' in response.text
    assert "Log file has not been written yet." in app_panel
    kms_panel_tag = response.text.split('id="logs-kms-panel"', 1)[1].split(">", 1)[0]
    assert 'class="tab-panel "' in kms_panel_tag
    assert " hidden" in kms_panel_tag


def test_logs_page_renders_refreshable_fixed_source_tabs_and_redacts_logs(client, tmp_path, monkeypatch):
    """Verify that logs page renders refreshable fixed source tabs and redacts logs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult

    app_log = tmp_path / "atlaso.log"
    kms_log = tmp_path / "kms.log"
    jwt_segment = (
        "eyJ2ZXIiOiIyIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ."
        "eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzgyNDQ1MzcxfQ."
        "signatureSegmentLongEnoughToLookLikeJwt"
    )
    app_log.write_text(
        "\n".join([*(f"app line {index}" for index in range(120)), "token=secret-download-token", f"GET https://dl.broadcom.com/{jwt_segment}/PROD/file.json"]),
        encoding="utf-8",
    )
    monkeypatch.setattr("atlaso.app.ui.ATLASO_APP_LOG_PATH", app_log)
    monkeypatch.setattr("atlaso.app.ui.KMS_SERVER_LOG_PATH", kms_log)
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_dnsmasq_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "dnsmasq", "logs"],
            dry_run=False,
            stdout=(
                "dnsmasq[10]: query[A] example.test from 192.0.2.10\n"
                "dnsmasq-dhcp[10]: DHCPACK(eth1) 192.0.2.20 client\n"
                "dnsmasq-tftp[10]: sent /var/lib/atlaso/pxe/tftp/snponly.efi to 192.0.2.20\n"
                "password=do-not-render\n"
            ),
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "logs"],
            dry_run=False,
            stdout="ntpd ready\nprivate_key=do-not-render\n",
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ldap_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ldap", "logs"],
            dry_run=False,
            stdout='slapd[30]: conn=1000 op=0 BIND dn="uid=operator,ou=users,dc=org1" method=128\nbind_password=do-not-render\n',
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_nginx_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "nginx", "logs"],
            dry_run=False,
            stdout="nginx[20]: management request completed\nrequest_token=do-not-render\n",
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_nginx_access_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "nginx", "access-logs"],
            dry_run=False,
            stdout='192.0.2.10 - - [13/Jul/2026:20:15:31 -0700] "GET /dashboard HTTP/1.1" 200 1234\naccess_token=do-not-render\n',
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_nginx_error_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "nginx", "error-logs"],
            dry_run=False,
            stdout="2026/07/13 20:15:31 [error] 12#12: upstream timed out\npassword=do-not-render\n",
        ),
    )

    login(client)
    response = client.get("/logs")

    assert response.status_code == 200
    assert "Logs" in response.text
    assert 'data-tab-storage-key="atlaso:logs:active-tab"' in response.text
    assert 'data-log-source-tab="vcfdt"' not in response.text
    assert "Atlaso App" in response.text
    assert "DNS" in response.text
    assert "DHCP" in response.text
    assert "TFTP" in response.text
    assert "LDAP / LDAPS" in response.text
    assert "KMS" in response.text
    assert "NTP / NTS" in response.text
    assert "ESX Storage NFS" in response.text
    assert "Nginx" in response.text
    assert "HTTP Access" in response.text
    assert "HTTP Errors" in response.text
    assert "logs-audit-panel" not in response.text
    assert 'data-log-source-tab="dnsmasq-dns"' in response.text
    assert 'title="dnsmasq.service journal: DNS and service messages"' in response.text
    assert 'data-log-source-tab="dnsmasq-dhcp"' in response.text
    assert 'title="dnsmasq.service journal: DHCP messages"' in response.text
    assert 'data-log-source-tab="dnsmasq-tftp"' in response.text
    assert 'title="dnsmasq.service journal: TFTP messages"' in response.text
    assert 'data-log-source-tab="ldap"' in response.text
    assert 'title="slapd.service journal: LDAP and LDAPS directory events"' in response.text
    assert 'data-log-source-tab="nginx"' in response.text
    assert 'title="systemd journal: nginx.service"' in response.text
    assert 'data-log-source-tab="nginx-access"' in response.text
    assert 'title="/var/log/nginx/access.log · management and service HTTP requests"' in response.text
    assert 'data-log-source-tab="nginx-error"' in response.text
    assert 'title="/var/log/nginx/error.log · management and service HTTP errors"' in response.text
    assert 'data-log-source-tab="kms"' in response.text
    kms_tab = response.text.split('data-log-source-tab="kms"', 1)[1].split("</button>", 1)[0]
    assert 'aria-disabled="true"' in kms_tab
    assert "disabled" in kms_tab
    assert "data-log-availability" not in response.text
    assert 'data-log-lines aria-label="Log lines"' in response.text
    assert '<option value="100" selected>100</option>' in response.text
    assert '<option value="200" >200</option>' in response.text
    assert '<option value="500" >500</option>' in response.text
    assert "Refresh 5s" in response.text
    assert 'class="language-atlaso-log" data-log-lines-output' in response.text
    assert response.text.count('data-terminal-note-open="false"') == 11
    toolbar = response.text.split('<div class="logs-toolbar">', 1)[1].split("</div>", 1)[0]
    assert toolbar.index("data-log-refresh-status") < toolbar.index("data-log-lines")
    assert "logs-refresh-status" in toolbar
    assert "token= [redacted]" in response.text
    assert "https://dl.broadcom.com/[redacted-token]/PROD/file.json" in response.text
    assert "secret-download-token" not in response.text
    assert jwt_segment not in response.text
    assert "ntpd ready" in response.text
    assert "query[A] example.test" in response.text
    assert "DHCPACK(eth1)" in response.text
    assert "sent /var/lib/atlaso/pxe/tftp/snponly.efi" in response.text
    assert "slapd[30]: conn=1000 op=0 BIND" in response.text
    assert "uid=operator,ou=users,dc=org1" in response.text
    assert "bind_password= [redacted]" in response.text
    assert "private_key= [redacted]" in response.text
    assert "management request completed" in response.text
    assert "GET /dashboard HTTP/1.1" in response.text
    assert "upstream timed out" in response.text
    assert "access_token= [redacted]" in response.text
    assert "request_token= [redacted]" in response.text
    assert "password= [redacted]" in response.text
    assert "do-not-render" not in response.text
    assert "Log file has not been written yet." in response.text

    data_response = client.get("/logs/data?lines=500")
    assert data_response.status_code == 200
    payload = data_response.json()
    assert payload["line_count"] == 500
    assert [source["id"] for source in payload["sources"]] == [
        "app",
        "dnsmasq-dns",
        "dnsmasq-dhcp",
        "dnsmasq-tftp",
            "ldap",
            "ntp",
            "esx-storage",
            "nginx",
        "nginx-access",
        "nginx-error",
        "kms",
    ]
    assert "query[A] example.test" in "\n".join(payload["sources"][1]["lines"])
    assert "DHCPACK(eth1)" not in "\n".join(payload["sources"][1]["lines"])
    assert "DHCPACK(eth1)" in "\n".join(payload["sources"][2]["lines"])
    assert "sent /var/lib/atlaso/pxe/tftp/snponly.efi" in "\n".join(payload["sources"][3]["lines"])
    assert 'BIND dn="uid=operator,ou=users,dc=org1"' in "\n".join(payload["sources"][4]["lines"])
    assert len(payload["sources"][0]["lines"]) == 122
    assert "secret-download-token" not in "\n".join(payload["sources"][0]["lines"])

    invalid_response = client.get("/logs/data?lines=240")
    assert invalid_response.status_code == 200
    assert invalid_response.json()["line_count"] == 100

    js = client.get("/static/app.js")
    assert "function initializeLogsPage" in js.text
    assert 'window.setInterval(refresh, 5000)' in js.text
    assert 'atlaso:logs:line-count' in js.text
    assert "refreshQueued = true" in js.text
    assert "tabButton.disabled = !source.available" in js.text
    assert "activeButton.disabled" in js.text
    assert 'window.Prism.languages["atlaso-log"]' in js.text
    assert '"level-error"' in js.text
    assert "highlightConfigPreviewElement(output);" in js.text
    css = client.get("/static/app.css")
    assert "height: calc(100vh - 120px);" in css.text
    assert "flex: 1 1 0;" in css.text
    assert "grid-template-rows: minmax(0, 1fr);" in css.text
    assert "grid-template-rows: auto minmax(0, 1fr);" in css.text
    assert "overflow-y: auto;" in css.text
    logs_css = css.text[
        css.text.index("[data-logs-page]") : css.text.index(".audit-events-panel")
    ]
    assert "scrollbar-gutter: stable;" not in logs_css
    assert "scrollbar-width: thin;" not in logs_css
    assert "scrollbar-color:" not in logs_css
    assert "overscroll-behavior:" not in logs_css
    assert "::-webkit-scrollbar-thumb" in css.text
    assert "white-space: nowrap;" in css.text


def test_configure_logging_writes_main_app_log(tmp_path, monkeypatch):
    """Verify that configure logging writes main app log.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import logging
    from logging.handlers import RotatingFileHandler

    from atlaso.app.config import get_settings
    from atlaso.app.main import configure_logging

    log_path = tmp_path / "atlaso.log"
    monkeypatch.setenv("ATLASO_APP_LOG_PATH", str(log_path))
    get_settings.cache_clear()

    configure_logging()
    logging.getLogger("atlaso.appliance_apply").error("apply failure visible in main log")
    for handler in logging.getLogger().handlers:
        handler.flush()

    assert "apply failure visible in main log" in log_path.read_text(encoding="utf-8")

    for handler in list(logging.getLogger().handlers):
        if isinstance(handler, RotatingFileHandler) and handler.baseFilename == str(log_path):
            logging.getLogger().removeHandler(handler)
            handler.close()
    get_settings.cache_clear()


def test_appliance_apply_logging_redacts_commands_and_helper_output(caplog):
    """Verify appliance apply logging reports evidence without command or helper content.

    Args:
        caplog: Pytest log capture fixture.
    """
    import logging

    from atlaso.app.ui import (
        log_appliance_apply_failures,
        log_appliance_apply_submission,
    )

    unit_results = [
        {
            "unit_id": "kms",
            "label": "KMS",
            "status": "failed",
            "dry_run": False,
            "validation_errors": [],
            "validation_warnings": [],
            "summary": "Apply failed.",
            "commands": [
                {
                    "command_line": "atlaso-helper kms apply sensitive-command-value",
                    "returncode": 2,
                    "stdout": "sensitive-helper-stdout",
                    "stderr": "sensitive-helper-stderr",
                    "dry_run": False,
                }
            ],
        }
    ]

    with caplog.at_level(logging.INFO, logger="atlaso.appliance_apply"):
        log_appliance_apply_failures("job_redacted", unit_results)
        log_appliance_apply_submission(
            "job_redacted",
            selected_units=["kms"],
            skipped_changed_units=[],
            unit_results=unit_results,
            succeeded=False,
        )

    logged = caplog.text
    assert "sensitive-command-value" not in logged
    assert "sensitive-helper-stdout" not in logged
    assert "sensitive-helper-stderr" not in logged
    assert "job_redacted" in logged
    assert "helper and desired-state details omitted" in logged
    assert "desired-state and helper details omitted" in logged
    assert "command_index" not in logged
    assert "returncode" not in logged
    assert "stdout_present" not in logged


def test_record_audit_writes_redacted_operational_log(client, tmp_path, monkeypatch):
    """Verify that record audit writes redacted operational log.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import logging
    from logging.handlers import RotatingFileHandler

    from atlaso.app.audit import record_audit
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.main import configure_logging

    log_path = tmp_path / "atlaso.log"
    monkeypatch.setenv("ATLASO_APP_LOG_PATH", str(log_path))
    get_settings.cache_clear()

    with SessionLocal() as db:
        configure_logging(db)
        record_audit(
            db,
            actor="admin",
            action="update_dns_settings",
            resource_type="dns",
            resource_id="1",
            detail="password=super-secret\nlisten_address=192.168.49.1",
            request_id="req_test",
        )

    for handler in logging.getLogger().handlers:
        handler.flush()

    text = log_path.read_text(encoding="utf-8")
    assert "audit actor=admin action=update_dns_settings resource=dns resource_id=1 success=True request_id=req_test" in text
    assert "password= [redacted]" in text
    assert "listen_address=192.168.49.1" in text
    assert "super-secret" not in text

    for handler in list(logging.getLogger().handlers):
        if isinstance(handler, RotatingFileHandler) and handler.baseFilename == str(log_path):
            logging.getLogger().removeHandler(handler)
            handler.close()
    get_settings.cache_clear()


def test_logs_page_handles_default_pure_posix_log_path(client, monkeypatch):
    """Verify that logs page handles default pure posix log path.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from pathlib import PurePosixPath

    from atlaso.app.adapters.system import AdapterResult

    monkeypatch.setattr("atlaso.app.ui.ATLASO_APP_LOG_PATH", PurePosixPath("/var/log/atlaso/atlaso.log"))
    monkeypatch.setattr("atlaso.app.ui.KMS_SERVER_LOG_PATH", PurePosixPath("/var/log/atlaso/kms/server.log"))
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_dnsmasq_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "dnsmasq", "logs"], dry_run=True, stdout="No host dnsmasq journal is read in development mode."
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ntpd_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ntpd", "logs"], dry_run=True, stdout="No host NTPsec journal is read in development mode."
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_ldap_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "ldap", "logs"], dry_run=True, stdout="No host LDAP journal is read in development mode."
        ),
    )
    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_nginx_logs",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "nginx", "logs"], dry_run=True, stdout="No host Nginx journal is read in development mode."
        ),
    )

    login(client)
    response = client.get("/logs")

    assert response.status_code == 200
    assert "VCFDT" not in response.text
    assert "Atlaso App" in response.text
    assert "DNS" in response.text
    assert "DHCP" in response.text
    assert "TFTP" in response.text
    assert "LDAP / LDAPS" in response.text
    assert "logs-audit-panel" not in response.text
    assert "NTPsec" in response.text
    assert "Nginx" in response.text
    assert "Log file has not been written yet." in response.text




def test_new_record_rows_lock_defaults_until_required_field(client):
    """Verify that new record rows lock defaults until required field.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200

    assert "function lockNewRecordColumns" in app_js.text
    assert "function markNewRecordRow" in app_js.text
    assert "newRecordRequiredCellEditable" in app_js.text
    firewall_block = app_js.text[
        app_js.text.index("function initializeFirewallRulesTable"):
        app_js.text.index("function managedFirewallStatusFormatter")
    ]
    assert 'field: "enabled"' in firewall_block
    assert 'editor: "tickCross"' not in firewall_block
    assert "initializeAtlasoResourceWizard({" in firewall_block
    assert "supportsInlineEnabled" in app_js.text
    configured_columns_block = app_js.text[
        app_js.text.index("const configuredColumns"):
        app_js.text.index("const options =", app_js.text.index("const configuredColumns"))
    ]
    assert 'editor: "tickCross"' not in configured_columns_block
    assert 'toggle.className = "inline-boolean-toggle"' in configured_columns_block
    assert "void saveInlineEnabled(cell, previousValue)" in configured_columns_block
    assert "cell.setValue(previousValue)" in app_js.text
    assert firewall_block.index('{ id: "state"') < firewall_block.index('{ id: "enablement"')
    assert firewall_block.index('{ id: "enablement"') < firewall_block.index('{ id: "review"')
    assert 'title: "Choose rule enablement"' in firewall_block
    assert ".new-record-row-pending" in app_css.text
    assert ".new-record-primary-cell" in app_css.text

    def function_block(name, next_name):
        """Return function block.

        Args:
            name: Stable name identifying the resource or operation.
            next_name: Next name supplied to the test scenario.
        """
        start = app_js.text.index(f"function {name}()")
        end = app_js.text.index(f"function {next_name}", start)
        return app_js.text[start:end]

    routes_wan_blocks = [
        ("initializeRoutesWanRoutesTable", "initializeRoutesWanPoliciesTable", "route"),
        ("initializeRoutesWanRoutingTable", "initializeRoutesWanNatTable", "routing"),
        ("initializeRoutesWanNatTable", "initializeRoutesWanRoutesTable", "nat"),
        ("initializeRoutesWanPoliciesTable", "showNetworkMessage", "policy"),
    ]
    for name, next_name, resource in routes_wan_blocks:
        block = function_block(name, next_name)
        assert "columns: lockNewRecordColumns([" not in block, name
        assert 'pattern: "wizard-backed"' in block, name
        assert f'openRoutesWanWizard("{resource}",' in block, name
        assert f'routesWanAddButton("{resource}",' in block, name

    ca_certificates_block = function_block("initializeCaCertificatesTable", "initializeFirewallRulesTable")
    assert "columns: lockNewRecordColumns([" not in ca_certificates_block
    assert "+ Add certificate here" in ca_certificates_block
    assert "initializeAtlasoResourceWizard({" in ca_certificates_block
    assert 'editor:' not in ca_certificates_block

    dns_block = app_js.text[
        app_js.text.index("function initializeDnsRecordsTableElement"):
        app_js.text.index("function initializeDhcpScopesTable")
    ]
    assert 'markNewRecordRow(row, "host_label")' in dns_block






def test_dns_ipv4_suggestion_falls_back_to_existing_a_record_network():
    """Verify that dns ipv4 suggestion falls back to existing a record network."""
    from atlaso.app.models import DhcpReservation, DhcpScope, DnsRecord
    from atlaso.app.ui import dhcp_scope_name_for_ip, dns_record_suggested_ipv4

    records = [
        DnsRecord(hostname="core.atlaso.internal", record_type="A", address="192.168.49.1", enabled=True),
        DnsRecord(hostname="used.atlaso.internal", record_type="A", address="192.168.49.2", enabled=True),
    ]

    assert dns_record_suggested_ipv4(records, "atlaso.internal", [], []) == "192.168.49.3"

    scopes = [
        DhcpScope(
            name="SiteA",
            site_address="192.168.50.1",
            prefix_length=24,
            range_expression="192.168.50.100-200",
            domain_name="atlaso.internal",
            enabled=True,
        )
    ]
    reservations = [
        DhcpReservation(
            hostname="reserved.atlaso.internal",
            mac_address="02:15:5d:00:20:10",
            ip_address="192.168.50.2",
        )
    ]

    assert dns_record_suggested_ipv4(records, "atlaso.internal", scopes, reservations) == "192.168.50.3"
    assert dhcp_scope_name_for_ip("192.168.50.140", scopes) == "SiteA"
    assert dhcp_scope_name_for_ip("192.168.1.140", scopes) == ""









def test_certificate_authority_page_renders(client):
    """Verify that certificate authority page renders.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re

    login(client)
    ca = client.get("/certificate-authority")
    assert ca.status_code == 200
    assert "Certificate Authority" in ca.text
    assert "Certificate Requests" in ca.text
    assert "Profiles" in ca.text
    assert "CSR Intake" in ca.text
    assert "ca-certificates-table" in ca.text
    assert "ca-profiles-table" in ca.text
    assert "+ Add certificate here" in client.get("/static/app.js").text
    assert 'id="ca-certificate-dialog"' in ca.text
    assert 'data-ca-certificate-form' in ca.text
    assert "Define the certificate request" in ca.text
    assert 'id="ca-csr-dialog"' in ca.text
    assert "data-ca-csr-form" in ca.text
    assert "data-ca-csr-open" in ca.text
    assert 'data-atlaso-wizard-step="csr"' in ca.text
    assert 'name="csr_text"' in ca.text
    assert "function initializeCaCsrWizard()" in client.get("/static/app.js").text
    certificate_wizard = ca.text.split('id="ca-certificate-dialog"', 1)[1].split("</dialog>", 1)[0]
    identity_step = certificate_wizard.split('data-atlaso-wizard-step="identity"', 1)[1].split("</section>", 1)[0]
    names_step = certificate_wizard.split('data-atlaso-wizard-step="names"', 1)[1].split("</section>", 1)[0]
    assert 'class="form-stack"' in identity_step
    assert 'class="form-grid"' not in identity_step
    assert 'class="form-stack"' in names_step
    assert 'class="form-grid"' not in names_step
    assert 'data-atlaso-wizard-step="enablement"' in certificate_wizard
    certificate_identity = certificate_wizard.split('data-atlaso-wizard-step="identity"', 1)[1].split("</section>", 1)[0]
    assert 'name="description"' in certificate_identity
    assert '<textarea name="description" rows="3" maxlength="1000">' in certificate_identity
    certificate_enablement = certificate_wizard.split('data-atlaso-wizard-step="enablement"', 1)[1].split("</section>", 1)[0]
    assert 'name="description"' not in certificate_enablement
    profile_wizard = ca.text.split('id="ca-profile-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert 'data-atlaso-wizard-step="enablement"' in profile_wizard
    profile_identity = profile_wizard.split('data-atlaso-wizard-step="identity"', 1)[1].split("</section>", 1)[0]
    assert 'name="description"' in profile_identity
    assert "Issued, CSR-based, and service-owned certificates are read-only." in ca.text
    assert "<th>Exports</th>" not in ca.text
    certificate_table_js = client.get("/static/app.js").text.split("function initializeCaCertificatesTable()", 1)[1].split("async function postKmsAction", 1)[0]
    assert 'editLabel: "Edit request"' in certificate_table_js
    assert 'label: "Copy fingerprint"' in certificate_table_js
    assert 'action: (_event, row) => copyCaCertificateFingerprint(row)' in certificate_table_js
    assert 'label: "Export",' in certificate_table_js
    assert "menu: [" in certificate_table_js
    assert 'label: "Certificate"' in certificate_table_js
    assert 'label: "Certificate chain"' in certificate_table_js
    assert 'label: "Private key"' in certificate_table_js
    app_js = client.get("/static/app.js").text
    assert 'window.location.assign(`/certificate-authority/certificates/${data.id}/downloads/${artifact}`)' in app_js
    assert 'managementUiPath(`/certificate-authority/certificates/${data.id}/downloads/${artifact}`)' not in app_js
    assert 'title: "Exports"' not in certificate_table_js
    assert re.search(r'title: "Status",\s+field: "status",\s+width: 100', certificate_table_js)
    assert 'formatter: (cell) => escapeHtml(cell.getValue() || "")' in certificate_table_js
    assert re.search(r'cssClass: "mono-text",\s+width: 480,', certificate_table_js)
    assert "value.slice(0, 12)" not in certificate_table_js
    assert "+ Add profile here" in client.get("/static/app.js").text
    assert "Atlaso Internal Root CA" in ca.text
    assert "VCF service TLS" in ca.text
    assert "core.atlaso.internal" in ca.text
    assert 'data-autosave-status-id="ca-settings-autosave-status"' in ca.text
    assert "Listen interfaces" in ca.text
    assert "Listen addresses" in ca.text
    assert "Portal hostname" in ca.text
    assert "ca.atlaso.internal" in ca.text
    assert "Open request portal" in ca.text
    assert 'href="https://ca.atlaso.internal/ui/public/ca/requests"' in ca.text
    assert 'name="listen_interfaces_present"' in ca.text
    assert 'name="listen_interfaces"' in ca.text
    assert 'data-derived-listen-addresses' in ca.text
    assert 'placeholder="Add interface..."' in ca.text
    assert 'placeholder="Add listen address..."' not in ca.text
    assert 'data-tag-option="eth2"' in ca.text
    assert "eth1 - unused / trunk" not in ca.text
    assert "Read-only addresses resolved" in ca.text
    assert 'data-ca-derived-address' not in ca.text
    assert 'name="listen_interface"' not in ca.text
    assert 'name="listen_address"' not in ca.text
    assert "Changes save automatically." in ca.text
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in ca.text
    assert "Review appliance changes" in ca.text
    assert "atlaso-ca.json" in ca.text
    assert 'class="validation-preview-source language-json"' in ca.text
    assert "data-confirm-modal" in ca.text
    assert '<strong>/etc/atlaso/ca</strong>' in ca.text
    assert "fixed-value-field" in ca.text
    assert 'name="storage_path"' not in ca.text
    assert '<input name="storage_path"' not in ca.text
    assert "Downloads" in ca.text
    assert "Download root CA" in ca.text
    assert "Download CA bundle" in ca.text
    assert "ca-download-details" in ca.text
    assert 'data-secret-mask="hidden">hidden</span>' in ca.text
    assert 'data-secret-toggle aria-label="Show secrets key source"' in ca.text
    assert 'href="/certificate-authority/downloads/root-ca.pem"' in ca.text
    assert 'href="/certificate-authority/downloads/ca-bundle.pem"' in ca.text
    assert 'href="/ui/management/certificate-authority/downloads/' not in ca.text
    assert not re.search(r'href="/ui/management/certificate-authority/certificates/[^"]+/downloads/', ca.text)


def test_certificate_request_creation_is_atomic_and_issues_submitted_sans(client):
    """Verify that certificate request creation is atomic and issues submitted sans.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaProfile, CaSettings

    login(client)
    page = client.get("/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.enabled = True
        profile = db.execute(select(CaProfile).where(CaProfile.name == "VCF service TLS")).scalar_one()
        profile_id = profile.id
        db.commit()

    submitted = client.post(
        "/certificate-authority/certificates",
        data={
            "csrf": csrf,
            "common_name": "atomic.atlaso.internal",
            "profile_id": str(profile_id),
            "subject_alt_names": "atomic.atlaso.internal\nalias.atlaso.internal",
            "ip_addresses": "192.168.50.25",
            "description": "Atomic certificate request",
            "enabled": "on",
            "status": "issued",
            "serial_number": "client-controlled",
        },
        follow_redirects=False,
    )

    assert submitted.status_code == 303
    with SessionLocal() as db:
        staged = db.execute(select(CaCertificate).where(CaCertificate.common_name == "atomic.atlaso.internal")).scalar_one()
        assert staged.status == "planned"
        assert staged.serial_number is None
        assert staged.profile_id == profile_id
        assert staged.subject_alt_names == "atomic.atlaso.internal\nalias.atlaso.internal"
        assert staged.ip_addresses == "192.168.50.25"
        assert staged.certificate_pem == ""

    issued_page = client.get("/certificate-authority")
    assert issued_page.status_code == 200
    with SessionLocal() as db:
        issued = db.execute(select(CaCertificate).where(CaCertificate.common_name == "atomic.atlaso.internal")).scalar_one()
        assert issued.status == "issued"
        parsed = x509.load_pem_x509_certificate(issued.certificate_pem.encode("utf-8"))
        assert parsed.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "atomic.atlaso.internal"
        sans = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert sans.get_values_for_type(x509.DNSName) == ["atomic.atlaso.internal", "alias.atlaso.internal"]
        assert [str(value) for value in sans.get_values_for_type(x509.IPAddress)] == ["192.168.50.25"]
        eku = parsed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_certificate_request_creation_validates_profile_and_sans(client):
    """Verify that certificate request creation validates profile and sans.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaProfile

    login(client)
    page = client.get("/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        profile = db.execute(select(CaProfile).where(CaProfile.name == "VCF service TLS")).scalar_one()
        profile_id = profile.id

    missing_profile = client.post(
        "/certificate-authority/certificates",
        data={"csrf": csrf, "common_name": "missing-profile.atlaso.internal", "profile_id": "", "enabled": "on"},
    )
    assert missing_profile.status_code == 422
    assert missing_profile.json()["detail"] == "Select an enabled CA profile."

    missing_san = client.post(
        "/certificate-authority/certificates",
        data={"csrf": csrf, "common_name": "missing-san.atlaso.internal", "profile_id": str(profile_id), "enabled": "on"},
    )
    assert missing_san.status_code == 422
    assert "requires at least one DNS name or IP SAN" in missing_san.json()["detail"]

    invalid_ip = client.post(
        "/certificate-authority/certificates",
        data={
            "csrf": csrf,
            "common_name": "invalid-ip.atlaso.internal",
            "profile_id": str(profile_id),
            "subject_alt_names": "invalid-ip.atlaso.internal",
            "ip_addresses": "999.1.1.1",
            "enabled": "on",
        },
    )
    assert invalid_ip.status_code == 422
    assert "invalid IP SAN 999.1.1.1" in invalid_ip.json()["detail"]

    with SessionLocal() as db:
        profile = db.get(CaProfile, profile_id)
        profile.enabled = False
        db.commit()
    disabled_profile = client.post(
        "/certificate-authority/certificates",
        data={
            "csrf": csrf,
            "common_name": "disabled-profile.atlaso.internal",
            "profile_id": str(profile_id),
            "subject_alt_names": "disabled-profile.atlaso.internal",
            "enabled": "on",
        },
    )
    assert disabled_profile.status_code == 422
    assert disabled_profile.json()["detail"] == "Select an enabled CA profile."

    with SessionLocal() as db:
        names = set(db.execute(select(CaCertificate.common_name)).scalars().all())
    assert "missing-profile.atlaso.internal" not in names
    assert "missing-san.atlaso.internal" not in names
    assert "invalid-ip.atlaso.internal" not in names
    assert "disabled-profile.atlaso.internal" not in names


def test_certificate_request_editing_enforces_immutable_and_managed_boundaries(client):
    """Verify that certificate request editing enforces immutable and managed boundaries.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaProfile

    login(client)
    page = client.get("/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        profile = db.execute(select(CaProfile).where(CaProfile.name == "VCF service TLS")).scalar_one()
        planned = CaCertificate(
            common_name="planned.atlaso.internal",
            profile_id=profile.id,
            subject_alt_names="planned.atlaso.internal",
            status="planned",
            serial_number="preserved",
            enabled=True,
        )
        issued = CaCertificate(
            common_name="issued-immutable.atlaso.internal",
            profile_id=profile.id,
            subject_alt_names="issued-immutable.atlaso.internal",
            status="issued",
            serial_number="10",
            certificate_pem="-----BEGIN CERTIFICATE-----\nimmutable\n-----END CERTIFICATE-----\n",
            fingerprint="original-fingerprint",
            enabled=True,
        )
        managed = CaCertificate(
            common_name="managed-immutable.atlaso.internal",
            profile_id=profile.id,
            subject_alt_names="managed-immutable.atlaso.internal",
            status="planned",
            managed_owner="test:https",
            enabled=True,
        )
        db.add_all([planned, issued, managed])
        db.commit()
        planned_id = planned.id
        issued_id = issued.id
        managed_id = managed.id
        profile_id = profile.id

    edited = client.post(
        f"/certificate-authority/certificates/{planned_id}/edit",
        data={
            "csrf": csrf,
            "common_name": "planned-updated.atlaso.internal",
            "profile_id": str(profile_id),
            "subject_alt_names": "planned-updated.atlaso.internal",
            "ip_addresses": "192.168.50.30",
            "description": "Updated before issue",
            "enabled": "on",
            "status": "issued",
            "serial_number": "overwritten",
        },
        follow_redirects=False,
    )
    assert edited.status_code == 303

    immutable = client.post(
        f"/certificate-authority/certificates/{issued_id}/edit",
        data={
            "csrf": csrf,
            "common_name": "changed.atlaso.internal",
            "profile_id": str(profile_id),
            "subject_alt_names": "changed.atlaso.internal",
            "enabled": "on",
        },
    )
    assert immutable.status_code == 409
    assert immutable.json()["detail"] == "Only unissued manual certificate requests can be edited."

    managed_delete = client.post(
        f"/certificate-authority/certificates/{managed_id}/delete",
        data={"csrf": csrf},
    )
    assert managed_delete.status_code == 409
    assert managed_delete.json()["detail"] == "Service-owned certificates must be managed from their owning service."

    with SessionLocal() as db:
        planned = db.get(CaCertificate, planned_id)
        issued = db.get(CaCertificate, issued_id)
        managed = db.get(CaCertificate, managed_id)
        assert planned.common_name == "planned-updated.atlaso.internal"
        assert planned.status == "planned"
        assert planned.serial_number == "preserved"
        assert planned.ip_addresses == "192.168.50.30"
        assert issued.common_name == "issued-immutable.atlaso.internal"
        assert issued.subject_alt_names == "issued-immutable.atlaso.internal"
        assert issued.fingerprint == "original-fingerprint"
        assert managed is not None


def test_certificate_authority_downloads_public_pems(client):
    """Verify that certificate authority downloads public pems.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    root = client.get("/certificate-authority/downloads/root-ca.pem")
    assert root.status_code == 200
    assert root.headers["content-disposition"] == 'attachment; filename="atlaso-root-ca.pem"'
    assert "BEGIN CERTIFICATE" in root.text
    assert "BEGIN PRIVATE KEY" not in root.text

    bundle = client.get("/certificate-authority/downloads/ca-bundle.pem")
    assert bundle.status_code == 200
    assert bundle.headers["content-disposition"] == 'attachment; filename="atlaso-ca-bundle.pem"'
    assert "BEGIN CERTIFICATE" in bundle.text


def test_public_ca_root_page_is_unauthenticated(client):
    """Verify that public ca root page is unauthenticated.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaSettings, PhysicalInterface

    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.management_https_enabled = True
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.enabled = True
        settings.root_certificate_pem = "-----BEGIN CERTIFICATE-----\npublic-root\n-----END CERTIFICATE-----\n"
        settings.root_fingerprint = "abc123"
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.87.32\nfd00:87::32"
        db.add(settings)
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.ip_cidr = "192.168.167.10/24"
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        eth2.ipv6_cidr = "fd00:87::32/64"
        db.commit()

    public_headers = {"host": "ca.atlaso.internal"}
    page = client.get("/ui/public/ca", headers=public_headers)
    assert page.status_code == 200
    assert "Atlaso Certificate Authority" in page.text
    assert "Photon appliance" in page.text
    assert 'class="brand" href="/ui/public"' in page.text
    assert "Atlaso Internal Root CA" in page.text
    assert "abc123" in page.text
    assert "ca-fingerprint-block" in page.text
    assert 'data-copy-value="abc123"' in page.text
    assert "Copy fingerprint" in page.text
    assert "ca.atlaso.internal" in page.text
    assert "/ca/downloads/root-ca.pem" in page.text
    assert 'href="/ui/public/ca/requests"' in page.text
    assert page.text.count('href="/ui/public/ca/requests"') == 1
    assert "public-link-panel" in page.text
    assert "Open request portal" not in page.text
    assert 'href="/ui/public/ca/login"' in page.text
    assert "Trust Material" not in page.text
    assert "Appliance Information" not in page.text
    assert "https://github.com/mdaneri/Atlaso" in page.text
    public_footer = page.text.split('<footer class="public-info-footnote"', 1)[1].split("</footer>", 1)[0]
    documentation_link = (
        'href="https://mdaneri.github.io/Atlaso/docs/" target="_blank" rel="noopener" '
        'title="Atlaso documentation"'
    )
    assert documentation_link in public_footer
    assert ">Documentation<" in public_footer
    assert public_footer.index("https://github.com/mdaneri/Atlaso") < public_footer.index(documentation_link)
    assert public_footer.index(documentation_link) < public_footer.index(">Swagger<")
    assert 'href="https://192.168.167.10/ui/management"' in page.text
    assert ">Management<" in page.text
    assert 'href="https://192.168.167.10/api/docs"' in page.text
    assert ">Swagger<" in page.text
    assert 'href="https://www.python.org/"' in page.text
    assert "Python " in page.text
    assert "/certificate-authority" not in page.text
    assert "/appliance-apply" not in page.text

    login_page = client.get("/ui/public/ca/login", headers=public_headers)
    assert login_page.status_code == 200
    assert "Sign in to user portal" in login_page.text
    assert "Use your Atlaso user account to continue." in login_page.text
    assert 'action="/ui/public/ca/login" method="post" target="_self"' in login_page.text
    assert 'name="next" value="/ui/public/ca"' in login_page.text
    assert 'data-history-back' in login_page.text
    assert ">Cancel<" in login_page.text
    assert 'class="public-portal-shell"' in login_page.text
    assert "https://github.com/mdaneri/Atlaso" in login_page.text
    assert 'href="https://192.168.167.10/api/docs"' in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    login_response = client.post(
        "/ui/public/ca/login",
        headers=public_headers,
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf, "next": "/ca"},
        follow_redirects=False,
    )
    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/ui/public/ca"

    signed_in_page = client.get("/ui/public/ca", headers=public_headers)
    assert signed_in_page.status_code == 200
    assert "Sign out" in signed_in_page.text
    assert 'name="next" value="/ui/public/ca"' in signed_in_page.text
    csrf = signed_in_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    logout_response = client.post(
        "/ui/public/ca/requests/logout",
        headers=public_headers,
        data={"csrf": csrf, "next": "/ui/public/ca"},
        follow_redirects=False,
    )
    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/ui/public/ca"

    ca_host_home = client.get("/", headers={"host": "ca.atlaso.internal"})
    assert ca_host_home.status_code == 200
    assert "Atlaso Public Services" in ca_host_home.text
    assert "Certificate Authority" in ca_host_home.text
    assert 'class="public-portal-shell"' in ca_host_home.text
    assert 'class="app-shell"' not in ca_host_home.text
    assert 'class="sidebar"' not in ca_host_home.text
    assert "/certificate-authority" not in ca_host_home.text

    ca_ip_home = client.get("/", headers={"host": "192.168.87.32"})
    assert ca_ip_home.status_code == 200
    assert "Atlaso Public Services" in ca_ip_home.text
    assert "Certificate Authority" in ca_ip_home.text
    assert "/ca/downloads/root-ca.pem" not in ca_ip_home.text
    assert "Appliance Information" not in ca_ip_home.text
    assert 'href="/ui/public/ca/login"' in ca_ip_home.text
    assert ">Login<" in ca_ip_home.text
    assert "https://github.com/mdaneri/Atlaso" in ca_ip_home.text
    assert 'href="https://192.168.167.10/ui/management"' in ca_ip_home.text
    assert ">Management<" in ca_ip_home.text
    assert 'href="https://192.168.167.10/api/docs"' in ca_ip_home.text
    assert ">Swagger<" in ca_ip_home.text
    assert 'href="https://www.python.org/"' in ca_ip_home.text
    assert 'href="/ui/public/ca/requests"' not in ca_ip_home.text
    assert "Request certificate" not in ca_ip_home.text
    assert ca_ip_home.text.index("https://github.com/mdaneri/Atlaso") > ca_ip_home.text.index('href="/ui/public/ca/login"')
    assert ca_ip_home.text.index("https://github.com/mdaneri/Atlaso") > ca_ip_home.text.index("Public Services")
    assert 'class="public-portal-shell"' in ca_ip_home.text
    assert 'class="app-shell"' not in ca_ip_home.text
    assert 'class="sidebar"' not in ca_ip_home.text
    assert "/certificate-authority" not in ca_ip_home.text

    ca_ipv6_home = client.get("/", headers={"host": "[fd00:87::32]"})
    assert ca_ipv6_home.status_code == 200
    assert "Atlaso Public Services" in ca_ipv6_home.text
    assert "Certificate Authority" in ca_ipv6_home.text
    assert "/certificate-authority" not in ca_ipv6_home.text

    management_ip_home = client.get("/", headers={"host": "192.168.167.10"}, follow_redirects=False)
    assert management_ip_home.status_code == 303
    assert management_ip_home.headers["location"] == "/ui/management"

    root = client.get("/ca/downloads/root-ca.pem")
    assert root.status_code == 200
    assert "public-root" in root.text
    assert "PRIVATE KEY" not in root.text


def test_public_services_reject_terminal_listener_without_valid_management_https_certificate(client):
    """Verify that public services reject terminal listener without valid management https certificate.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaCertificate, PhysicalInterface
    from atlaso.app.ui import public_services_context

    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.management_https_enabled = False
        appliance_settings.web_terminal_enabled = True
        appliance_settings.web_terminal_interfaces_json = '["eth0", "eth2"]'
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.ip_cidr = "192.168.167.10/24"
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.admin_state = "up"
        eth2.oper_state = "up"
        eth2.ip_cidr = "192.168.87.32/24"
        for certificate in db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")
        ).scalars():
            db.delete(certificate)
        db.commit()

        context = public_services_context(db, reconcile=False)

    assert context["public_service_validation_errors"] == [
        "Web terminal public listeners require valid Management HTTPS and an issued appliance HTTPS certificate. Apply Certificate Authority and Appliance Settings first."
    ]
    assert "Terminal-only HTTPS front door" not in context["public_service_config_preview"]
    assert not any(entry.get("web_terminal") for entry in context["public_service_entries"])


def test_public_services_rejects_authenticated_depot_with_disabled_http_user(client):
    """Verify that public services rejects authenticated depot with disabled http user.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User, VcfOfflineDepotSettings
    from atlaso.app.ui import public_services_context

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        depot_user = db.execute(select(User).where(User.username == "vcf-depot")).scalar_one()
        settings.enabled = True
        settings.allow_unauthenticated_access = False
        settings.http_user_id = depot_user.id
        depot_user.enabled = False
        db.commit()

        context = public_services_context(db, reconcile=False)

    assert (
        "Public Services cannot publish VCF Offline Depot while HTTP user vcf-depot is disabled. "
        "Enable the user and apply Local Users first."
    ) in context["public_service_validation_errors"]


def test_public_service_home_is_scoped_to_called_ip(client, tmp_path, monkeypatch):
    """Verify that public service home is scoped to called ip.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        CaCertificate,
        CaSettings,
        PhysicalInterface,
        Setting,
        User,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )

    depot_store = tmp_path / "depot"
    prod_root = depot_store / "PROD"
    component_dir = prod_root / "COMP"
    component_dir.mkdir(parents=True)
    (component_dir / "manifest.json").write_text('{"depot": true}\n', encoding="utf-8")

    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.management_https_enabled = True
        appliance_settings.web_terminal_enabled = True
        appliance_settings.web_terminal_interfaces_json = '["eth0", "eth2"]'
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.ip_cidr = "192.168.167.10/24"
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        eth3 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth3")).scalar_one_or_none()
        if eth3 is None:
            eth3 = PhysicalInterface(name="eth3", mac_address="00:15:5d:00:00:33", role="access", mode="access", ip_cidr="192.168.88.32/24")
            db.add(eth3)
        else:
            eth3.role = "access"
            eth3.mode = "access"
            eth3.ip_cidr = "192.168.88.32/24"

        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        ca_settings.root_certificate_pem = "-----BEGIN CERTIFICATE-----\npublic-root\n-----END CERTIFICATE-----\n"
        ca_settings.listen_interface = "eth2"
        ca_settings.listen_address = "192.168.87.32"
        db.add(
            CaCertificate(
                common_name="core.atlaso.internal",
                status="issued",
                certificate_pem="-----BEGIN CERTIFICATE-----\nterminal-leaf\n-----END CERTIFICATE-----\n",
                private_key_encrypted="fernet:v1:test",
                managed_owner="appliance:https",
                cert_path="/etc/atlaso/https/certs/core.atlaso.internal.crt",
                key_path="/etc/atlaso/https/certs/core.atlaso.internal.key",
                chain_path="/etc/atlaso/https/certs/core.atlaso.internal-chain.pem",
            )
        )

        depot_settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        depot_settings.enabled = True
        depot_settings.listen_interface = "eth2"
        depot_settings.listen_address = "192.168.87.32"
        depot_settings.port = 8443
        depot_settings.depot_store_path = str(depot_store)
        depot_settings.http_user = db.execute(select(User).where(User.username == "vcf-depot")).scalar_one()
        depot_settings.http_user.enabled = True

        registry_settings = db.execute(select(VcfPrivateRegistrySettings)).scalar_one()
        registry_settings.enabled = True
        registry_settings.hostname = "registry.atlaso.internal"
        registry_settings.listen_interface = "eth3"
        registry_settings.listen_address = "192.168.88.32"
        registry_settings.port = 9443

        for key, value in {
            "esxi_pxe.boot.enabled": "true",
            "esxi_pxe.boot.hostname": "esxi-pxe.atlaso.internal",
            "esxi_pxe.boot.listen_interface": "eth2",
            "esxi_pxe.boot.listen_address": "192.168.87.32",
            "esxi_pxe.boot.http_port": "8081",
        }.items():
            row = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
            if row is None:
                row = Setting(key=key, value=value)
            else:
                row.value = value
            db.add(row)
        db.commit()

    page = client.get("/", headers={"host": "192.168.87.32"})
    assert page.status_code == 200
    assert "Atlaso Public Services" in page.text
    assert "Certificate Authority" in page.text
    assert "VCF Offline Depot" in page.text
    assert "ESXi PXE" in page.text
    assert "Web Terminal" in page.text
    assert "Administrative appliance shell" in page.text
    assert "ca.atlaso.internal" in page.text
    assert "depot.atlaso.internal" in page.text
    assert "esxi-pxe.atlaso.internal" in page.text
    assert 'data-public-address-mode-toggle' in page.text
    assert 'data-public-address-mode-option="name" aria-pressed="true"' in page.text
    assert 'data-public-address-mode-option="ip" aria-pressed="false"' in page.text
    assert 'href="https://ca.atlaso.internal/ui/public/ca"' in page.text
    assert 'data-ip-href="https://192.168.87.32/ui/public/ca"' in page.text
    assert 'href="https://depot.atlaso.internal:8443/PROD/"' in page.text
    assert 'data-ip-href="https://192.168.87.32:8443/PROD/"' in page.text
    assert 'href="http://esxi-pxe.atlaso.internal:8081/pxe/esxi/"' in page.text
    assert 'data-ip-href="http://192.168.87.32:8081/pxe/esxi/"' in page.text
    assert 'href="https://192.168.87.32/ui/public/terminal"' in page.text
    assert 'data-ip-href="https://192.168.87.32/ui/public/terminal"' in page.text
    assert "Appliance Information" not in page.text
    assert 'href="/ui/public/ca/login"' in page.text
    assert ">Login<" in page.text
    assert "https://github.com/mdaneri/Atlaso" in page.text
    assert ">Management<" in page.text
    assert 'href="https://192.168.167.10/api/docs"' in page.text
    assert ">Swagger<" in page.text
    assert ">Open<" not in page.text
    assert 'href="/ui/public/ca/requests"' not in page.text
    assert "Request certificate" not in page.text
    assert 'class="public-portal-shell"' in page.text
    assert 'class="app-shell"' not in page.text
    assert 'class="sidebar"' not in page.text
    assert "VCF Private Registry" not in page.text
    assert "/registry" not in page.text

    ca_direct = client.get("/ca", headers={"host": "192.168.87.32"})
    assert ca_direct.status_code == 200
    assert "Atlaso Certificate Authority" in ca_direct.text
    assert 'class="public-portal-shell"' in ca_direct.text

    requests_direct = client.get("/requests", headers={"host": "192.168.87.32"})
    assert requests_direct.status_code == 200
    assert "Sign in to user portal" in requests_direct.text
    assert 'action="/ui/public/ca/requests/login" method="post" target="_self"' in requests_direct.text

    management_ip_home = client.get("/", headers={"host": "192.168.167.10"}, follow_redirects=False)
    assert management_ip_home.status_code == 303
    assert management_ip_home.headers["location"] == "/ui/management"

    login(client)
    apply_page = client.get("/appliance-apply")
    assert apply_page.status_code == 200
    review = client.get("/appliance-apply/review")
    public_services_unit = next(unit for unit in review.json()["units"] if unit["id"] == "public_services")
    assert "listen 192.168.87.32:8081;" in public_services_unit["config_preview"]
    assert "return 301 /pxe/esxi/;" in public_services_unit["config_preview"]
    client.cookies.clear()

    depot_redirect = client.get("/PROD/", headers={"host": "192.168.87.32"}, follow_redirects=False)
    assert depot_redirect.status_code == 303
    assert depot_redirect.headers["location"] == "/PROD/login?next=/PROD/"

    depot_login = client.get(depot_redirect.headers["location"], headers={"host": "192.168.87.32"})
    assert depot_login.status_code == 200
    assert "Sign in to user portal" in depot_login.text
    assert "Use your Atlaso user account to continue." in depot_login.text
    assert ">Cancel<" in depot_login.text
    assert 'action="/PROD/login" method="post" target="_self"' in depot_login.text
    assert 'name="next" value="/PROD/"' in depot_login.text

    from atlaso.app.adapters.system import AdapterResult

    authentication_calls: list[str] = []

    class DepotAuthenticationAdapter:
        """Represent depot authentication adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        def authenticate_local_user(self, username: str, password: str) -> AdapterResult:
            """Return authenticate local user.

            Args:
                username: Account name used for authentication or lookup.
                password: Password supplied for the immediate authenticated operation.
            """
            authentication_calls.append(username)
            return AdapterResult(
                command=["atlaso-helper", "local-users", "authenticate", username],
                dry_run=False,
                returncode=0 if username == "vcf-depot" and password == "Depot-user1!" else 1,
            )

    monkeypatch.setattr("atlaso.app.ui.SystemAdapter", DepotAuthenticationAdapter)
    depot_csrf = depot_login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    depot_signed_in = client.post(
        "/PROD/login",
        headers={"host": "192.168.87.32"},
        data={
            "username": "vcf-depot",
            "password": "Depot-user1!",
            "csrf": depot_csrf,
            "next": "/PROD/COMP/?view=compact",
        },
        follow_redirects=False,
    )
    assert depot_signed_in.status_code == 303
    assert depot_signed_in.headers["location"] == "/PROD/COMP/?view=compact"
    assert authentication_calls == ["vcf-depot"]
    assert client.get("/PROD/auth-check", headers={"host": "192.168.87.32"}).status_code == 204
    client.cookies.clear()

    unsafe_login = client.get("/PROD/login", headers={"host": "192.168.87.32"})
    unsafe_csrf = unsafe_login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    unsafe_signed_in = client.post(
        "/PROD/login",
        headers={"host": "192.168.87.32"},
        data={
            "username": "vcf-depot",
            "password": "Depot-user1!",
            "csrf": unsafe_csrf,
            "next": "/PROD/..\\..\\malicious.example",
        },
        follow_redirects=False,
    )
    assert unsafe_signed_in.status_code == 303
    assert unsafe_signed_in.headers["location"] == "/PROD/"
    client.cookies.clear()

    wrong_login = client.get("/PROD/login", headers={"host": "192.168.87.32"})
    wrong_csrf = wrong_login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    rejected = client.post(
        "/PROD/login",
        headers={"host": "192.168.87.32"},
        data={"username": "vcf-depot", "password": "wrong-password", "csrf": wrong_csrf, "next": "https://example.test/"},
    )
    assert rejected.status_code == 401
    assert "Invalid username or password" in rejected.text
    assert "wrong-password" not in rejected.text

    client.cookies.clear()
    admin_login = client.get("/PROD/login", headers={"host": "192.168.87.32"})
    admin_csrf = admin_login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    admin_signed_in = client.post(
        "/PROD/login",
        headers={"host": "192.168.87.32"},
        data={"username": "admin", "password": "atlaso-admin", "csrf": admin_csrf, "next": "/PROD/"},
        follow_redirects=False,
    )
    assert admin_signed_in.status_code == 303
    client.cookies.clear()

    assert client.get("/PROD/login", headers={"host": "192.168.167.10"}).status_code == 404

    depot_auth_check = client.get("/PROD/auth-check", headers={"host": "192.168.87.32"})
    assert depot_auth_check.status_code == 401

    cli_auth_failure = client.get(
        "/PROD/auth-failure",
        headers={"host": "192.168.87.32", "accept": "application/octet-stream", "X-Original-URI": "/PROD/COMP/manifest.json"},
        follow_redirects=False,
    )
    assert cli_auth_failure.status_code == 401
    assert cli_auth_failure.headers["www-authenticate"] == 'Basic realm="VCF Offline Depot"'
    cli_head_auth_failure = client.head(
        "/PROD/auth-failure",
        headers={"host": "192.168.87.32", "accept": "*/*", "X-Original-URI": "/PROD/"},
        follow_redirects=False,
    )
    assert cli_head_auth_failure.status_code == 401
    assert cli_head_auth_failure.headers["www-authenticate"] == 'Basic realm="VCF Offline Depot"'
    browser_auth_failure = client.get(
        "/PROD/auth-failure",
        headers={"host": "192.168.87.32", "accept": "text/html", "X-Original-URI": "/PROD/COMP/"},
        follow_redirects=False,
    )
    assert browser_auth_failure.status_code == 303
    assert browser_auth_failure.headers["location"] == "/PROD/login?next=/PROD/COMP/"

    login(client)
    signed_in_depot_auth_check = client.get("/PROD/auth-check", headers={"host": "192.168.87.32"})
    assert signed_in_depot_auth_check.status_code == 204

    unrelated_depot_auth_check = client.get("/PROD/auth-check", headers={"host": "192.168.88.32"})
    assert unrelated_depot_auth_check.status_code == 401

    client.cookies.clear()
    basic_depot_browser = client.get(
        "/PROD/",
        headers={"host": "192.168.87.32", "X-Atlaso-Depot-Basic-User": "vcf-depot"},
        follow_redirects=False,
    )
    assert basic_depot_browser.status_code == 200
    assert "VCF Offline Depot" in basic_depot_browser.text
    basic_depot_head = client.head(
        "/PROD/",
        headers={"host": "192.168.87.32", "X-Atlaso-Depot-Basic-User": "vcf-depot"},
        follow_redirects=False,
    )
    assert basic_depot_head.status_code == 200
    assert basic_depot_head.content == b""

    with SessionLocal() as db:
        depot_settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        depot_settings.allow_unauthenticated_access = True
        db.commit()

    depot_browser = client.get("/PROD/", headers={"host": "192.168.87.32"}, follow_redirects=False)
    assert depot_browser.status_code == 200
    assert "VCF Offline Depot" in depot_browser.text
    assert "Index of /PROD/" not in depot_browser.text
    assert 'class="public-portal-shell"' in depot_browser.text
    assert 'id="depot-browser-table"' in depot_browser.text
    assert 'data-fallback-id="depot-browser-fallback"' in depot_browser.text
    assert 'href="/PROD/COMP/"' in depot_browser.text

    depot_subdir = client.get("/PROD/COMP/", headers={"host": "192.168.87.32"})
    assert depot_subdir.status_code == 200
    assert 'href="/PROD/COMP/manifest.json"' in depot_subdir.text
    assert ">Up one level</a>" in depot_subdir.text

    depot_file = client.get("/PROD/COMP/manifest.json", headers={"host": "192.168.87.32"})
    assert depot_file.status_code == 404

    unrelated_depot = client.get("/PROD/", headers={"host": "192.168.88.32"})
    assert unrelated_depot.status_code == 404

    unrelated_ca = client.get("/ca", headers={"host": "192.168.88.32"})
    assert unrelated_ca.status_code == 404
    unrelated_requests = client.get("/requests", headers={"host": "192.168.88.32"})
    assert unrelated_requests.status_code == 404

    registry_page = client.get("/", headers={"host": "192.168.88.32"})
    assert registry_page.status_code == 200
    assert "VCF Private Registry" in registry_page.text
    assert 'href="https://registry.atlaso.internal:9443"' in registry_page.text
    assert "Certificate Authority" not in registry_page.text
    assert "VCF Offline Depot" not in registry_page.text
    assert "Web Terminal" not in registry_page.text


def test_safe_depot_login_next_requires_canonical_depot_path():
    """Verify that depot login returns only to canonical depot paths."""
    from atlaso.app.ui import safe_depot_login_next

    assert safe_depot_login_next("/PROD") == "/PROD"
    assert safe_depot_login_next("/PROD/COMP/ESX_HOST/?view=compact") == "/PROD/COMP/ESX_HOST/?view=compact"
    for unsafe_target in (
        "https://malicious.example/",
        "//malicious.example/",
        "/PROD/..\\..\\malicious.example",
        "/PROD/../ui/management",
        "/PROD/%252e%252e/%252f%252fmalicious.example",
        "/PROD//malicious.example",
        "/PROD/COMP/#fragment",
        "/PROD/COMP/\r\nLocation: https://malicious.example/",
    ):
        assert safe_depot_login_next(unsafe_target) == "/PROD/"


def test_public_service_home_empty_state_for_non_management_ip(client):
    """Verify that public service home empty state for non management ip.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.mode = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        db.commit()

    page = client.get("/", headers={"host": "192.168.87.32"})
    assert page.status_code == 200
    assert "No public services on this interface" in page.text
    assert 'class="public-portal-shell"' in page.text
    assert 'class="app-shell"' not in page.text
    assert ">Login<" not in page.text


def test_certificate_operator_uses_request_page_without_console_access(client):
    """Verify that certificate operator uses request page without console access.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        CaCertificate,
        CaSettings,
        PhysicalInterface,
        Role,
        User,
        utcnow,
    )
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.management_https_enabled = True
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        ca_settings.listen_interface = "eth2"
        ca_settings.listen_address = "192.168.87.32"
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.ip_cidr = "192.168.167.10/24"
        eth2 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2.role = "access"
        eth2.ip_cidr = "192.168.87.32/24"
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.CERTIFICATE_OPERATOR.value
        admin.roles_json = roles_to_json([Role.CERTIFICATE_OPERATOR.value])
        db.add(
            CaCertificate(
                common_name="issued.atlaso.internal",
                status="issued",
                serial_number="10",
                certificate_pem="-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
                enabled=True,
                issued_at=utcnow(),
            )
        )
        db.commit()

    public_headers = {"host": "ca.atlaso.internal"}
    login_page = client.get("/ui/public/ca/requests", headers=public_headers)
    assert login_page.status_code == 200
    assert "Certificate Request Portal" in login_page.text
    assert "Sign in to user portal" in login_page.text
    assert "Use your Atlaso user account to continue." in login_page.text
    assert "Sign in to the appliance" not in login_page.text
    assert 'action="/ui/public/ca/requests/login" method="post" target="_self"' in login_page.text
    assert 'action="/ui/management/login"' not in login_page.text
    assert 'name="next" value="/ui/public/ca/requests"' in login_page.text
    assert 'data-history-back' in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    login_response = client.post(
        "/ui/public/ca/requests/login",
        headers=public_headers,
        data={
            "username": "admin",
            "password": "atlaso-admin",
            "csrf": csrf,
            "next": "/ui/public/ca/requests",
        },
        follow_redirects=False,
    )
    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/ui/public/ca/requests"

    console = client.get("/certificate-authority")
    assert console.status_code == 403

    page = client.get("/ca/requests")
    assert page.status_code == 200
    assert "Certificate Requests" in page.text
    assert "Submit Request" in page.text
    assert "CA Settings" not in page.text
    assert "atlaso-ca.json" not in page.text
    assert "/certificate-authority" not in page.text
    assert 'id="ca-requests-table"' in page.text
    assert 'data-fallback-id="ca-requests-fallback"' in page.text
    assert 'data-revoke-url-template="/ui/management/ca/certificates/__id__/revoke"' in page.text
    request_rows = json.loads(
        page.text.split('id="ca-requests-table"', 1)[1].split("data-rows='", 1)[1].split("'", 1)[0]
    )
    assert set(request_rows[0]) == {
        "id",
        "common_name",
        "profile_name",
        "status",
        "serial_number",
        "revoked_at",
        "can_revoke",
    }
    issued_request_row = next(row for row in request_rows if row["common_name"] == "issued.atlaso.internal")
    assert issued_request_row["can_revoke"] is True
    assert "certificate_pem" not in page.text
    with SessionLocal() as db:
        issued = db.execute(select(CaCertificate).where(CaCertificate.common_name == "issued.atlaso.internal")).scalar_one()
        certificate_id = issued.id
    portal_page = client.get("/ui/public/ca/requests", headers=public_headers)
    assert portal_page.status_code == 200
    assert "Certificate Request Portal" in portal_page.text
    assert 'class="brand" href="/ui/public"' in portal_page.text
    assert 'action="/ui/public/ca/requests"' in portal_page.text
    assert 'action="/ui/public/ca/requests/logout"' in portal_page.text
    assert 'data-history-back' in portal_page.text
    assert 'name="next" value="/ui/public/ca/requests"' in portal_page.text
    assert f'action="/ui/public/ca/requests/certificates/{certificate_id}/revoke"' in portal_page.text
    assert 'id="ca-requests-table"' in portal_page.text
    assert 'data-fallback-id="ca-requests-fallback"' in portal_page.text
    assert 'data-revoke-url-template="/ui/public/ca/requests/certificates/__id__/revoke"' in portal_page.text
    public_request_rows = json.loads(
        portal_page.text.split('id="ca-requests-table"', 1)[1].split("data-rows='", 1)[1].split("'", 1)[0]
    )
    assert public_request_rows == request_rows
    request_grid_js = client.get("/static/app.js").text.split("function initializeCaRequestsTable()", 1)[0]
    assert 'label: "Revoke certificate"' in request_grid_js
    assert 'confirmLabel: "Revoke certificate"' not in request_grid_js
    assert "row?.getElement?.()?.focus();" in request_grid_js
    assert 'class="app-shell"' not in portal_page.text
    assert 'class="sidebar"' not in portal_page.text
    assert "Unprivileged control plane" not in portal_page.text
    assert "/certificate-authority" not in portal_page.text
    csrf = portal_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    submitted = client.post(
        "/ui/public/ca/requests",
        headers=public_headers,
        data={
            "csrf": csrf,
            "common_name": "operator-request.atlaso.internal",
            "subject_alt_names": "operator-request.atlaso.internal",
            "description": "operator request",
        },
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    assert submitted.headers["location"] == "/ui/public/ca/requests"

    with SessionLocal() as db:
        request_row = db.execute(select(CaCertificate).where(CaCertificate.common_name == "operator-request.atlaso.internal")).scalar_one()
        assert request_row.status == "planned"

    revoked = client.post(
        f"/ui/public/ca/requests/certificates/{certificate_id}/revoke",
        headers=public_headers,
        data={"csrf": csrf, "reason": "rotation"},
        follow_redirects=False,
    )
    assert revoked.status_code == 303
    assert revoked.headers["location"] == "/ui/public/ca/requests"
    with SessionLocal() as db:
        issued = db.get(CaCertificate, certificate_id)
        assert issued.status == "revoked"
        assert issued.revoked_by == "admin"
        assert issued.revocation_reason == "rotation"


def test_ca_apply_payload_leaves_csr_private_key_empty():
    """Verify that ca apply payload leaves csr private key empty."""
    import json

    from atlaso.app.models import CaCertificate, CaSettings
    from atlaso.app.services.ca import render_ca_apply_payload

    settings = CaSettings(
        enabled=True,
        root_common_name="Atlaso Test Root CA",
        root_certificate_pem="-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n",
        storage_path="/etc/atlaso/ca",
    )
    certificate = CaCertificate(
        common_name="client-a.atlaso.internal",
        status="issued",
        certificate_pem="-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
        chain_pem="-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
        csr_text="-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----\n",
        cert_path="/etc/atlaso/ca/client-a.crt",
        key_path="",
        chain_path="/etc/atlaso/ca/client-a-chain.pem",
        enabled=True,
    )

    payload = json.loads(render_ca_apply_payload(settings, [certificate], include_private_keys=True))

    assert payload["certificates"][0]["managed_owner"] == ""
    assert payload["certificates"][0]["private_key_pem"] == ""


def test_certificate_authority_issues_encrypted_managed_certs_and_exports(client):
    """Verify that certificate authority issues encrypted managed certs and exports.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaSettings

    with SessionLocal() as db:
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.enabled = True
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.50.1"
        db.commit()

    login(client)
    page = client.get("/certificate-authority")
    assert page.status_code == 200
    assert "Managed certs" in page.text
    assert "appliance:https" in page.text
    assert "Private key" in page.text
    assert "BEGIN PRIVATE KEY" not in page.text

    with SessionLocal() as db:
        settings = db.execute(select(CaSettings)).scalar_one()
        managed = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https")).scalar_one()
        assert settings.root_certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert settings.root_private_key_encrypted.startswith("fernet:v1:")
        assert "BEGIN PRIVATE KEY" not in settings.root_private_key_encrypted
        assert managed.status == "issued"
        assert managed.private_key_encrypted.startswith("fernet:v1:")
        assert managed.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        certificate_id = managed.id

    cert = client.get(f"/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem")
    assert cert.status_code == 200
    assert "BEGIN CERTIFICATE" in cert.text
    assert "BEGIN PRIVATE KEY" not in cert.text

    key = client.get(f"/certificate-authority/certificates/{certificate_id}/downloads/private-key.pem")
    assert key.status_code == 200
    assert "BEGIN PRIVATE KEY" in key.text


def test_vsphere_key_provider_page_uses_shared_management_contract(client):
    """Verify the provider-management page and shared UI contract.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ui/management/vsphere-key-providers")
    assert page.status_code == 200
    assert "vSphere Key Providers" in page.text
    assert "bounded candidate VCF 9.1 profile" in page.text
    assert "vsphere-providers-table" in page.text
    assert "vsphere-vcenters-table" in page.text
    assert "vsphere-certificates-table" in page.text
    assert "vsphere-health-table" in page.text
    assert "Providers" in page.text
    assert "Trusted vCenters" in page.text
    assert "Certificates" in page.text
    assert "/ui/management/vsphere-key-providers/server-certificate.pem" not in page.text
    assert "Health &amp; lifecycle" in page.text
    assert "Listen interfaces" in page.text
    assert "Listen addresses" in page.text
    assert "Internal CA + imported public certificates" in page.text
    assert "Exact fingerprint to provider UUID" in page.text
    assert 'id="vsphere-provider-dialog"' in page.text
    assert 'id="vsphere-vcenter-dialog"' in page.text
    assert 'id="vsphere-certificate-dialog"' in page.text
    assert "PRIVATE KEY" not in page.text
    assert "Managed Keys" not in page.text
    assert "Create KMS key" not in page.text
    assert "data-confirm-modal" in page.text
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in page.text

    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "initializeVsphereKeyProviderTables" in app_js.text
    assert "window.AtlasoUiPatterns.createGrid" in app_js.text
    assert "window.AtlasoUiPatterns.createWizard" in app_js.text
    assert "+ Add provider here" in app_js.text
    assert "+ Add trusted vCenter here" in app_js.text
    assert "upsertOption(vcenterProviderSelect" in app_js.text
    assert "removeOption(vcenterProviderSelect" in app_js.text
    assert "onSaved: ({ resource }) => upsertOption(" in app_js.text
    assert "certificateTargetSelect," in app_js.text
    assert "removeOption(certificateTargetSelect" in app_js.text
    assert "updateCertificateCounts" in app_js.text
    assert "await updateCertificateCounts(providerId, vcenterId, 1" in app_js.text
    assert "await updateCertificateCounts(data.provider_id, data.trusted_vcenter_id, -1" in app_js.text
    certificate_actions = app_js.text.split("const certificateForm =", 1)[1].split(
        'const healthElement = document.getElementById("vsphere-health-table")', 1
    )[0]
    assert certificate_actions.count("await refreshNetworkSideStack();") == 2


def test_vsphere_key_provider_browser_routes_enforce_kms_scopes(client):
    """Verify browser reads and mutations enforce the renamed KMS scope boundary.

    Args:
        client: HTTP test client used to exercise browser authorization.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    page = client.get("/ui/management/vsphere-key-providers")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    denied_write = client.post(
        "/ui/management/vsphere-key-providers/settings",
        data={"hostname": "kms.atlaso.internal", "port": "5696", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert denied_write.status_code == 403
    assert "Missing required scope: write:kms" in denied_write.text

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.NETWORK_ADMIN.value
        admin.roles_json = roles_to_json([Role.NETWORK_ADMIN.value])
        db.commit()

    denied_read = client.get("/ui/management/vsphere-key-providers")
    assert denied_read.status_code == 403
    assert "Missing required scope: read:kms" in denied_read.text


def test_root_aware_initializers_do_not_receive_dom_content_loaded_event():
    """Verify that root aware initializers do not receive dom content loaded event."""
    source = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    initializers = (
        "initializeCaSettings",
        "initializeKmsSettings",
        "initializeNtpSettings",
        "initializeOidcProviderSettings",
        "initializeSwitchFields",
        "initializeAutosaveForms",
        "initializeFirewallSettings",
        "initializeDnsSettings",
        "initializeVcfBackupSettings",
        "initializeVcfRegistrySettings",
        "initializeVcfDepotSettings",
        "initializeTagEditors",
        "initializeServiceBindEditors",
    )

    for initializer in initializers:
        assert (
            f'document.addEventListener("DOMContentLoaded", () => {initializer}());'
            in source
        )
        assert (
            f'document.addEventListener("DOMContentLoaded", {initializer});'
            not in source
        )


def test_kms_settings_autosave_returns_json(client):
    """Verify that kms settings autosave returns json.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    page = client.get("/vsphere-key-providers")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vsphere-key-providers/settings",
        data={
            "enabled": "on",
            "backend": "atlaso-kmip",
            "listen_interface": "eth2",
            "listen_address": "10.0.0.99",
            "port": "5696",
            "hostname": "kms.atlaso.internal",
            "server_certificate": "rogue-kms.atlaso.internal",
            "ca_certificate_path": "/tmp/rogue-client-ca.crt",
            "database_path": "/tmp/rogue-kms.db",
            "config_path": "/tmp/rogue-kms.conf",
            "require_client_cert": "on",
            "allow_register": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["listen_address"] == "192.168.50.1"
    assert payload["listen_addresses"] == ["192.168.50.1"]
    assert payload["server_certificate"] == "kms.atlaso.internal"
    assert "KMS requires Certificate Authority to be enabled before activation." in payload["validation_errors"]
    refreshed = client.get("/vsphere-key-providers")
    assert "enabled" in refreshed.text
    assert "/tmp/rogue-kms.db" not in refreshed.text
    assert "/tmp/rogue-kms.conf" not in refreshed.text
    assert "/tmp/rogue-client-ca.crt" not in refreshed.text
    assert "/etc/atlaso/kmip/client-trust.pem" in refreshed.text
    assert "/var/lib/atlaso/kmip/store.db" in refreshed.text
    assert "/etc/atlaso/kmip/server.json" in refreshed.text
    assert "10.0.0.99" not in refreshed.text

    with SessionLocal() as db:
        record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms.atlaso.internal", DnsRecord.record_type == "CNAME")).scalar_one()
        assert record.address == "kms-192-168-50-1.atlaso.internal"
        interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms-192-168-50-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert interface_record.address == "192.168.50.1"
        assert "KMS/KMIP endpoint" in (interface_record.description or "")


def test_kms_settings_accept_multiple_listen_targets(client):
    """Verify that kms settings accept multiple listen targets.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/vsphere-key-providers")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vsphere-key-providers/settings",
        data={
            "enabled": "on",
            "backend": "atlaso-kmip",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2", "eth0"],
            "listen_addresses": ["192.168.50.1", "192.168.49.1"],
            "port": "5696",
            "hostname": "kms.atlaso.internal",
            "server_certificate": "kms.atlaso.internal",
            "require_client_cert": "on",
            "allow_register": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["listen_interfaces"] == ["eth2"]
    assert payload["listen_addresses"] == ["192.168.50.1"]
    config_preview = json.loads(payload["config_preview"])
    assert config_preview["listen"] == {"addresses": ["192.168.50.1"], "port": 5696}
    assert config_preview["schema_version"] == 1


def test_vsphere_provider_enable_creates_only_shared_server_identity(client):
    """Verify provider enablement never generates a vCenter client private key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaSettings

    login(client)
    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        db.commit()

    page = client.get("/vsphere-key-providers")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vsphere-key-providers/settings",
        data={
            "enabled": "on",
            "backend": "atlaso-kmip",
            "listen_interface": "eth2",
            "port": "5696",
            "hostname": "kms.atlaso.internal",
            "server_certificate": "kms.atlaso.internal",
            "require_client_cert": "on",
            "allow_register": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert any("public client certificate" in error for error in response.json()["validation_errors"])

    with SessionLocal() as db:
        server_cert = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "kms:server")).scalar_one()
        assert server_cert.status == "issued"
        assert server_cert.ip_addresses == "192.168.50.1"
        assert server_cert.cert_path == "/etc/atlaso/kmip/certs/kms.atlaso.internal.crt"
        client_certificates = db.execute(
            select(CaCertificate).where(CaCertificate.managed_owner.like("kms:client:%"))
        ).scalars().all()
        assert client_certificates == []

    download = client.get("/vsphere-key-providers/server-certificate.pem")
    assert download.status_code == 200
    assert download.text.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in download.text
    assert download.headers["cache-control"] == "no-store"
    assert "atlaso-kmip-server-chain.pem" in download.headers["content-disposition"]


def test_kms_apply_task_captures_current_desired_state(client):
    """Verify that kms apply task captures current desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/vsphere-key-providers")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    disabled = client.post(
        "/vsphere-key-providers/settings",
        data={"hostname": "kms.atlaso.internal", "port": "5696", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert disabled.status_code == 200
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "kms"})

    assert_apply_redirect(response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "/var/lib/atlaso/apply/kms/server.json" in (job.result or "")
        assert "atlaso-helper kms" in (job.result or "")


def test_successful_kms_apply_marks_disabled_provider_removal_applied(monkeypatch, tmp_path):
    """Verify a successful real apply acknowledges disabled-provider runtime removal.

    Args:
        monkeypatch: Pytest fixture used to replace fixed staging paths.
        tmp_path: Temporary directory provided for isolated staged files.
    """
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.models import VsphereKeyProvider
    from atlaso.app.ui import execute_appliance_apply_unit

    provider = VsphereKeyProvider(name="Disabled provider removal", enabled=False)

    class SuccessfulKmsAdapter:
        """Return successful non-dry-run helper results."""

        dry_run = False

        @staticmethod
        def validate_kms_config(path):
            """Return successful KMS validation.

            Args:
                path: Fixed staged KMS configuration path.
            """
            return AdapterResult(["kms", "validate", path], False)

        @staticmethod
        def apply_kms_config(path):
            """Return successful KMS apply.

            Args:
                path: Fixed staged KMS configuration path.
            """
            return AdapterResult(["kms", "apply", path], False)

    config_path = tmp_path / "kms" / "server.json"
    trust_path = tmp_path / "kms" / "client-trust.pem"
    monkeypatch.setattr("atlaso.app.ui.KMS_STAGED_CONFIG_PATH", str(config_path))
    monkeypatch.setattr("atlaso.app.ui.KMS_STAGED_CLIENT_TRUST_PATH", str(trust_path))
    unit = {
        "id": "kms",
        "label": "vSphere Key Providers",
        "context": {
            "vsphere_key_providers": [provider],
            "kms_client_trust_bundle": "",
        },
        "raw_config_preview": "{}",
        "summary": ["service disabled"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": str(config_path),
        "config_preview": "{}",
        "config_diff": "",
    }

    result = execute_appliance_apply_unit(unit, adapter=SuccessfulKmsAdapter())

    assert result["success"] is True
    assert provider.applied_at is not None


def test_vcf_backups_page_uses_local_user_for_sftp(client):
    """Verify that vcf backups page uses local user for sftp.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/vcf-backups")
    assert page.status_code == 200
    assert "VCF Backup SFTP" in page.text
    assert "Authentication uses one local Atlaso user from Users" in page.text
    assert "SFTP user" in page.text
    assert "vcf-backup" in page.text
    assert "/mnt/atlaso-vcf-backups" in page.text
    assert "/backups" in page.text
    assert 'action="/ui/management/vcf-backups/settings"' in page.text
    assert 'data-autosave-status-id="vcf-backup-settings-status"' in page.text
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in page.text
    assert "Review appliance changes" in page.text
    assert "VCF Backup SFTP desired state is disabled" in page.text
    assert "Listen interfaces" in page.text
    assert "Listen addresses" in page.text
    assert "service-bind-editor stacked-service-bind-editor" in page.text
    assert 'data-tag-name="listen_interfaces"' in page.text
    assert 'data-tag-name="listen_addresses"' not in page.text
    assert page.text.index('data-derived-listen-addresses') < page.text.index('name="port"')
    assert page.text.count("fixed-value-field") >= 2
    assert "<span>Config path</span>" not in page.text
    assert "eth1 - access / trunk" not in page.text
    assert "eth2 - access / access / 192.168.50.1" in page.text
    assert 'data-service-bind-address="192.168.50.1"' in page.text
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "initializeVcfBackupSettings" in app_js.text
    assert "updateVcfBackupDerivedAddress" in app_js.text
    assert "updateVcfBackupValidation" in app_js.text


def test_vcf_private_registry_page_models_harbor_and_bundle_relocation(client):
    """Verify that vcf private registry page models harbor and bundle relocation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/vcf-private-registry")
    assert page.status_code == 200
    assert "VCF Private Registry" in page.text
    assert "Harbor-backed private registry" in page.text
    assert '<aside class="side-stack">' in page.text
    assert "<h2>Harbor Settings</h2>" in page.text
    assert 'data-tab-target="vcf-registry-settings-panel"' not in page.text
    assert "<span>Config path</span>" not in page.text
    assert "registry.atlaso.internal" in page.text
    assert "vcf-supervisor-services" in page.text
    assert "/mnt/atlaso-vcf-registry" in page.text
    assert "Upload CA bundle" in page.text
    assert "Choose CA bundle" in page.text
    assert "file-upload-icon" in page.text
    assert "not uploaded" in page.text
    assert 'action="/ui/management/vcf-private-registry/settings"' in page.text
    assert 'data-autosave-status-id="vcf-registry-settings-status"' in page.text
    assert "Supervisor Service bundles" in page.text
    assert "Review appliance changes" in page.text
    assert "Review appliance changes" in page.text
    assert "harbor_admin_password: &lt;provisioned-by-atlaso-helper&gt;" in page.text
    assert "eth1 - access / trunk" not in page.text
    assert "eth2 - access / access / 192.168.50.1" in page.text
    assert "Listen addresses" in page.text
    assert "service-bind-editor" in page.text
    assert 'data-service-bind-address="192.168.50.1"' in page.text
    assert 'data-tag-name="listen_addresses"' not in page.text
    assert page.text.count("fixed-value-field") >= 1
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "initializeVcfRegistrySettings" in app_js.text
    assert "initializeVcfRegistryBundlesTable" in app_js.text
    assert "initializeFileUploadControls" in app_js.text
    assert "updateVcfRegistryValidation" in app_js.text


def test_vcf_private_registry_settings_autosave_bundle_status_api_and_apply_task(client):
    """Verify that vcf private registry settings autosave bundle status api and apply task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job

    login(client)
    page = client.get("/vcf-private-registry")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    settings_response = client.post(
        "/vcf-private-registry/settings",
        data={
            "enabled": "on",
            "hostname": "registry.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "harbor_project": "vcf-supervisor-services",
            "config_path": "/etc/atlaso/harbor/harbor.yml",
            "ca_bundle_path": "/etc/atlaso/ca/ca-bundle.pem",
            "server_certificate": "registry.atlaso.internal",
            "robot_account": "robot$vcf-supervisor-services",
            "relocation_dry_run": "on",
            "csrf": csrf,
        },
        files={"ca_bundle_file": ("registry-ca.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "application/x-pem-file")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert settings_response.status_code == 200
    assert settings_response.json()["status"] == "saved"
    assert settings_response.json()["listen_address"] == "192.168.50.1"
    assert settings_response.json()["listen_addresses"] == ["192.168.50.1"]
    assert settings_response.json()["endpoint"] == "registry.atlaso.internal"
    assert settings_response.json()["dns_record_action"] == "created"
    assert settings_response.json()["ca_bundle_source"] == "uploaded"
    assert settings_response.json()["ca_bundle_uploaded_name"] == "registry-ca.pem"
    assert settings_response.json()["ca_bundle_available"] is True
    assert settings_response.json()["validation_warnings"] == []
    assert "hostname: registry.atlaso.internal" in settings_response.json()["harbor_config_preview"]
    assert "<provisioned-by-atlaso-helper>" in settings_response.json()["harbor_config_preview"]
    with SessionLocal() as db:
        dns_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "registry.atlaso.internal",
                DnsRecord.record_type == "CNAME",
            )
        ).scalar_one()
        assert dns_record.address == "registry-192-168-50-1.atlaso.internal"
        assert dns_record.enabled is True
        interface_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "registry-192-168-50-1.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one()
        assert interface_record.address == "192.168.50.1"

    multi_response = client.post(
        "/vcf-private-registry/settings",
        data={
            "enabled": "on",
            "hostname": "registry.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth2", "eth0"],
            "listen_addresses": ["192.168.50.1", "192.168.49.1"],
            "port": "443",
            "harbor_project": "vcf-supervisor-services",
            "server_certificate": "registry.atlaso.internal",
            "robot_account": "robot$vcf-supervisor-services",
            "relocation_dry_run": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert multi_response.status_code == 200
    assert multi_response.json()["listen_interfaces"] == ["eth2"]
    assert multi_response.json()["listen_addresses"] == ["192.168.50.1"]
    assert "atlaso_listen_interfaces: ['eth2']" in multi_response.json()["harbor_config_preview"]

    moved_response = client.post(
        "/vcf-private-registry/settings",
        data={
            "enabled": "on",
            "hostname": "registry.atlaso.internal",
            "listen_interface": "eth0",
            "port": "443",
            "harbor_project": "vcf-supervisor-services",
            "ca_bundle_path": "/etc/atlaso/ca/ca-bundle.pem",
            "server_certificate": "registry.atlaso.internal",
            "robot_account": "robot$vcf-supervisor-services",
            "relocation_dry_run": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert moved_response.status_code == 200
    assert moved_response.json()["listen_interface"] == ""
    assert moved_response.json()["listen_address"] == ""
    assert moved_response.json()["listen_interfaces"] == []
    assert moved_response.json()["listen_addresses"] == []
    assert moved_response.json()["dns_record_action"] == "removed-old"
    assert moved_response.json()["ca_bundle_source"] == "uploaded"
    with SessionLocal() as db:
        dns_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "registry.atlaso.internal",
                DnsRecord.record_type == "CNAME",
            )
        ).scalar_one_or_none()
        assert dns_record is None
        interface_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "registry-192-168-50-1.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one_or_none()
        assert interface_record is None

    restore_response = client.post(
        "/vcf-private-registry/settings",
        data={
            "enabled": "on",
            "hostname": "registry.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "harbor_project": "vcf-supervisor-services",
            "ca_bundle_path": "/etc/atlaso/ca/ca-bundle.pem",
            "server_certificate": "registry.atlaso.internal",
            "robot_account": "robot$vcf-supervisor-services",
            "relocation_dry_run": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert restore_response.status_code == 200
    assert restore_response.json()["listen_address"] == "192.168.50.1"

    bundle_response = client.post(
        "/vcf-private-registry/bundles",
        data={
            "name": "sample-supervisor-service",
            "source_reference": "projects.registry.vmware.com/sample/supervisor-service:1.0.0",
            "target_reference": "",
            "enabled": "on",
            "status": "planned",
            "notes": "sample relocation",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert bundle_response.status_code == 303
    refreshed = client.get("/vcf-private-registry")
    assert "sample-supervisor-service" in refreshed.text
    assert "imgpkg copy -b projects.registry.vmware.com/sample/supervisor-service:1.0.0" in refreshed.text
    assert "registry.atlaso.internal/vcf-supervisor-services/supervisor-service" in refreshed.text

    raw_token = create_api_token(client, ["read:vcf-registry"])
    status = client.get("/api/v1/vcf-private-registry/status", headers={"Authorization": f"Bearer {raw_token}"})
    assert status.status_code == 200
    assert status.json()["hostname"] == "registry.atlaso.internal"
    assert status.json()["endpoint"] == "registry.atlaso.internal"
    assert status.json()["bundle_count"] == 1

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_private_registry"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "vcf-private-registry" in (job.result or "")
        assert "imgpkg copy" in (job.result or "")
        assert "provisioned-by-atlaso-helper" not in (job.result or "")
        assert "password123" not in (job.result or "").lower()


def make_vcfdt_archive(path, version="9.1.0.0100.25429019"):
    """Build vcfdt archive.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        version: Version identifier to validate or publish.
    """
    import io
    import tarfile

    with tarfile.open(path, "w:gz") as archive:
        payload = version.encode("utf-8")
        info = tarfile.TarInfo("conf/tool-version.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        properties_payload = b"spring.profiles.active=depot\nlcm.depot.adapter.host=archive.example.test\n"
        properties_info = tarfile.TarInfo("conf/application-prodv2.properties")
        properties_info.size = len(properties_payload)
        archive.addfile(properties_info, io.BytesIO(properties_payload))


def test_vcf_offline_depot_page_redirect_and_uploads_are_sanitized(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot page redirect and uploads are sanitized.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html
    import json
    import re

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job, Setting, VcfDepotDownloadProfile
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    login(client)
    legacy = client.get("/https-repository", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/ui/management/https-repository"

    page = client.get("/vcf-offline-depot")
    assert page.status_code == 200
    assert "VCF Offline Depot" in page.text
    assert "HTTPS Repository" not in page.text
    assert "Download profiles" in page.text
    assert "Profile download tasks" in page.text
    depot_profile_wizard = page.text.split('id="vcf-depot-profile-dialog"', 1)[1].split("</dialog>", 1)[0]
    assert 'data-atlaso-wizard-step="state"' not in depot_profile_wizard
    assert 'name="status"' not in depot_profile_wizard
    assert depot_profile_wizard.index('name="notes"') < depot_profile_wizard.index('data-atlaso-wizard-step="release"')
    assert 'data-atlaso-wizard-step="enablement"' in depot_profile_wizard
    assert 'class="vcf-depot-task-history task-grid-section"' in page.text
    assert "data-tasks-page" in page.text
    assert 'data-task-type="vcf-depot-download"' in page.text
    assert 'data-task-lock-component-filter="true"' in page.text
    assert 'data-task-grid-height="100%"' in page.text
    assert 'id="tasks-table" class="tabulator-shell"' in page.text
    assert 'id="task-detail-modal"' in page.text
    assert 'id="task-log-modal"' in page.text
    assert "Profile downloads only" in page.text
    assert "Open full task history" in page.text
    assert "No VCF profile download tasks have been recorded yet." in page.text
    profile_rows = json.loads(html.unescape(page.text.split("data-profiles='", 1)[1].split("'", 1)[0]))
    assert [row["name"] for row in profile_rows] == ["Metadata", "Binaries", "Esx"]
    with SessionLocal() as db:
        default_profiles = db.execute(select(VcfDepotDownloadProfile).order_by(VcfDepotDownloadProfile.name)).scalars().all()
        assert [(profile.name, profile.profile_type, profile.enabled) for profile in default_profiles] == [
            ("Binaries", "binaries", False),
            ("Esx", "esx", False),
            ("Metadata", "metadata", False),
        ]
    assert 'role="tab" data-tab-target="vcf-depot-preview-panel"' not in page.text
    assert 'data-vcf-depot-command-preview' not in page.text
    assert "Tool & Credentials" not in page.text
    assert "Review appliance changes" in page.text
    assert "VCF Download Tool" in page.text
    assert 'data-vcf-depot-tool-package-open' in page.text
    assert 'id="vcf-depot-tool-package-dialog"' in page.text
    assert 'data-vcf-depot-tool-package-form' in page.text
    assert 'action="/ui/management/vcf-offline-depot/tool-package"' in page.text
    assert 'data-atlaso-wizard-step="package"' in page.text
    assert 'data-vcf-depot-package-progress hidden' in page.text
    assert 'data-vcf-depot-package-status role="status" aria-live="polite"' in page.text
    assert "Select <strong>Stage package</strong> to start the upload." in page.text
    assert "Add or update the VCF Download Tool package" in page.text
    assert "no package staged" in page.text
    assert '>Add</span></button>' in page.text
    assert "Reset VCFDT staging" in page.text
    assert "application-prodv2.properties configuration" in page.text
    assert "Also reset saved application-prodv2.properties configuration" not in page.text
    assert 'data-vcf-depot-tool-reset-action>Reset</button>' in page.text
    assert 'button danger compact-button hidden' in page.text
    assert "Configure VCF Download Tool" in page.text
    assert ">Configure</button>" in page.text
    assert 'data-vcf-depot-configuration-open data-vcf-depot-requires-tool disabled' in page.text
    assert "Choose whether to queue a Software Depot ID refresh" in page.text
    assert "No Broadcom credentials staged." in page.text
    assert 'action="/ui/management/vcf-offline-depot/tool-configuration"' in page.text
    assert 'id="vcf-depot-configuration-dialog"' in page.text
    assert 'data-vcf-depot-configuration-form' in page.text
    assert 'data-atlaso-wizard-step="credentials"' in page.text
    assert 'data-atlaso-wizard-step="credential-input"' in page.text
    assert 'data-atlaso-wizard-step="properties"' in page.text
    assert 'data-atlaso-wizard-step="software-depot-id"' in page.text
    assert 'data-atlaso-wizard-step="review"' in page.text
    assert '<select name="credential_replacement_choice" data-vcf-depot-credential-choice required>' in page.text
    assert '<option value="" selected disabled>Select a credential</option>' in page.text
    assert '<option value="download_token">Use download token</option>' in page.text
    assert 'name="download_token_file"' in page.text
    assert 'name="download_token_text"' in page.text
    assert '<option value="activation_code">Use activation code</option>' in page.text
    assert '<option value="preserve">' not in page.text
    assert 'name="activation_code_file"' in page.text
    assert 'name="activation_code_text"' in page.text
    assert "application-prodv2.properties" in page.text
    assert 'name="application_properties"' in page.text
    assert 'aria-label="Application properties editor"' in page.text
    assert 'data-vcf-depot-properties-editor' in page.text
    assert '<label>\n      <span class="field-label"><span>application-prodv2.properties' not in page.text
    assert "Save VCFDT configuration" in page.text
    assert "lcm.depot.adapter.host=dl.broadcom.com" in page.text
    assert "/vcf-offline-depot/profiles/" in page.text
    assert "Start" in page.text
    assert "Start, schedule, and preview actions" in page.text
    assert "Schedule" in page.text
    template_text = Path("atlaso/app/templates/vcf_offline_depot.html").read_text(encoding="utf-8")
    assert "new=vcf_depot_download" not in template_text
    assert "?schedule_profile_id={{ profile.id }}#vcf-depot-schedule-modal" in template_text
    contextual_schedule = page.text.split('id="vcf-depot-schedule-modal"', 1)[1].split("</dialog>", 1)[0]
    assert contextual_schedule.count("data-atlaso-wizard-nav=") == 4
    assert all(f">{label}<" in contextual_schedule for label in ("Schedule", "Timing", "State", "Review"))
    assert 'name="task_type"' not in contextual_schedule
    assert 'name="vcf_profile_id"' not in contextual_schedule
    assert "The task type and profile are bound by the server" in contextual_schedule
    app_js = client.get("/static/app.js").text
    assert '"Schedule download (enable profile first)"' in app_js
    assert "function scheduleVcfDepotProfileDownload(row, launcher = null)" in app_js
    schedule_action_source = app_js.split("function scheduleVcfDepotProfileDownload", 1)[1].split("let vcfDepotProfilesTable", 1)[0]
    assert "atlasoOpenScheduleWizard" in schedule_action_source
    assert "window.location.assign" not in schedule_action_source
    start_action_source = app_js.split("async function startVcfDepotProfileDownload", 1)[1].split("async function previewVcfDepotProfileScript", 1)[0]
    assert "showTransientGridStatus" in start_action_source
    assert "showTransientGridError" in start_action_source
    assert "showVcfDepotMessage" not in start_action_source
    assert page.text.index("<th>Name</th>") < page.text.index("<th>Start</th>") < page.text.index("<th>Type</th>")
    assert 'href="/ui/management/logs"' in page.text
    assert "Generate the Software Depot ID" in page.text
    assert 'name="refresh_software_depot_id"' in page.text
    assert 'data-vcf-depot-refresh-id checked' in page.text
    assert 'data-vcf-depot-refresh-label' in page.text
    assert page.text.index('data-atlaso-wizard-step="software-depot-id"') < page.text.index('data-atlaso-wizard-step="credentials"')
    assert 'id="vcf-depot-generate-id-modal"' not in page.text
    assert "Software depot ID" in page.text
    assert "VCFDT staging" in page.text
    assert "Staged VCFDT inputs" not in page.text
    depot_settings_index = page.text.index("<h2>Depot Settings</h2>")
    vcfdt_staging_index = page.text.index("VCFDT staging")
    assert depot_settings_index < vcfdt_staging_index < page.text.index("VCF Download Tool", vcfdt_staging_index) < page.text.index("VCFDT configuration")
    assert '<span class="status-pill warn">dry-run</span>' not in page.text
    assert "Activation code" in page.text
    assert "Choose token file" in page.text
    assert "no file selected" in page.text
    assert "Choose the VCFDT archive" in page.text
    assert "DNS alias follows the first selected service listener." in page.text
    assert "Server certificate" not in page.text
    assert 'name="server_certificate"' not in page.text
    assert "Telemetry choice" not in page.text
    assert "<span>Telemetry</span>" not in page.text
    assert "<span>VMware CEIP</span>" in page.text
    assert 'href="/ui/management/settings#vmware-product-preferences"' in page.text
    assert 'name="telemetry_enabled"' not in page.text
    assert 'name="telemetry_choice"' not in page.text
    assert "<span>HTTP user</span>" in page.text
    assert "vcf-depot (disabled)" in page.text
    assert "<span>Unauthenticated access</span>" in page.text
    assert 'name="allow_unauthenticated_access"' in page.text
    assert "stacked-service-bind-editor" in page.text
    assert "depot-port-telemetry-row" not in page.text
    assert 'data-vcf-depot-software-depot-cell' in page.text
    assert 'data-vcf-depot-software-depot-id' in page.text
    assert 'data-vcf-depot-software-depot-id data-present="0"' in page.text
    rail_configuration_status = page.text.split('<div class="vcf-depot-configuration-status"', 1)[1].split("</div>", 1)[0]
    assert 'data-vcf-depot-software-depot-copy' not in rail_configuration_status
    assert 'vcf-depot-status-copy' not in rail_configuration_status
    assert 'Copy software depot ID' not in rail_configuration_status
    assert "Atlaso removes the staged download token and activation code" in page.text
    assert 'data-vcf-depot-package-progress' in page.text
    assert "Not generated" in page.text
    assert "<span>Tool file</span>" not in page.text
    assert 'data-vcf-depot-tool-name' not in page.text
    assert 'data-tab-storage-key="atlaso:vcf-offline-depot:active-tab"' not in page.text
    assert "/mnt/atlaso-vcf-offline-depot" in page.text
    assert "Depot store volume" in page.text
    assert page.text.count("fixed-value-field") >= 1
    assert "depot.atlaso.internal" in page.text
    assert "eth0 - management / access" not in page.text
    assert "eth1 - access / trunk" not in page.text
    assert "eth2 - access / access / 192.168.50.1" in page.text
    assert "Listen interfaces" in page.text
    assert "Listen addresses" in page.text
    assert 'data-tag-name="listen_addresses"' not in page.text
    assert "Listen addresses" in page.text
    assert "service-bind-editor" in page.text
    assert 'data-service-bind-address="192.168.50.1"' in page.text
    assert '<div class="settings-action-row software-depot-id-row">' in page.text
    assert 'action="/ui/management/vcf-offline-depot/settings"' in page.text
    assert 'data-autosave-status-id="vcf-depot-settings-status"' in page.text
    assert 'data-components=' in page.text
    assert 'data-esx-platforms=' in page.text
    assert "VCF_OBSERVABILITY_DATA_PLATFORM" in page.text
    assert "VSAN_FILE_SERVICES" in page.text
    assert "embeddedEsx-6.7-INT" in page.text
    assert "esxio-9.1-INTL" in page.text
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in page.text
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "initializeVcfDepotSettings" in app_js.text
    assert "initializeVcfDepotToolPackageWizard" in app_js.text
    assert "initializeVcfDepotConfigurationWizard" in app_js.text
    assert "Review VCFDT package staging" in app_js.text
    assert "Discard VCFDT package upload?" in app_js.text
    assert 'form.toggleAttribute("aria-busy", uploading)' in app_js.text
    assert "transferred" in app_js.text
    assert "Atlaso is validating and saving the package" in app_js.text
    assert "window.AtlasoUiPatterns.createWizard" in app_js.text
    assert 'body.set("application_properties", content)' in app_js.text
    assert "new TextEncoder().encode(content).length > 512 * 1024" in app_js.text
    assert 'fetch(managementUiPath("/vcf-offline-depot/software-depot-id/generate")' in app_js.text
    assert 'softwareDepotIdElement.dataset.present === "1"' in app_js.text
    assert 'refreshId.checked = !softwareDepotIdPresent' in app_js.text
    assert 'refreshId.disabled = !softwareDepotIdPresent' in app_js.text
    assert 'softwareDepotIdPresent ? "Refresh the Software Depot ID" : "Generate the Software Depot ID"' in app_js.text
    assert 'choice.disabled = refreshId instanceof HTMLInputElement && refreshId.checked' in app_js.text
    assert "Queueing the VCFDT Software Depot ID task" in app_js.text
    assert "task queued for execution" in app_js.text
    assert 'data-vcf-depot-queue-status role="status" aria-live="polite"' in page.text
    assert 'step.id === "software-depot-id"' in app_js.text
    assert 'return "review"' in app_js.text
    assert 'selectedCredential() === "preserve"' in app_js.text
    assert 'choice instanceof HTMLSelectElement' in app_js.text
    assert 'window.AtlasoMonaco.layout?.(properties)' in app_js.text
    assert "Queue Software Depot ID task" in app_js.text
    assert 'controller.setSkippedSteps' in app_js.text
    assert 'wizard.setSkippedSteps' in app_js.text
    assert "data-vcf-depot-configuration-credentials" in page.text
    assert "0 credentials ·" not in page.text
    assert "formatNginxListen(listenAddress, port)" in app_js.text
    assert "initializeVcfDepotProfilesTable" in app_js.text
    assert "initializeVcfDepotTasksTable" not in app_js.text
    assert "initializeTasksPage" in app_js.text
    assert 'query.set("task_type", page.dataset.taskType)' in app_js.text
    apply_refresh_js = app_js.text.split("function refreshCurrentWorkflowAfterApplianceApply", 1)[1].split("async function submitApplianceApplyForm", 1)[0]
    assert 'new Set([managementUiPath("/esx-storage"), managementUiPath("/vcf-offline-depot")])' in apply_refresh_js
    assert 'task?.status !== "succeeded"' in apply_refresh_js
    assert "window.location.reload()" in apply_refresh_js
    submit_apply_js = app_js.text.split("async function submitApplianceApplyForm", 1)[1].split("async function pollGlobalApplianceApply", 1)[0]
    assert 'form.querySelector("[data-appliance-apply-submit-error]")' in submit_apply_js
    assert "return true" in submit_apply_js
    assert "return false" in submit_apply_js
    assert 'paginationMode: "remote"' in app_js.text
    assert "paginationSize: 25" in app_js.text
    assert 'placeholder: page.dataset.taskEmptyMessage' in app_js.text
    assert "openTaskDetail" in app_js.text
    assert "openTaskLog" in app_js.text
    open_task_log_js = app_js.text.split("async function openTaskLog", 1)[1].split("async function cancelTask", 1)[0]
    assert "task?.log_url" in open_task_log_js
    assert 'headers: { "X-Atlaso-Task-Log": "1" }' in open_task_log_js
    assert "payload.profile_name" in open_task_log_js
    assert 'window.Prism.languages["atlaso-log"]' in app_js.text
    new_profile_js = app_js.text.split("function newVcfDepotProfileRow", 1)[1].split("function ", 1)[0]
    assert "enabled: false" in new_profile_js
    profiles_columns = app_js.text.split("function initializeVcfDepotProfilesTable", 1)[1].split("function ", 1)[0]
    assert profiles_columns.index('title: "Type"') < profiles_columns.index('title: "Enabled"') < profiles_columns.index('title: "SKU"')
    assert 'title: "Last run"' in profiles_columns
    assert 'blocked: "Failed"' in profiles_columns
    assert "All components" in app_js.text
    assert "componentValues" in app_js.text
    assert "esxPlatformValues" in app_js.text
    assert "vcfDepotDisabledPlatformsEditor" in app_js.text
    assert "formatVcfDepotDisabledPlatforms" in app_js.text
    assert "vcf-platform-tooltip" in app_js.text
    assert "Disabled platforms: ${escapeHtml(ariaLabel)}" in app_js.text
    assert 'cssClass: "vcf-platforms-cell"' in app_js.text
    assert "vcfDepotRememberActiveTab" not in app_js.text
    assert "tabulator-checklist-option" in app_js.text
    assert "tool staged" in app_js.text
    assert "DNS alias and target records created for this endpoint." in app_js.text
    assert "Old endpoint DNS alias and target records removed." in app_js.text
    assert "updateVcfDepotHttpsPreview" in app_js.text
    assert "if (payload.tool_archive_uploaded)" in app_js.text
    assert "location ^~ /static/" in app_js.text
    assert "location = /ui/public" in app_js.text
    assert "location ^~ /ui/public/" in app_js.text
    assert "location = /manifest.webmanifest" not in app_js.text
    assert "location = /service-worker.js" not in app_js.text
    assert "location = /ca" not in app_js.text
    assert "location ^~ /ca/" not in app_js.text
    assert "location = /requests" not in app_js.text
    assert "location ^~ /requests/" not in app_js.text
    assert "updateVcfDepotValidation" in app_js.text
    assert "initializeVcfDepotSoftwareDepotIdGenerator" not in app_js.text
    assert "initializeVcfDepotCredentialsPaste" in app_js.text
    assert "updateVcfDepotCredentialStatus" in app_js.text
    assert 'new Option("Keep staged credentials unchanged", "preserve", true, true)' in app_js.text
    assert 'choice.replaceChildren(...options)' in app_js.text
    assert "previewVcfDepotProfileScript" in app_js.text
    assert 'label: "Preview script"' in app_js.text
    assert "Global Appliance Apply is still required." in app_js.text
    assert "initializeVcfDepotPropertiesEditor" in app_js.text
    assert "initializeCopyValueButtons" in app_js.text
    assert "clearSelectedFileInputs" in app_js.text
    assert "Uploaded ${payload.tool_archive_name" in app_js.text
    assert "autosaveErrorFromText" in app_js.text
    assert "copyTextWithTextareaFallback" in app_js.text
    assert "window.isSecureContext" in app_js.text
    assert "softwareDepotId instanceof HTMLInputElement" in app_js.text
    assert "softwareDepotCopies.forEach" in app_js.text
    assert "softwareDepotCopy.dataset.copyValue = depotId" in app_js.text
    assert 'remove after the depot identity changes' in app_js.text
    assert "remove after first ID generation" in app_js.text
    assert "setVcfDepotToolDependentActions" in app_js.text
    assert "startVcfDepotProfileDownload" in app_js.text
    start_download_js = app_js.text.split("async function startVcfDepotProfileDownload", 1)[1].split("async function ", 1)[0]
    assert "window.location.reload()" not in start_download_js
    assert "await row.update({" in start_download_js
    assert "active_job_id: payload.job_id" in start_download_js
    assert "await atlasoTasksTable.setPage(1)" in start_download_js
    assert "await refreshTasksPage()" in start_download_js
    assert 'title: "Download mode"' in app_js.text
    assert 'field: "download_mode"' in app_js.text
    assert 'standard: "Standard"' not in app_js.text
    assert 'data.download_mode || "automated_install"' in app_js.text
    assert 'title: "Automated"' not in app_js.text
    assert 'title: "Upgrades only"' not in app_js.text
    assert 'title: "Patches only"' not in app_js.text
    assert "Download job ${payload.job_id}" not in app_js.text
    assert 'label: "Start download"' in app_js.text
    profiles_table_js = app_js.text.split("function initializeVcfDepotProfilesTable", 1)[1]
    assert profiles_table_js.index('title: "Name"') < profiles_table_js.index('title: "Start"') < profiles_table_js.index('title: "Type"')
    assert "rowHeight: 34" in profiles_table_js.split("columns:", 1)[0]
    assert "!data.can_start" in profiles_table_js
    assert "data.download_active" in profiles_table_js
    assert (
        "function setVcfDepotDownloadStates(activeTasks = [], activeExclusiveOperation = null, "
        "profileStartStates = [])"
    ) in app_js.text
    assert "const byProfile = new Map" in app_js.text
    assert "const prerequisitesByProfile = new Map" in app_js.text
    assert "profileStartStates: Array.isArray(payload.profile_start_states)" in app_js.text
    assert "data.start_blocker" in profiles_table_js

    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200
    assert ".tabulator-checklist-editor" in app_css.text
    assert ".inline-action-row" in app_css.text
    assert ".setting-inline-actions" in app_css.text
    assert "overflow-wrap: anywhere" in app_css.text
    assert ".setting-inline-actions .button" in app_css.text
    assert ".software-depot-id-row" in app_css.text
    assert ".copyable-inline-value" in app_css.text
    assert ".vcf-depot-status-copy" in app_css.text
    assert ".vcf-platform-tooltip" in app_css.text
    assert ".vcf-platform-tip table" in app_css.text
    assert ".vcf-platforms-cell" in app_css.text
    assert ".tabulator-cell.vcf-platforms-cell:hover .vcf-platform-tip" in app_css.text
    assert ".readonly-inline-value" in app_css.text
    assert ".software-depot-id-value" in app_css.text
    assert ".icon-button" in app_css.text
    assert ".code-editor-textarea" in app_css.text
    assert ".code-editor-textarea + .atlaso-monaco-shell .atlaso-monaco-editor" in app_css.text
    assert "#vcf-depot-properties-modal .confirm-modal-panel" in app_css.text
    assert ".vcf-offline-depot-workspace > .side-stack .detail-panel" in app_css.text
    assert ".vcf-offline-depot-main-panel" in app_css.text
    assert ".vcf-depot-task-history .task-grid-shell" in app_css.text
    assert ".vcfdt-tool-manager" in app_css.text
    assert ".compact-file-upload" in app_css.text
    assert 'data-monaco-editor data-monaco-language="ini" data-vcf-depot-properties-textarea' in page.text

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    depot_user_id = re.search(r'<option value="(\d+)" selected>vcf-depot(?: \(disabled\))?</option>', page.text).group(1)
    reset = client.post(
        f"/users/{depot_user_id}/password",
        data={"password": "Depot-user1!", "confirm_password": "Depot-user1!", "csrf": csrf},
    )
    assert reset.status_code in {200, 303}
    with SessionLocal() as db:
        binaries_profile = db.execute(select(VcfDepotDownloadProfile).where(VcfDepotDownloadProfile.name == "Binaries")).scalar_one()
        binaries_profile.enabled = True
        db.commit()
    response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "enabled": "on",
            "hostname": "depot.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "http_user_id": depot_user_id,
            "csrf": csrf,
        },
        files={
            "tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", archive_path.read_bytes(), "application/gzip"),
            "download_token_file": ("download-token.txt", "super-secret-token", "text/plain"),
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["listen_address"] == "192.168.50.1"
    assert payload["listen_addresses"] == ["192.168.50.1"]
    assert payload["endpoint"] == "depot.atlaso.internal"
    assert payload["server_certificate"] == "depot.atlaso.internal"
    assert payload["http_username"] == "vcf-depot"
    assert payload["allow_unauthenticated_access"] is False
    assert payload["vmware_ceip_enabled"] is False
    assert payload["tool_archive_name"] == "vcf-download-tool-9.1.0.test.tar.gz"
    assert payload["tool_archive_uploaded"] is True
    assert payload["tool_version"] == "9.1.0"
    assert payload["software_depot_id"] == ""
    assert payload["software_depot_id_error"] == ""
    assert payload["download_token_present"] is True
    assert payload["application_properties_present"] is True
    assert payload["application_properties_saved"] is False
    assert payload["application_properties_source"] == "Atlaso default"
    assert payload["valid"] is True
    assert payload["dns_record_action"] == "created"
    assert "listen 192.168.50.1:443 ssl;" in payload["https_config_preview"]
    assert 'auth_basic "VCF Offline Depot";' in payload["https_config_preview"]
    assert "auth_basic_user_file /etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd;" in payload["https_config_preview"]
    assert "satisfy any;" in payload["https_config_preview"]
    assert "auth_request /_atlaso_depot_auth;" in payload["https_config_preview"]
    assert "error_page 401 = /_atlaso_depot_login;" in payload["https_config_preview"]
    assert "proxy_pass http://127.0.0.1:8000/PROD/auth-failure;" in payload["https_config_preview"]
    assert "location = /PROD/" in payload["https_config_preview"]
    assert "location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$" in payload["https_config_preview"]
    assert "alias /mnt/atlaso-vcf-offline-depot/PROD/$1;" in payload["https_config_preview"]
    assert "autoindex off;" in payload["https_config_preview"]
    assert "root /mnt/atlaso-vcf-offline-depot;" not in payload["https_config_preview"]
    assert "--depot-store=/mnt/atlaso-vcf-offline-depot" in payload["command_preview"]
    assert "super-secret-token" not in response.text
    assert "archive.example.test" not in response.text

    multi_response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "enabled": "on",
            "hostname": "depot.atlaso.internal",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth0", "eth2"],
            "listen_addresses": ["192.168.49.1", "192.168.50.1"],
            "port": "443",
            "allow_unauthenticated_access": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert multi_response.status_code == 200
    multi_payload = multi_response.json()
    assert multi_payload["listen_interfaces"] == ["eth2"]
    assert multi_payload["listen_addresses"] == ["192.168.50.1"]
    assert multi_payload["valid"] is True
    assert multi_payload["allow_unauthenticated_access"] is True
    assert "auth_basic" not in multi_payload["https_config_preview"]
    assert "listen 192.168.49.1:443 ssl;" not in multi_payload["https_config_preview"]
    assert "listen 192.168.50.1:443 ssl;" in multi_payload["https_config_preview"]

    with SessionLocal() as db:
        token_secret = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one()
        software_id = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)).scalar_one_or_none()
        dns_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "depot.atlaso.internal",
                DnsRecord.record_type == "CNAME",
            )
        ).scalar_one()
        interface_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "depot-192-168-50-1.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one()
        assert token_secret.value == "super-secret-token"
        assert software_id is None
        assert dns_record.address == "depot-192-168-50-1.atlaso.internal"
        assert dns_record.enabled is True
        assert interface_record.address == "192.168.50.1"

    moved_response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "enabled": "on",
            "hostname": "offline-depot.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "http_user_id": depot_user_id,
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert moved_response.status_code == 200
    moved_payload = moved_response.json()
    assert moved_payload["hostname"] == "offline-depot.atlaso.internal"
    assert moved_payload["server_certificate"] == "offline-depot.atlaso.internal"
    assert moved_payload["vmware_ceip_enabled"] is False
    assert moved_payload["listen_address"] == "192.168.50.1"
    assert moved_payload["valid"] is True
    assert moved_payload["http_username"] == "vcf-depot"
    assert moved_payload["dns_record_action"] == "created+removed-old"
    with SessionLocal() as db:
        old_dns_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "depot.atlaso.internal",
                DnsRecord.record_type == "CNAME",
            )
        ).scalar_one_or_none()
        new_dns_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "offline-depot.atlaso.internal",
                DnsRecord.record_type == "CNAME",
            )
        ).scalar_one()
        old_interface_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "depot-192-168-50-1.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one_or_none()
        new_interface_record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "offline-depot-192-168-50-1.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one()
        assert old_dns_record is None
        assert old_interface_record is None
        assert new_dns_record.address == "offline-depot-192-168-50-1.atlaso.internal"
        assert new_interface_record.address == "192.168.50.1"

    properties_response = client.post(
        "/vcf-offline-depot/application-properties",
        data={
            "application_properties": "spring.profiles.active=depot\nlcm.depot.adapter.host=stage.example.test\nactivation.code=secret-activation-property\n",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert properties_response.status_code == 200
    properties_payload = properties_response.json()
    assert properties_payload["application_properties_present"] is True
    assert properties_payload["application_properties_saved"] is True
    assert properties_payload["application_properties_source"] == "operator saved"
    assert properties_payload["application_properties_updated_at"]
    assert "secret-activation-property" not in properties_response.text
    with SessionLocal() as db:
        properties_setting = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY)).scalar_one()
        assert "stage.example.test" in properties_setting.value

    raw_token = create_api_token(client, ["read:repository"])
    status = client.get("/api/v1/vcf-offline-depot/status", headers={"Authorization": f"Bearer {raw_token}"})
    assert status.status_code == 200
    assert status.json()["hostname"] == "offline-depot.atlaso.internal"
    assert status.json()["tool_archive_name"] == "vcf-download-tool-9.1.0.test.tar.gz"
    assert status.json()["software_depot_id"] == ""
    assert status.json()["software_depot_id_error"] == ""
    assert status.json()["download_token_present"] is True
    assert status.json()["activation_code_present"] is False
    assert status.json()["application_properties_present"] is True
    assert status.json()["application_properties_source"] == "operator saved"
    assert status.json()["http_username"] == "vcf-depot"
    assert status.json()["allow_unauthenticated_access"] is False
    assert "super-secret" not in status.text
    assert "secret-activation-property" not in status.text
    alias = client.get("/api/v1/repository/status", headers={"Authorization": f"Bearer {raw_token}"})
    assert alias.status_code == 200
    assert alias.json()["endpoint"] == status.json()["endpoint"]

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_offline_depot"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "vcf-offline-depot" in (job.result or "")
        assert "stage-tool" in (job.result or "")
        assert "generate-software-depot-id" in (job.result or "")
        assert "apply-properties" in (job.result or "")
        assert "apply-ceip DISABLE" in (job.result or "")
        assert "vcf-download-tool binaries download" in (job.result or "")
    assert "super-secret-token" not in (job.result or "")
    assert "secret-activation-property" not in (job.result or "")


def test_vcf_offline_depot_tool_upload_marks_apply_pending_without_profiles(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot tool upload marks apply pending without profiles.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import (
        appliance_apply_status,
        appliance_apply_units,
        update_appliance_apply_baselines,
    )

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        assert appliance_apply_status(db, "vcf_offline_depot", refresh=True)["changed"] is False

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "hostname": "depot.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "csrf": csrf,
        },
        files={
            "tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", archive_path.read_bytes(), "application/gzip"),
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["tool_archive_name"] == "vcf-download-tool-9.1.0.test.tar.gz"
    pending = client.get("/appliance-apply/status")
    assert pending.status_code == 200
    assert pending.json()["pending_count"] > 0
    with SessionLocal() as db:
        status = appliance_apply_status(db, "vcf_offline_depot", refresh=True)
        assert status["changed"] is True
        unit = next(unit for unit in appliance_apply_units(db) if unit["id"] == "vcf_offline_depot")
        assert "# VCFDT tool package status" in unit["config_preview"]
        assert "# Archive: vcf-download-tool-9.1.0.test.tar.gz" in unit["config_preview"]


def test_vcf_offline_depot_generation_timestamp_does_not_reopen_apply_unit(client):
    """Verify that vcf offline depot generation timestamp does not reopen apply unit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
    )
    from atlaso.app.ui import (
        appliance_apply_units,
        set_setting_value,
        update_appliance_apply_baselines,
    )

    with SessionLocal() as db:
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, "generated-depot-id")
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY, "2026-07-16T19:05:04.930993+00:00")
        unit = next(unit for unit in appliance_apply_units(db) if unit["id"] == "vcf_offline_depot")
        assert "# Software depot ID: generated" in unit["config_preview"]
        assert "# Software depot ID generated:" not in unit["config_preview"]
        update_appliance_apply_baselines(db, [unit], {"vcf_offline_depot"})
        db.commit()

        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY, "2026-07-16T19:22:22.389728+00:00")
        db.commit()

        refreshed = next(unit for unit in appliance_apply_units(db) if unit["id"] == "vcf_offline_depot")
        assert refreshed["changed"] is False
        assert refreshed["config_diff"] == ""


def test_vcf_offline_depot_apply_preserves_existing_software_depot_id_unless_refresh_is_explicit(tmp_path):
    """Verify that vcf offline depot apply preserves existing software depot id unless refresh is explicit.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import json
    from types import SimpleNamespace

    from atlaso.app.adapters.system import SystemAdapter
    from atlaso.app.ui import execute_appliance_apply_unit

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive_path.write_bytes(b"placeholder")
    context = {
        "vcf_depot_settings": SimpleNamespace(
            enabled=True,
            tool_archive_path=str(archive_path),
            config_path="/etc/atlaso/nginx/sites.d/vcf-offline-depot.conf",
        ),
        "vcf_depot_software_depot_id": {
            "id": "8c9506c6-7bdf-44d5-b2e9-50d829d66b99",
            "generated_at": "2026-08-05T19:19:20+00:00",
            "error": "",
        },
        "vcf_depot_https_config_preview": "server { listen 443 ssl; }",
        "vcf_depot_application_properties": {"content": "spring.profiles.active=depot\n"},
        "vmware_ceip_enabled": False,
    }
    unit = {
        "id": "vcf_offline_depot",
        "label": "VCF Offline Depot",
        "context": context,
        "raw_config_preview": "server { listen 443 ssl; }",
        "summary": ["service enabled", "1 enabled profile"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": context["vcf_depot_settings"].config_path,
        "config_preview": "server { listen 443 ssl; }",
        "config_diff": "",
    }

    ordinary_apply = execute_appliance_apply_unit(unit, adapter=SystemAdapter(dry_run=True))
    ordinary_commands = json.dumps(ordinary_apply["commands"])
    assert "stage-tool" in ordinary_commands
    assert "generate-software-depot-id" not in ordinary_commands

    explicit_refresh = execute_appliance_apply_unit(
        {**unit, "refresh_vcf_depot_software_depot_id": True},
        adapter=SystemAdapter(dry_run=True),
    )
    assert "generate-software-depot-id" in json.dumps(explicit_refresh["commands"])

    id_only = execute_appliance_apply_unit(
        {**unit, "refresh_vcf_depot_software_depot_id": True, "vcf_depot_id_only": True},
        adapter=SystemAdapter(dry_run=True),
    )
    id_only_commands = json.dumps(id_only["commands"])
    assert "stage-tool" in id_only_commands
    assert "apply-properties" in id_only_commands
    assert "apply-ceip" in id_only_commands
    assert "generate-software-depot-id" in id_only_commands
    assert "validate" not in id_only_commands
    assert "sync" not in id_only_commands
    assert "apply-https" not in id_only_commands

    missing_id_context = {**context, "vcf_depot_software_depot_id": {"id": "", "generated_at": "", "error": ""}}
    first_apply = execute_appliance_apply_unit(
        {**unit, "context": missing_id_context},
        adapter=SystemAdapter(dry_run=True),
    )
    assert "generate-software-depot-id" in json.dumps(first_apply["commands"])

    missing_id_context["vcf_depot_settings"].enabled = False
    disabled_service_first_apply = execute_appliance_apply_unit(
        {**unit, "context": missing_id_context},
        adapter=SystemAdapter(dry_run=True),
    )
    disabled_service_commands = json.dumps(disabled_service_first_apply["commands"])
    assert "stage-tool" in disabled_service_commands
    assert "generate-software-depot-id" in disabled_service_commands


def test_vcf_offline_depot_apply_stages_tool_without_download_profiles(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot apply stages tool without download profiles.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import delete, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, VcfDepotDownloadProfile

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    login(client)
    with SessionLocal() as db:
        db.execute(delete(VcfDepotDownloadProfile))
        db.commit()
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-offline-depot/settings",
        data={
            "enabled": "on",
            "hostname": "depot.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "allow_unauthenticated_access": "on",
            "csrf": csrf,
        },
        files={
            "tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", archive_path.read_bytes(), "application/gzip"),
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_offline_depot"})

    assert apply_response.status_code == 200
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "stage-tool" in (job.result or "")
        assert "generate-software-depot-id" in (job.result or "")
        assert "apply-properties" in (job.result or "")
        assert "apply-ceip DISABLE" in (job.result or "")
        assert "vcf-download-tool binaries download" not in (job.result or "")


def test_vcf_offline_depot_apply_stages_vcfdt_while_https_is_disabled(client, tmp_path):
    """Verify that vcf offline depot apply stages vcfdt while https is disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, VcfDepotDownloadProfile, VcfOfflineDepotSettings

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.enabled = False
        settings.tool_archive_path = str(archive_path)
        profile = VcfDepotDownloadProfile(
            name="Disabled profile",
            profile_type="binaries",
            enabled=False,
            vcf_version="9.1.0",
            sku="VCF",
            binary_type="INSTALL",
        )
        db.add(profile)
        db.commit()

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_offline_depot"})

    assert apply_response.status_code == 200
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "validate" in (job.result or "")
        assert "apply-https" in (job.result or "")
        assert "stage-tool" in (job.result or "")
        assert "apply-properties" in (job.result or "")
        assert "generate-software-depot-id" in (job.result or "")


def test_vcf_offline_depot_tool_package_wizard_endpoint_and_reset_clear_configuration(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot tool package wizard endpoint and reset clear configuration.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from pathlib import Path

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
        VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
    )

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    missing_upload = client.post("/vcf-offline-depot/tool-package", data={"csrf": csrf})
    assert missing_upload.status_code == 400
    assert missing_upload.json()["detail"] == "Choose a VCF Download Tool package to upload."

    upload = client.post(
        "/vcf-offline-depot/tool-package",
        data={"csrf": csrf},
        files={"tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", archive_path.read_bytes(), "application/gzip")},
    )
    assert upload.status_code == 200
    upload_payload = upload.json()
    assert upload_payload["tool_archive_name"] == "vcf-download-tool-9.1.0.test.tar.gz"
    assert upload_payload["tool_archive_uploaded"] is True
    assert upload_payload["tool_version"] == "9.1.0"
    assert upload_payload["application_properties_saved"] is False
    assert "download_token_name" not in upload_payload
    assert "activation_code_name" not in upload_payload
    credential = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "download_token", "credential_text": "reset-me", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert credential.status_code == 200

    refreshed = client.get("/vcf-offline-depot")
    assert ">Update</span></button>" in refreshed.text
    assert refreshed.text.count("<strong data-vcf-depot-tool-version>9.1.0</strong>") == 2
    assert 'data-vcf-depot-tool-reset-action>Reset</button>' in refreshed.text
    assert 'button danger compact-button hidden' not in refreshed.text
    assert '<option value="preserve">Keep staged credentials unchanged</option>' in refreshed.text
    assert '<option value="download_token">Replace download token</option>' in refreshed.text
    assert '<option value="activation_code">Use activation code</option>' in refreshed.text

    properties = client.post(
        "/vcf-offline-depot/application-properties",
        data={"csrf": csrf, "application_properties": "spring.profiles.active=depot\ncustom.setting=true\n"},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert properties.status_code == 200
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        stored_archive = Path(settings.tool_archive_path)
        assert stored_archive.exists()
        assert settings.tool_version == ""

    reset = client.post("/vcf-offline-depot/tool/reset", data={"csrf": csrf}, follow_redirects=False)
    assert reset.status_code == 303
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert settings.tool_archive_path == ""
        assert settings.tool_version == ""
        assert not stored_archive.exists()
        for key in [
            VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
            VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
            VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
            VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
            VCF_DEPOT_TOKEN_NAME_KEY,
            VCF_DEPOT_TOKEN_VALUE_KEY,
            VCF_DEPOT_ACTIVATION_NAME_KEY,
            VCF_DEPOT_ACTIVATION_VALUE_KEY,
        ]:
            assert db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none() is None
        for key in [
            VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
            VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
            VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
        ]:
            assert db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none() is None

    reset_page = client.get("/vcf-offline-depot")
    assert "no package staged" in reset_page.text
    assert "operator saved · saved" not in reset_page.text
    assert "Properties</small><strong>Default</strong>" in reset_page.text
    assert 'data-vcf-depot-configuration-open data-vcf-depot-requires-tool disabled' in reset_page.text

    apply_reset = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_offline_depot"})
    assert apply_reset.status_code == 200
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "reset-tool" in (job.result or "")

def test_vcf_offline_depot_without_tool_clears_stale_credential_state(client, monkeypatch):
    """Verify that vcf offline depot without tool clears stale credential state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)
    with SessionLocal() as db:
        db.add_all(
            [
                Setting(key=VCF_DEPOT_TOKEN_NAME_KEY, value="pasted token"),
                Setting(key=VCF_DEPOT_TOKEN_VALUE_KEY, value="stale-secret"),
            ]
        )
        db.commit()

    login(client)
    page = client.get("/vcf-offline-depot")

    assert page.status_code == 200
    assert "No Broadcom credentials staged." in page.text
    assert "pasted token" not in page.text
    assert "stale-secret" not in page.text
    with SessionLocal() as db:
        assert db.execute(select(Setting).where(Setting.key.in_([VCF_DEPOT_TOKEN_NAME_KEY, VCF_DEPOT_TOKEN_VALUE_KEY]))).scalars().all() == []


def test_vcf_offline_depot_profiles_cannot_enable_without_installed_tool(client, monkeypatch):
    """Verify that vcf offline depot profiles cannot enable without installed tool.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfDepotDownloadProfile

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)
    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-offline-depot/profiles",
        data={"csrf": csrf, "name": "Disabled without tool", "profile_type": "binaries", "enabled": "on"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        profile = db.execute(select(VcfDepotDownloadProfile).where(VcfDepotDownloadProfile.name == "Disabled without tool")).scalar_one()
        assert profile.enabled is False


def test_vcf_offline_depot_active_log_moves_to_named_task_log(tmp_path, monkeypatch):
    """Verify that vcf offline depot active log moves to named task log.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.services import vcf_depot_downloads

    active_log = tmp_path / "active-tool" / "log" / "vdt.log"
    task_logs = tmp_path / "task-logs"
    monkeypatch.setattr(ui, "VCF_DEPOT_VDT_LOG_PATH", active_log)
    monkeypatch.setattr(vcf_depot_downloads, "VCF_DEPOT_TASK_LOG_DIR", str(task_logs))
    active_log.parent.mkdir(parents=True)
    active_log.write_text("live output\n", encoding="utf-8")

    archived = ui.archive_vcf_depot_task_log("job_123", "Binaries Download")

    assert archived == task_logs / "job_123.log"
    assert archived.read_text(encoding="utf-8") == "live output\n"
    assert not active_log.exists()


def test_vcf_offline_depot_appliance_requires_staged_and_active_tool(tmp_path, monkeypatch):
    """Verify that vcf offline depot appliance requires staged and active tool.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from types import SimpleNamespace

    from atlaso.app import ui
    from atlaso.app.models import VcfOfflineDepotSettings

    runtime_dir = tmp_path / "active-tool"
    runtime_binary = runtime_dir / "bin" / "vcf-download-tool"
    runtime_binary.parent.mkdir(parents=True)
    runtime_binary.write_text("tool", encoding="utf-8")
    monkeypatch.setattr(ui, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    monkeypatch.setattr(ui, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_dir)
    settings = VcfOfflineDepotSettings(tool_archive_path="")

    assert ui.vcf_depot_tool_installed(settings) is False
    settings.tool_archive_path = "vcfDownloadTool/vcf-download-tool-test.tar.gz"
    assert ui.vcf_depot_tool_installed(settings) is True


def test_vcf_offline_depot_accepts_pasted_download_token_and_activation_code(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot accepts pasted download token and activation code.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from pathlib import PurePosixPath

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, VcfDepotDownloadProfile
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )
    from atlaso.app.ui import vcf_depot_secret_snapshot, vcf_offline_depot_context

    runtime_log = tmp_path / "active-tool" / "log" / "vdt.log"
    runtime_token = tmp_path / "active-tool" / "secrets" / "download-token.txt"
    runtime_activation = tmp_path / "active-tool" / "secrets" / "activation-code.txt"
    tool_archive = tmp_path / "vcf-download-tool-9.0.0.tar.gz"
    tool_archive.write_bytes(b"test archive")
    monkeypatch.setattr("atlaso.app.ui.VCF_DEPOT_VDT_LOG_PATH", PurePosixPath(runtime_log.as_posix()))
    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: tool_archive)

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        db.add(VcfDepotDownloadProfile(name="metadata", profile_type="metadata", enabled=True))
        db.commit()

    def metadata_command(preview: str) -> str:
        """Return metadata command.

        Args:
            preview: Preview supplied to the test scenario.
        """
        return next(line for line in preview.splitlines() if line.startswith("vcf-download-tool metadata download"))

    response = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "download_token", "credential_text": "pasted-secret-token", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["download_token_present"] is True
    assert payload["download_token_name"] == "pasted token"
    assert payload["download_token_updated_at"]
    assert "pasted-secret-token" not in payload["command_preview"]
    assert "pasted-secret-token" not in response.text
    assert runtime_token.read_text(encoding="utf-8") == "pasted-secret-token"

    with SessionLocal() as db:
        token_name = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_NAME_KEY)).scalar_one()
        token_secret = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one()
        assert token_name.value == "pasted token"
        assert token_secret.value == "pasted-secret-token"

    upload_response = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "download_token", "credential_text": "", "csrf": csrf},
        files={"credential_file": ("download-token.txt", "uploaded-secret-token", "text/plain")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert upload_response.status_code == 200
    upload_payload = upload_response.json()
    assert upload_payload["download_token_present"] is True
    assert upload_payload["download_token_name"] == "download-token.txt"
    assert "uploaded-secret-token" not in upload_response.text
    assert runtime_token.read_text(encoding="utf-8") == "uploaded-secret-token"

    staged_page = client.get("/vcf-offline-depot")
    assert staged_page.status_code == 200
    assert "download-token.txt" not in staged_page.text
    assert "download token staged" in staged_page.text
    assert "uploaded-secret-token" not in staged_page.text

    with SessionLocal() as db:
        token_name = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_NAME_KEY)).scalar_one()
        token_secret = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one()
        assert token_name.value == "download-token.txt"
        assert token_secret.value == "uploaded-secret-token"

    activation_response = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "activation_code", "credential_text": "pasted-secret-activation-code", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert activation_response.status_code == 200
    activation_payload = activation_response.json()
    assert activation_payload["activation_code_present"] is True
    assert activation_payload["activation_code_name"] == "pasted activation code"
    activation_command = metadata_command(activation_payload["command_preview"])
    assert "--depot-download-activation-code-file=${ACTIVATION_CODE_FILE}" in activation_command
    assert "--depot-download-token-file=${TOKEN_FILE}" not in activation_command
    assert "pasted-secret-activation-code" not in activation_payload["command_preview"]
    assert "pasted-secret-activation-code" not in activation_response.text
    assert runtime_activation.read_text(encoding="utf-8") == "pasted-secret-activation-code"

    with SessionLocal() as db:
        activation_name = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_NAME_KEY)).scalar_one()
        activation_secret = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)).scalar_one()
        assert activation_name.value == "pasted activation code"
        assert activation_secret.value == "pasted-secret-activation-code"

    activation_upload_response = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "activation_code", "credential_text": "", "csrf": csrf},
        files={"credential_file": ("activation-code.txt", "uploaded-secret-activation-code", "text/plain")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert activation_upload_response.status_code == 200
    activation_upload_payload = activation_upload_response.json()
    assert activation_upload_payload["activation_code_present"] is True
    assert activation_upload_payload["activation_code_name"] == "activation-code.txt"
    activation_upload_command = metadata_command(activation_upload_payload["command_preview"])
    assert "--depot-download-activation-code-file=${ACTIVATION_CODE_FILE}" in activation_upload_command
    assert "--depot-download-token-file=${TOKEN_FILE}" not in activation_upload_command
    assert "uploaded-secret-activation-code" not in activation_upload_response.text
    assert runtime_activation.read_text(encoding="utf-8") == "uploaded-secret-activation-code"

    with SessionLocal() as db:
        activation_name = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_NAME_KEY)).scalar_one()
        activation_secret = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)).scalar_one()
        assert activation_name.value == "activation-code.txt"
        assert activation_secret.value == "uploaded-secret-activation-code"

    with SessionLocal() as db:
        snapshot = vcf_depot_secret_snapshot(vcf_offline_depot_context(db))
        assert "Download token input file: staged" in snapshot
        assert "Activation-code input file: staged" in snapshot
        assert "pasted-secret-token" not in snapshot
        assert "uploaded-secret-token" not in snapshot
        assert "pasted-secret-activation-code" not in snapshot
        assert "uploaded-secret-activation-code" not in snapshot

    token_replacement_response = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "download_token", "credential_text": "replacement-secret-token", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert token_replacement_response.status_code == 200
    replacement_payload = token_replacement_response.json()
    replacement_command = metadata_command(replacement_payload["command_preview"])
    assert "--depot-download-token-file=${TOKEN_FILE}" in replacement_command
    assert "--depot-download-activation-code-file=${ACTIVATION_CODE_FILE}" not in replacement_command
    assert "replacement-secret-token" not in token_replacement_response.text


def test_vcf_offline_depot_tool_configuration_is_atomic_and_presence_only(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot tool configuration is atomic and presence only.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from pathlib import PurePosixPath

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Setting
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )

    runtime_log = tmp_path / "active-tool" / "log" / "vdt.log"
    tool_archive = tmp_path / "vcf-download-tool-9.1.0.tar.gz"
    tool_archive.write_bytes(b"test archive")
    monkeypatch.setattr("atlaso.app.ui.VCF_DEPOT_VDT_LOG_PATH", PurePosixPath(runtime_log.as_posix()))
    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: tool_archive)

    with SessionLocal() as db:
        db.add(Setting(key=VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, value="existing-depot-id"))
        db.commit()

    login(client)
    page = client.get("/vcf-offline-depot")
    rail_configuration_status = page.text.split('<div class="vcf-depot-configuration-status"', 1)[1].split("</div>", 1)[0]
    assert 'data-vcf-depot-software-depot-copy' in rail_configuration_status
    assert 'vcf-depot-status-copy' in rail_configuration_status
    assert 'Copy software depot ID' in rail_configuration_status
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    properties = "spring.profiles.active=depot\nfixture.setting=combined-save\n"
    response = client.post(
        "/vcf-offline-depot/tool-configuration",
        data={
            "csrf": csrf,
            "replace_download_token": "on",
            "download_token_text": "ignored-token-text",
            "application_properties": properties,
        },
        files={"download_token_file": ("fixture-token.txt", "fixture-token-file", "text/plain")},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["download_token_present"] is True
    assert payload["activation_code_present"] is False
    assert payload["application_properties_present"] is True
    assert payload["application_properties_name"] == "application-prodv2.properties"
    assert payload["software_depot_id"] == "existing-depot-id"
    assert "ignored-token-text" not in response.text
    assert "fixture-token-file" not in response.text
    assert "fixture-activation-text" not in response.text
    assert "fixture.setting" not in response.text

    activation_response = client.post(
        "/vcf-offline-depot/tool-configuration",
        data={
            "csrf": csrf,
            "replace_activation_code": "on",
            "activation_code_text": "fixture-activation-text",
            "application_properties": properties,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert activation_response.status_code == 200
    assert activation_response.json()["download_token_present"] is True
    assert activation_response.json()["activation_code_present"] is True
    assert "fixture-activation-text" not in activation_response.text

    with SessionLocal() as db:
        values = {
            setting.key: setting.value
            for setting in db.execute(
                select(Setting).where(
                    Setting.key.in_(
                        [
                            VCF_DEPOT_TOKEN_NAME_KEY,
                            VCF_DEPOT_TOKEN_VALUE_KEY,
                            VCF_DEPOT_ACTIVATION_NAME_KEY,
                            VCF_DEPOT_ACTIVATION_VALUE_KEY,
                            VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
                            VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
                        ]
                    )
                )
            ).scalars()
        }
        assert values[VCF_DEPOT_TOKEN_NAME_KEY] == "fixture-token.txt"
        assert values[VCF_DEPOT_TOKEN_VALUE_KEY] == "fixture-token-file"
        assert values[VCF_DEPOT_ACTIVATION_NAME_KEY] == "pasted activation code"
        assert values[VCF_DEPOT_ACTIVATION_VALUE_KEY] == "fixture-activation-text"
        assert values[VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY] == properties
        assert values[VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY] == "existing-depot-id"
        audit_text = "\n".join(str(event.detail or "") for event in db.execute(select(AuditEvent)).scalars())
        assert "fixture-token-file" not in audit_text
        assert "fixture-activation-text" not in audit_text
        assert "fixture.setting" not in audit_text

    exclusive = client.post(
        "/vcf-offline-depot/tool-configuration",
        data={
            "csrf": csrf,
            "replace_download_token": "on",
            "download_token_text": "must-not-save",
            "replace_activation_code": "on",
            "activation_code_text": "must-not-save",
            "application_properties": "fixture.setting=must-not-save\n",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert exclusive.status_code == 400
    assert "only one Broadcom credential" in exclusive.text

    failed = client.post(
        "/vcf-offline-depot/tool-configuration",
        data={
            "csrf": csrf,
            "replace_activation_code": "on",
            "activation_code_text": "   ",
            "application_properties": "fixture.setting=must-not-save\n",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert failed.status_code == 400
    assert "cannot be empty" in failed.text
    with SessionLocal() as db:
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one().value == "fixture-token-file"
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)).scalar_one().value == "fixture-activation-text"
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY)).scalar_one().value == properties
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)).scalar_one().value == "existing-depot-id"

    blank_file = client.post(
        "/vcf-offline-depot/tool-configuration",
        data={
            "csrf": csrf,
            "replace_download_token": "on",
            "download_token_text": "pasted-text-must-not-win",
            "application_properties": properties,
        },
        files={"download_token_file": ("blank-token.txt", b"", "text/plain")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert blank_file.status_code == 400
    assert "uploads cannot be empty" in blank_file.text
    with SessionLocal() as db:
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one().value == "fixture-token-file"

    preserved = client.post(
        "/vcf-offline-depot/tool-configuration",
        data={"csrf": csrf, "application_properties": properties.replace("combined-save", "preserved-credentials")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert preserved.status_code == 200
    with SessionLocal() as db:
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)).scalar_one().value == "fixture-token-file"
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)).scalar_one().value == "fixture-activation-text"
        assert db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)).scalar_one().value == "existing-depot-id"


def test_vcf_offline_depot_manual_profile_download_starts_job(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot manual profile download starts job.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        Job,
        Setting,
        VcfDepotDownloadProfile,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.tool_version = "9.1.0"
        db.add(Setting(key=VCF_DEPOT_TOKEN_NAME_KEY, value="download-token.txt"))
        db.add(Setting(key=VCF_DEPOT_TOKEN_VALUE_KEY, value="manual-secret-token"))
        profile = VcfDepotDownloadProfile(
            name="vcf-install",
            profile_type="binaries",
            sku="VCF",
            vcf_version="9.1.0",
            binary_type="INSTALL",
            enabled=True,
        )
        db.add(profile)
        db.commit()
        profile_id = profile.id

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    conflicting_mode_response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/edit",
        data={
            "csrf": csrf,
            "name": "vcf-install",
            "profile_type": "binaries",
            "automated_install": "on",
            "upgrades_only": "on",
        },
    )
    assert conflicting_mode_response.status_code == 400
    assert "Choose only one VCFDT download mode" in conflicting_mode_response.text
    preview_response = client.get(f"/vcf-offline-depot/profiles/{profile_id}/preview")
    assert preview_response.status_code == 200
    preview_payload = preview_response.json()
    assert preview_payload["profile_name"] == "vcf-install"
    assert "vcf-download-tool configuration get --software-depot-id" not in preview_payload["script"]
    assert "vcf-download-tool binaries list" not in preview_payload["script"]
    assert "vcf-download-tool binaries download" in preview_payload["script"]
    assert "manual-secret-token" not in preview_response.text
    response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/download",
        data={"csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "started"
    assert payload["profile_name"] == "vcf-install"
    assert payload["profile_status"] == "ready"
    assert payload["dry_run"] is False
    assert payload["log_path"] == f"/var/lib/atlaso/vcfDownloadTool/task-logs/{payload['job_id']}.log"
    assert len(payload["commands"]) == 1
    assert payload["commands"][0]["command"][0] == "/var/lib/atlaso/vcfDownloadTool/active-tool/bin/vcf-download-tool"
    assert payload["commands"][0]["command"][1:3] == ["binaries", "download"]
    assert "--depot-download-token-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/download-token.txt" in payload["commands"][0]["command"]
    assert "manual-secret-token" not in response.text

    concurrent_response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/download",
        data={"csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert concurrent_response.status_code == 409
    assert payload["job_id"] in concurrent_response.json()["detail"]
    assert "Wait for that profile task to finish" in concurrent_response.json()["detail"]

    active_page = client.get("/vcf-offline-depot")
    active_rows_payload = active_page.text.split("data-profiles='", 1)[1].split("'", 1)[0]
    active_rows = json.loads(html.unescape(active_rows_payload))
    active_row = next(item for item in active_rows if item["id"] == profile_id)
    assert active_row["download_active"] is True
    assert payload["job_id"] in active_row["active_task_blocker"]

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "vcf-depot-download")).scalar_one()
        profile = db.get(VcfDepotDownloadProfile, profile_id)
        assert json.loads(job.task_config_json or "{}") == {"profile_id": profile_id}
        assert job.status == "pending"
        assert '"profile_name": "vcf-install"' in (job.result or "")
        assert '"dry_run": false' in (job.result or "")
        assert f'"log_path": "/var/lib/atlaso/vcfDownloadTool/task-logs/{job.id}.log"' in (job.result or "")
        assert '"trigger": "manual"' in (job.result or "")
        assert '"commands"' not in (job.result or "")
        assert "manual-secret-token" not in (job.result or "")
        assert profile and profile.status == "ready"

    identity_edit = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/edit",
        data={
            "csrf": csrf,
            "name": "vcf-install",
            "profile_type": "binaries",
            "sku": "VCF",
            "vcf_version": "9.1.0",
            "binary_type": "INSTALL",
            "automated_install": "on",
            "enabled": "on",
            "notes": "Status remains task-owned",
        },
        follow_redirects=False,
    )
    assert identity_edit.status_code == 303
    with SessionLocal() as db:
        profile = db.get(VcfDepotDownloadProfile, profile_id)
        assert profile and profile.status == "ready"
        assert profile.notes == "Status remains task-owned"

    shared_runtime_log = tmp_path / "active-tool" / "log" / "vdt.log"
    shared_runtime_log.parent.mkdir(parents=True)
    shared_runtime_log.write_text("another profile is running\n", encoding="utf-8")
    monkeypatch.setattr(ui, "VCF_DEPOT_VDT_LOG_PATH", shared_runtime_log)
    task_log_page = client.get(f"/vcf-offline-depot/tasks/{payload['job_id']}/log")
    assert task_log_page.status_code == 200
    assert "VCFDT task log" in task_log_page.text
    assert "No task log is available." in task_log_page.text
    assert "another profile is running" not in task_log_page.text
    task_log_payload = client.get(
        f"/vcf-offline-depot/tasks/{payload['job_id']}/log",
        headers={"X-Atlaso-Task-Log": "1"},
    )
    assert task_log_payload.status_code == 200
    assert task_log_payload.json()["job_id"] == payload["job_id"]
    assert task_log_payload.json()["text"] == "No task log is available."
    task_status_payload = client.get("/vcf-offline-depot/tasks/status")
    assert task_status_payload.status_code == 200
    assert task_status_payload.json()["last_row"] >= 1
    assert task_status_payload.json()["download_active"] is True
    assert task_status_payload.json()["active_job_id"] == payload["job_id"]
    assert task_status_payload.json()["active_downloads"] == [
        {"job_id": payload["job_id"], "profile_id": profile_id, "status": "pending"}
    ]
    task_row = next(task for task in task_status_payload.json()["tasks"] if task["id"] == payload["job_id"])
    assert task_row["status"] == "pending"
    assert task_row["progress_percent"] == "0"
    shared_task_payload = client.get(
        "/tasks/status",
        params={"task_type": "vcf-depot-download", "job_id": payload["job_id"]},
    )
    assert shared_task_payload.status_code == 200
    assert shared_task_payload.json()["selected_task"]["id"] == payload["job_id"]
    assert shared_task_payload.json()["selected_task"]["log_url"] == f"/vcf-offline-depot/tasks/{payload['job_id']}/log"
    assert shared_task_payload.json()["active_downloads"] == [
        {"job_id": payload["job_id"], "profile_id": profile_id, "status": "pending"}
    ]
    assert all(task["type"] == "vcf-depot-download" for task in shared_task_payload.json()["tasks"])


def test_vcf_offline_depot_contextual_schedule_is_server_bound_and_stays_in_page(client, tmp_path):
    """Verify the depot schedule endpoint binds task and profile server-side.

    Args:
        client: HTTP test client used to exercise the depot schedule endpoint.
        tmp_path: Temporary directory used for a staged VCFDT package fixture.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        Schedule,
        VcfDepotDownloadProfile,
        VcfOfflineDepotSettings,
    )

    login(client)
    archive_path = tmp_path / "vcf-download-tool-9.1.0.contextual.tar.gz"
    make_vcfdt_archive(archive_path)
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.tool_version = "9.1.0"
        profile = VcfDepotDownloadProfile(
            name="contextual-schedule-profile",
            profile_type="metadata",
            enabled=True,
        )
        other = VcfDepotDownloadProfile(
            name="other-contextual-profile",
            profile_type="metadata",
            enabled=True,
        )
        db.add_all([profile, other])
        db.commit()
        profile_id, other_id = profile.id, other.id

    page = client.get("/automation")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "contextual-profile-nightly",
            "schedule_kind": "cron",
            "cron_expression": "15 3 * * *",
            "timezone_name": "UTC",
            "enabled": "on",
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 201
    assert response.json()["profile_id"] == profile_id
    assert response.json()["automation_url"] == "/ui/management/automation#schedules"
    with SessionLocal() as db:
        schedule = db.execute(select(Schedule).where(Schedule.name == "contextual-profile-nightly")).scalar_one()
        assert schedule.task_type == "vcf_depot_download"
        assert json.loads(schedule.task_config_json) == {"profile_id": profile_id}
        audit = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "create_automation_schedule",
                AuditEvent.resource_id == str(schedule.id),
            )
        ).scalar_one()
        assert f"profile_id={profile_id}" in audit.detail

    fallback_page = client.get(
        "/vcf-offline-depot",
        params={"schedule_profile_id": profile_id},
    )
    assert fallback_page.status_code == 200
    fallback_schedule = fallback_page.text.split(
        'id="vcf-depot-schedule-modal"', 1
    )[1].split("</dialog>", 1)[0]
    assert " open" in fallback_schedule.split(">", 1)[0]
    assert (
        f'action="/ui/management/vcf-offline-depot/profiles/{profile_id}/schedules"'
        in fallback_schedule
    )
    assert "contextual-schedule-profile" in fallback_schedule
    assert "<noscript><style>" in fallback_page.text
    assert fallback_schedule.count('name="cron_expression"') == 1
    assert "data-automation-cron-native-expression" in fallback_schedule
    assert ".automation-cron-builder { display: none !important; }" in fallback_page.text
    assert ".automation-once-native { display: grid !important; }" in fallback_page.text
    cron_native = fallback_schedule.split("data-automation-cron-native-expression", 1)[1].split("</label>", 1)[0]
    assert " required" not in cron_native
    assert f'data-context-profile-id="{profile_id}"' in fallback_schedule
    assert 'data-context-profile-name="contextual-schedule-profile"' in fallback_schedule
    assert f'data-vcf-depot-fallback-schedule="{profile_id}"' in fallback_page.text
    app_js = client.get("/static/app.js").text
    assert "if (isContextualVcfSchedule && scheduleForm.dataset.contextProfileId)" in app_js
    assert "if (scheduleModal.open) scheduleModal.close();" in app_js
    assert "openScheduleWizard(serverProfile, launcher instanceof HTMLElement ? launcher : null)" in app_js
    assert 'if (scheduleForm.dataset.contextReadOnly === "true")' in app_js
    assert "if (contextualError) scheduleWizard.setError(contextualError);" in app_js
    assert '!element.hasAttribute("data-automation-cron-native-expression")' in app_js
    automation_initializer = app_js.split("function initializeAutomationTables()", 1)[1]
    assert automation_initializer.index("initializeContextualVcfScheduleWizard();") < automation_initializer.index(
        'if (typeof Tabulator === "undefined") return;'
    )
    contextual_initializer = app_js.split(
        "function initializeContextualVcfScheduleWizard()", 1
    )[1].split("function initializeAutomationTables()", 1)[0]
    assert "window.AtlasoUiPatterns.createWizard({" in contextual_initializer
    assert "Tabulator" not in contextual_initializer

    fallback_submit = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "contextual-profile-fallback",
            "schedule_kind": "cron",
            "cron_expression": "30 4 * * *",
            "timezone_name": "UTC",
        },
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert fallback_submit.status_code == 303
    assert fallback_submit.headers["location"] == (
        "/ui/management/vcf-offline-depot#vcf-depot-profiles-panel"
    )
    with SessionLocal() as db:
        fallback_schedule_row = db.execute(
            select(Schedule).where(Schedule.name == "contextual-profile-fallback")
        ).scalar_one()
        assert json.loads(fallback_schedule_row.task_config_json) == {"profile_id": profile_id}

    fallback_once = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "contextual-profile-fallback-once",
            "schedule_kind": "once",
            "cron_expression": "",
            "run_once_at": "2037-08-13T04:30",
            "timezone_name": "UTC",
        },
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert fallback_once.status_code == 303
    with SessionLocal() as db:
        once_schedule = db.execute(
            select(Schedule).where(Schedule.name == "contextual-profile-fallback-once")
        ).scalar_one()
        assert once_schedule.schedule_kind == "once"
        assert once_schedule.run_once_at is not None

    fallback_invalid = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "contextual-profile-fallback-invalid",
            "schedule_kind": "cron",
            "cron_expression": "invalid",
            "timezone_name": "America/Los_Angeles",
            "enabled": "on",
        },
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert fallback_invalid.status_code == 422
    assert "location" not in fallback_invalid.headers
    assert (
        "Cron expression must contain five fields: minute hour day month weekday."
        in fallback_invalid.text
    )
    assert 'value="contextual-profile-fallback-invalid"' in fallback_invalid.text
    assert 'value="America/Los_Angeles"' in fallback_invalid.text
    assert 'name="cron_expression" value="invalid"' in fallback_invalid.text
    assert 'name="enabled" checked' in fallback_invalid.text
    assert (
        f'action="/ui/management/vcf-offline-depot/profiles/{profile_id}/schedules"'
        in fallback_invalid.text
    )

    task_tamper = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "tampered-task",
            "task_type": "managed_script",
            "schedule_kind": "cron",
            "cron_expression": "0 4 * * *",
            "timezone_name": "UTC",
        },
    )
    assert task_tamper.status_code == 422
    profile_tamper = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "tampered-profile",
            "vcf_profile_id": str(other_id),
            "schedule_kind": "cron",
            "cron_expression": "0 4 * * *",
            "timezone_name": "UTC",
        },
    )
    assert profile_tamper.status_code == 422

    invalid_schedule = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/schedules",
        data={
            "csrf": csrf,
            "name": "invalid-contextual-schedule",
            "schedule_kind": "cron",
            "cron_expression": "invalid",
            "timezone_name": "UTC",
        },
        headers={"Accept": "application/json"},
    )
    assert invalid_schedule.status_code == 422
    assert invalid_schedule.json()["detail"] == (
        "Cron expression must contain five fields: minute hour day month weekday."
    )

    with SessionLocal() as db:
        disabled = VcfDepotDownloadProfile(
            name="disabled-contextual-profile",
            profile_type="metadata",
            enabled=False,
        )
        deleted = VcfDepotDownloadProfile(
            name="deleted-contextual-profile",
            profile_type="metadata",
            enabled=True,
        )
        db.add_all([disabled, deleted])
        db.commit()
        disabled_id, deleted_id = disabled.id, deleted.id
        db.delete(deleted)
        db.commit()

    disabled_fallback = client.post(
        f"/vcf-offline-depot/profiles/{disabled_id}/schedules",
        data={
            "csrf": csrf,
            "name": "disabled-race-fallback",
            "schedule_kind": "cron",
            "cron_expression": "0 4 * * *",
            "timezone_name": "America/Los_Angeles",
            "enabled": "on",
        },
        headers={"Accept": "text/html"},
    )
    assert disabled_fallback.status_code == 422
    disabled_dialog = disabled_fallback.text.split(
        'id="vcf-depot-schedule-modal"', 1
    )[1].split("</dialog>", 1)[0]
    assert " open" in disabled_dialog.split(">", 1)[0]
    assert 'data-context-read-only="true"' in disabled_dialog
    assert 'data-automation-wizard-next data-atlaso-wizard-next disabled' not in disabled_dialog
    assert 'form.querySelectorAll("input, select, textarea, [data-atlaso-wizard-submit]")' in app_js
    assert "[data-atlaso-wizard-nav], [data-atlaso-wizard-next]" not in app_js.split(
        'if (form.dataset.contextReadOnly === "true")', 1
    )[1].split("const contextualError", 1)[0]
    assert "disabled-contextual-profile" in disabled_dialog
    assert "Choose an enabled VCF Offline Depot download profile." in disabled_dialog
    assert 'value="disabled-race-fallback"' in disabled_dialog
    assert 'value="America/Los_Angeles"' in disabled_dialog
    assert "data-atlaso-wizard-submit disabled" in disabled_dialog
    assert "display: none !important" in disabled_fallback.text

    deleted_fallback = client.post(
        f"/vcf-offline-depot/profiles/{deleted_id}/schedules",
        data={
            "csrf": csrf,
            "name": "deleted-race-fallback",
            "schedule_kind": "cron",
            "cron_expression": "0 4 * * *",
            "timezone_name": "UTC",
        },
        headers={"Accept": "text/html"},
    )
    assert deleted_fallback.status_code == 422
    profile_error = deleted_fallback.text.split(
        'id="vcf-depot-profile-error"', 1
    )[1].split("</div>", 1)[0]
    assert " hidden" not in profile_error.split(">", 1)[0]
    assert "Choose an enabled VCF Offline Depot download profile." in profile_error

    for invalid_profile_id in (disabled_id, deleted_id, 999_999):
        invalid = client.post(
            f"/vcf-offline-depot/profiles/{invalid_profile_id}/schedules",
            data={
                "csrf": csrf,
                "name": f"invalid-contextual-{invalid_profile_id}",
                "schedule_kind": "cron",
                "cron_expression": "0 4 * * *",
                "timezone_name": "UTC",
            },
        )
        assert invalid.status_code == 422
        assert invalid.json()["detail"] == "Choose an enabled VCF Offline Depot download profile."


def test_vcf_offline_depot_marks_only_each_profiles_own_queued_download(client):
    """Verify per-row task state does not globally disable distinct profiles.

    Args:
        client: HTTP test client used to render the depot profile grid.
    """
    import html
    import json
    import re

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile

    login(client)
    with SessionLocal() as db:
        queued = VcfDepotDownloadProfile(name="queued-row", profile_type="metadata", enabled=True)
        available = VcfDepotDownloadProfile(name="available-row", profile_type="binaries", enabled=True)
        db.add_all([queued, available])
        db.flush()
        db.add(
            Job(
                id="job_queued_profile_row",
                type="vcf-depot-download",
                status=JobStatus.PENDING.value,
                created_by="admin",
                vcf_depot_profile_id=queued.id,
                task_config_json=json.dumps({"profile_id": queued.id}),
                result=json.dumps({"profile_id": queued.id, "profile_name": queued.name}),
            )
        )
        db.commit()
        queued_id, available_id = queued.id, available.id

    page = client.get("/vcf-offline-depot")
    rows_payload = page.text.split("data-profiles='", 1)[1].split("'", 1)[0]
    rows = {row["id"]: row for row in json.loads(html.unescape(rows_payload))}
    assert rows[queued_id]["download_active"] is True
    assert rows[queued_id]["active_job_id"] == "job_queued_profile_row"
    assert rows[queued_id]["can_start"] is False
    assert rows[queued_id]["start_blocker"] == rows[queued_id]["active_task_blocker"]
    assert rows[available_id]["download_active"] is False
    assert rows[available_id]["active_job_id"] == ""
    fallback = page.text.split('id="vcf-depot-profiles-fallback"', 1)[1].split("</table>", 1)[0]
    queued_markup = re.search(r"<tr>\s*<td>queued-row</td>.*?</tr>", fallback, re.DOTALL)
    assert queued_markup is not None
    queued_start = re.search(
        r'<button class="button tiny secondary"[^>]*>Start</button>', queued_markup.group()
    )
    assert queued_start is not None and " disabled" in queued_start.group()
    assert re.search(r"<td>\s*Queued\s*</td>", queued_markup.group())


def test_vcf_offline_depot_prevents_deleting_any_queued_profile(client):
    """Verify deletion checks the target against the complete profile queue.

    Args:
        client: HTTP test client used to submit the profile deletion.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        first = VcfDepotDownloadProfile(name="first-queued-delete", profile_type="metadata", enabled=True)
        second = VcfDepotDownloadProfile(name="second-queued-delete", profile_type="binaries", enabled=True)
        db.add_all([first, second])
        db.flush()
        for job_id, profile in (("job_delete_first", first), ("job_delete_second", second)):
            db.add(
                Job(
                    id=job_id,
                    type="vcf-depot-download",
                    status=JobStatus.PENDING.value,
                    created_by="admin",
                    vcf_depot_operation=True,
                    vcf_depot_profile_id=profile.id,
                    task_config_json=json.dumps({"profile_id": profile.id}),
                )
            )
        db.commit()
        second_id = second.id

    response = client.post(
        f"/vcf-offline-depot/profiles/{second_id}/delete",
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1"},
    )

    assert response.status_code == 409
    assert "job_delete_second" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.get(VcfDepotDownloadProfile, second_id) is not None


def test_vcf_download_task_refresh_includes_exclusive_operation(client):
    """Verify scoped task refresh preserves the queue-wide exclusive blocker.

    Args:
        client: HTTP test client used to request the scoped task payload.
    """
    import html
    import json
    import re

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, Setting, VcfDepotDownloadProfile
    from atlaso.app.services.vcf_offline_depot import VCF_DEPOT_TOKEN_VALUE_KEY

    login(client)
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(
            name="exclusive-blocked-profile",
            profile_type="metadata",
            enabled=True,
            status="synced",
        )
        db.add_all(
            [
                profile,
                Setting(key=VCF_DEPOT_TOKEN_VALUE_KEY, value="non-secret-refresh-fixture"),
                Job(
                    id="job_refresh_exclusive",
                    type="vcf-depot-software-id",
                    status=JobStatus.PENDING.value,
                    created_by="admin",
                    vcf_depot_operation=True,
                ),
            ]
        )
        db.commit()
        profile_id = profile.id

    response = client.get("/tasks/status", params={"task_type": "vcf-depot-download"})

    assert response.status_code == 200
    initial_start_state = next(
        state for state in response.json()["profile_start_states"] if state["profile_id"] == profile_id
    )
    assert initial_start_state == {
        "profile_id": profile_id,
        "status": "synced",
        "can_start": True,
        "start_blocker": "",
    }
    assert response.json()["active_downloads"] == []
    assert response.json()["active_exclusive_operation"] == {
        "job_id": "job_refresh_exclusive",
        "status": "pending",
        "type": "vcf-depot-software-id",
        "detail": (
            "VCFDT Software Depot ID task job_refresh_exclusive is already pending. "
            "Wait for it to finish before starting another VCFDT operation."
        ),
    }
    with SessionLocal() as db:
        token = db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY))
        assert token is not None
        db.delete(token)
        db.commit()
    refreshed = client.get("/tasks/status", params={"task_type": "vcf-depot-download"})
    assert refreshed.status_code == 200
    refreshed_start_state = next(
        state for state in refreshed.json()["profile_start_states"] if state["profile_id"] == profile_id
    )
    assert refreshed_start_state == {
        "profile_id": profile_id,
        "status": "synced",
        "can_start": False,
        "start_blocker": "Upload a Broadcom download token or activation code before starting this profile.",
    }
    page = client.get("/vcf-offline-depot")
    rows_payload = page.text.split("data-profiles='", 1)[1].split("'", 1)[0]
    row = next(
        item for item in json.loads(html.unescape(rows_payload)) if item["id"] == profile_id
    )
    assert row["download_active"] is True
    assert row["active_job_id"] == ""
    assert row["active_task_status"] == ""
    assert "job_refresh_exclusive" in row["active_task_blocker"]
    assert row["can_start"] is False
    assert row["start_blocker"] == row["active_task_blocker"]
    fallback = page.text.split('id="vcf-depot-profiles-fallback"', 1)[1].split("</table>", 1)[0]
    profile_markup = re.search(
        r"<tr>\s*<td>exclusive-blocked-profile</td>.*?</tr>", fallback, re.DOTALL
    )
    assert profile_markup is not None
    start_button = re.search(
        r'<button class="button tiny secondary"[^>]*>Start</button>', profile_markup.group()
    )
    assert start_button is not None and " disabled" in start_button.group()


def test_vcf_offline_depot_startup_recovers_interrupted_download(client):
    """Verify that vcf offline depot startup recovers interrupted download.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile
    from atlaso.app.ui import recover_interrupted_vcf_depot_download_jobs

    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="interrupted", profile_type="binaries", enabled=True, status="ready")
        queued_profile = VcfDepotDownloadProfile(name="queued-after-restart", profile_type="metadata", enabled=True, status="ready")
        db.add_all([profile, queued_profile])
        db.flush()
        db.add_all([
            Job(
                id="job_interrupted_vcfdt",
                type="vcf-depot-download",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=35,
                vcf_depot_profile_id=profile.id,
                result=json.dumps({"profile_id": profile.id, "profile_name": profile.name}),
            ),
            Job(
                id="job_queued_vcfdt",
                type="vcf-depot-download",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=0,
                vcf_depot_profile_id=queued_profile.id,
                result=json.dumps({"profile_id": queued_profile.id, "profile_name": queued_profile.name}),
            ),
        ])
        db.commit()

        assert recover_interrupted_vcf_depot_download_jobs(db) == 1
        job = db.get(Job, "job_interrupted_vcfdt")
        db.refresh(profile)
        assert job is not None
        assert job.status == JobStatus.FAILED.value
        assert job.progress_percent == 100
        assert job.finished_at is not None
        assert "restart" in (job.error or "")
        assert profile.status == "blocked"
        assert db.get(Job, "job_queued_vcfdt").status == JobStatus.PENDING.value
        assert recover_interrupted_vcf_depot_download_jobs(db) == 0


def test_vcf_offline_depot_root_runtime_wrapper_counts_as_installed(monkeypatch, tmp_path):
    """Verify that vcf offline depot root runtime wrapper counts as installed.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from pathlib import Path
    from types import SimpleNamespace

    from atlaso.app import ui
    from atlaso.app.models import VcfOfflineDepotSettings

    runtime_home = tmp_path / "active-tool"
    runtime_home.mkdir()
    (runtime_home / "vcf-download-tool").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(ui, "VCF_DEPOT_RUNTIME_TOOL_DIR", runtime_home)
    monkeypatch.setattr(ui, "filesystem_path", lambda path: Path(path))
    monkeypatch.setattr(ui, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    settings = VcfOfflineDepotSettings(tool_archive_path="/var/lib/atlaso/uploads/vcfdt.tar.gz")

    assert ui.vcf_depot_tool_installed(settings) is True


def test_vcf_offline_depot_profile_credentials_block_start_not_apply(client, tmp_path):
    """Verify that vcf offline depot profile credentials block start not apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, VcfDepotDownloadProfile, VcfOfflineDepotSettings

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.tool_version = "9.1.0"
        profile = VcfDepotDownloadProfile(
            name="vcf-install",
            profile_type="binaries",
            sku="VCF",
            vcf_version="9.1.0",
            binary_type="INSTALL",
            enabled=True,
        )
        db.add(profile)
        db.commit()
        profile_id = profile.id

    login(client)
    page = client.get("/vcf-offline-depot")
    assert page.status_code == 200
    rows_payload = page.text.split("data-profiles='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(rows_payload))
    row = next(item for item in rows if item["id"] == profile_id)
    assert row["can_start"] is False
    assert "download token or activation code" in row["start_blocker"]
    assert "Upload a Broadcom download token or activation code" in page.text

    apply_page = client.get("/appliance-apply")
    assert apply_page.status_code == 200
    review = client.get("/appliance-apply/review")
    depot_unit = next(unit for unit in review.json()["units"] if unit["id"] == "vcf_offline_depot")
    assert "requires an uploaded download token or activation-code file" not in " ".join(depot_unit["validation_errors"])

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/download",
        data={"csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 400
    assert "download token or activation code" in response.text
    with SessionLocal() as db:
        assert db.execute(select(Job).where(Job.type == "vcf-depot-download")).scalar_one_or_none() is None


def test_vcf_offline_depot_manual_profile_download_accepts_activation_code_without_token(client, tmp_path):
    """Verify that vcf offline depot manual profile download accepts activation code without token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        Job,
        Setting,
        VcfDepotDownloadProfile,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
    )

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.tool_version = "9.1.0"
        db.add(Setting(key=VCF_DEPOT_ACTIVATION_NAME_KEY, value="activation-code.txt"))
        db.add(Setting(key=VCF_DEPOT_ACTIVATION_VALUE_KEY, value="manual-secret-activation-code"))
        profile = VcfDepotDownloadProfile(
            name="vcf-install",
            profile_type="binaries",
            sku="VCF",
            vcf_version="9.1.0",
            binary_type="INSTALL",
            enabled=True,
        )
        db.add(profile)
        db.commit()
        profile_id = profile.id

    login(client)
    page = client.get("/vcf-offline-depot")
    assert "activation-code.txt" not in page.text
    assert "Download token</span>" in page.text
    assert "activation code staged" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/download",
        data={"csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "started"
    assert payload["profile_name"] == "vcf-install"
    assert payload["commands"][0]["command"][1:3] == ["binaries", "download"]
    assert "--depot-download-activation-code-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/activation-code.txt" in payload["commands"][0]["command"]
    assert "--depot-download-token-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/download-token.txt" not in payload["commands"][0]["command"]
    assert "manual-secret-activation-code" not in response.text

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "vcf-depot-download")).scalar_one()
        assert json.loads(job.task_config_json or "{}") == {"profile_id": profile_id}
        assert "configuration get --software-depot-id" not in (job.result or "")
        assert '"trigger": "manual"' in (job.result or "")
        assert '"commands"' not in (job.result or "")
        assert "--depot-download-token-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/download-token.txt" not in (job.result or "")
        assert "manual-secret-activation-code" not in (job.result or "")


def test_vcf_offline_depot_prepare_runtime_stages_saved_application_properties(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot prepare runtime stages saved application properties.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import io
    import tarfile
    from pathlib import PurePosixPath

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_NAME,
    )
    from atlaso.app.ui import prepare_vcf_depot_runtime

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive_properties = b"spring.profiles.active=depot\nlcm.depot.adapter.host=archive.example.test\n"
    tool_binary = b"#!/bin/sh\nexit 0\n"
    with tarfile.open(archive_path, "w:gz") as archive:
        binary_info = tarfile.TarInfo("vcf-download-tool-9.1.0/bin/vcf-download-tool")
        binary_info.size = len(tool_binary)
        binary_info.mode = 0o755
        archive.addfile(binary_info, io.BytesIO(tool_binary))
        properties_info = tarfile.TarInfo("vcf-download-tool-9.1.0/conf/application-prodv2.properties")
        properties_info.size = len(archive_properties)
        archive.addfile(properties_info, io.BytesIO(archive_properties))

    runtime_dir = tmp_path / "active-tool"
    monkeypatch.setattr("atlaso.app.ui.VCF_DEPOT_EXTRACT_DIR", runtime_dir)
    monkeypatch.setattr("atlaso.app.ui.VCF_DEPOT_VDT_LOG_PATH", PurePosixPath((runtime_dir / "log" / "vdt.log").as_posix()))

    saved_properties = "spring.profiles.active=depot\nlcm.depot.adapter.host=operator.example.test\ncustom.setting=true\n"
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.depot_store_path = str(tmp_path / "depot")
        db.add(Setting(key=VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY, value=saved_properties))
        db.commit()

        tool_path = prepare_vcf_depot_runtime(settings, db)

    expected_tool_home = runtime_dir / "vcf-download-tool-9.1.0"
    assert tool_path == expected_tool_home / "bin" / "vcf-download-tool"
    staged_properties = expected_tool_home / "conf" / VCF_DEPOT_APPLICATION_PROPERTIES_NAME
    assert staged_properties.read_text(encoding="utf-8") == saved_properties
    assert "archive.example.test" not in staged_properties.read_text(encoding="utf-8")


def test_vcf_offline_depot_queues_software_depot_id_task_and_persists_safe_readback(client, tmp_path, monkeypatch):
    """Verify that vcf offline depot queues software depot id task and persists safe readback.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
        VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
    )
    from atlaso.app.ui import persist_vcf_depot_metadata_from_apply, set_setting_value

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive_path.write_bytes(b"placeholder")
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.tool_version = "9.1.0"
        set_setting_value(db, VCF_DEPOT_TOKEN_NAME_KEY, "download-token.txt")
        set_setting_value(db, VCF_DEPOT_TOKEN_VALUE_KEY, "non-secret-token-fixture")
        set_setting_value(db, VCF_DEPOT_ACTIVATION_NAME_KEY, "activation-code.txt")
        set_setting_value(db, VCF_DEPOT_ACTIVATION_VALUE_KEY, "non-secret-activation-fixture")
        db.commit()

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_vcf_depot_software_id_job", lambda _job_id: None)

    response = client.post(
        "/vcf-offline-depot/software-depot-id/generate",
        data={"csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "pending"
    assert payload["task"]["type"] == "vcf-depot-software-id"
    assert payload["task"]["state"] == "pending"
    assert payload["task"]["can_start"] is False

    with SessionLocal() as db:
        persist_vcf_depot_metadata_from_apply(
            db,
            [
                {
                    "unit_id": "vcf_offline_depot",
                    "commands": [
                        {
                            "command": [
                                "atlaso-helper",
                                "vcf-offline-depot",
                                "stage-tool",
                                str(archive_path),
                            ],
                            "returncode": 0,
                            "stdout": (
                                '{"action": "stage-tool", "dry_run": false}\n'
                                '{"tool_version": "9.1.0.0100.25429019"}'
                            ),
                            "stderr": "",
                        },
                        {
                            "command": [
                                "atlaso-helper",
                                "vcf-offline-depot",
                                "generate-software-depot-id",
                            ],
                            "returncode": 0,
                            "stdout": (
                                '{"action": "generate-software-depot-id", "dry_run": false}\n'
                                '{"software_depot_id": "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"}'
                            ),
                            "stderr": "",
                        }
                    ],
                }
            ],
        )
        db.commit()

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        software_id = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)).scalar_one()
        generated_at = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY)).scalar_one()
        version_source = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_TOOL_VERSION_SOURCE_KEY)).scalar_one()
        assert settings.tool_version == "9.1.0.0100.25429019"
        assert version_source.value == "vcf-download-tool --version"
        assert software_id.value == "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"
        assert generated_at.value
        credential_keys = [
            VCF_DEPOT_TOKEN_NAME_KEY,
            VCF_DEPOT_TOKEN_VALUE_KEY,
            VCF_DEPOT_ACTIVATION_NAME_KEY,
            VCF_DEPOT_ACTIVATION_VALUE_KEY,
        ]
        assert db.scalars(select(Setting).where(Setting.key.in_(credential_keys))).all() == []


def test_vcf_offline_depot_invalidates_stale_id_only_after_successful_generation_with_failed_readback(client):
    """Verify that vcf offline depot invalidates stale id only after successful generation with failed readback.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )
    from atlaso.app.ui import persist_vcf_depot_metadata_from_apply, set_setting_value

    def persist_failure(*, stdout: str, stderr: str) -> None:
        """Persist failure.

        Args:
            stdout: Stdout supplied to the test scenario.
            stderr: Stderr supplied to the test scenario.
        """
        with SessionLocal() as db:
            persist_vcf_depot_metadata_from_apply(
                db,
                [
                    {
                        "unit_id": "vcf_offline_depot",
                        "commands": [
                            {
                                "command": ["atlaso-helper", "vcf-offline-depot", "generate-software-depot-id"],
                                "returncode": 2,
                                "stdout": stdout,
                                "stderr": stderr,
                            }
                        ],
                    }
                ],
            )
            db.commit()

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = "C:/fixtures/vcf-download-tool.tar.gz"
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, "previous-registered-id")
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY, "2026-08-05T19:19:20+00:00")
        set_setting_value(db, VCF_DEPOT_TOKEN_NAME_KEY, "download-token.txt")
        set_setting_value(db, VCF_DEPOT_TOKEN_VALUE_KEY, "non-secret-token-fixture")
        set_setting_value(db, VCF_DEPOT_ACTIVATION_NAME_KEY, "activation-code.txt")
        set_setting_value(db, VCF_DEPOT_ACTIVATION_VALUE_KEY, "non-secret-activation-fixture")
        db.commit()

    persist_failure(stdout="", stderr="VCFDT generation failed before changing the ID.")
    with SessionLocal() as db:
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)).value == "previous-registered-id"
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)) is not None
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)) is not None

    persist_failure(stdout='{"software_depot_id_invalidated": true}\n', stderr="VCFDT readback failed.")
    with SessionLocal() as db:
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)) is None
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY)) is None
        error = db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY))
        assert error.value == "VCFDT readback failed."
        credential_keys = [
            VCF_DEPOT_TOKEN_NAME_KEY,
            VCF_DEPOT_TOKEN_VALUE_KEY,
            VCF_DEPOT_ACTIVATION_NAME_KEY,
            VCF_DEPOT_ACTIVATION_VALUE_KEY,
        ]
        assert db.scalars(select(Setting).where(Setting.key.in_(credential_keys))).all() == []


def test_vcf_offline_depot_migrates_legacy_store_path(client):
    """Verify that vcf offline depot migrates legacy store path.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfOfflineDepotSettings

    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.depot_store_path = "/srv/repository"
        db.commit()

    login(client)
    page = client.get("/vcf-offline-depot")

    assert page.status_code == 200
    assert "/mnt/atlaso-vcf-offline-depot" in page.text
    assert "/srv/repository" not in page.text
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert settings.depot_store_path == "/mnt/atlaso-vcf-offline-depot"


def test_vcf_private_registry_uses_local_ca_bundle_when_ca_is_enabled(client):
    """Verify that vcf private registry uses local ca bundle when ca is enabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings

    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        ca_settings.storage_path = "/etc/atlaso/ca"
        db.commit()

    login(client)
    page = client.get("/vcf-private-registry")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert "CA bundle source" in page.text
    assert "Local CA" in page.text
    assert "Upload CA bundle" not in page.text

    response = client.post(
        "/vcf-private-registry/settings",
        data={
            "enabled": "on",
            "hostname": "registry.atlaso.internal",
            "listen_interface": "eth2",
            "port": "443",
            "harbor_project": "vcf-supervisor-services",
            "server_certificate": "registry.atlaso.internal",
            "robot_account": "robot$vcf-supervisor-services",
            "relocation_dry_run": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["ca_bundle_source"] == "local-ca"
    assert response.json()["ca_bundle_source_label"] == "Local CA"
    assert response.json()["ca_bundle_path"] == "/etc/atlaso/ca/ca-bundle.pem"
    assert response.json()["ca_bundle_available"] is True
    assert response.json()["validation_errors"] == []


def test_vcf_backups_listen_interfaces_include_vlans_not_trunks(client):
    """Verify that vcf backups listen interfaces include vlans not trunks.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VlanInterface

    with SessionLocal() as db:
        db.add(
            VlanInterface(
                name="eth1.60",
                parent_interface="eth1",
                vlan_id=60,
                ip_cidr="192.168.60.1/24",
                role="access",
                enabled=True,
            )
        )
        db.commit()

    login(client)
    page = client.get("/vcf-backups")
    assert page.status_code == 200
    assert "eth1 - access / trunk" not in page.text
    assert "eth1.60 - VLAN 60 on eth1 / access / 192.168.60.1" in page.text


def test_vcf_backups_settings_autosave_and_status_api(client):
    """Verify that vcf backups settings autosave and status api.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re

    login(client)
    page = client.get("/vcf-backups")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    user_id = re.search(r'<option value="(\d+)" selected>vcf-backup(?: \(disabled\))?</option>', page.text).group(1)
    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": "Backup-user1!", "confirm_password": "Backup-user1!", "csrf": csrf},
    )
    assert reset.status_code in {200, 303}
    response = client.post(
        "/vcf-backups/settings",
        data={
            "enabled": "on",
            "listen_interface": "eth2",
            "port": "22",
            "sftp_user_id": user_id,
            "storage_path": "/srv/vcf-backups",
            "chroot_enabled": "on",
            "allow_password_auth": "on",
            "allow_public_key_auth": "on",
            "max_sessions": "4",
            "config_path": "/etc/atlaso/ssh/sshd_config.d/atlaso-vcf-backups.conf",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "saved"
    assert response.json()["listen_interface"] == "eth2"
    assert response.json()["listen_address"] == "192.168.50.1"
    assert response.json()["sftp_username"] == "vcf-backup"
    assert response.json()["storage_path"] == "/mnt/atlaso-vcf-backups"
    assert response.json()["remote_directory"] == "/backups"
    assert response.json()["valid"] is True
    assert "# Service listener targets: 192.168.50.1:22" in response.json()["config_preview"]
    assert "Match User vcf-backup" in response.json()["config_preview"]
    assert "ForceCommand internal-sftp -d /backups" in response.json()["config_preview"]
    assert response.json()["appliance_apply_status"]["id"] == "vcf_backups"
    assert response.json()["appliance_apply_status"]["changed"] is True
    assert "enabled" in client.get("/vcf-backups").text

    raw_token = create_api_token(client, ["read:vcf-backups"])
    status = client.get("/api/v1/vcf-backups/status", headers={"Authorization": f"Bearer {raw_token}"})
    assert status.status_code == 200
    assert status.json()["listen_interface"] == "eth2"
    assert status.json()["listen_address"] == "192.168.50.1"
    assert status.json()["sftp_username"] == "vcf-backup"
    assert status.json()["storage_path"] == "/mnt/atlaso-vcf-backups"
    assert status.json()["remote_directory"] == "/backups"


def test_vcf_backups_settings_accept_multiple_listen_targets(client):
    """Verify that vcf backups settings accept multiple listen targets.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re

    login(client)
    page = client.get("/vcf-backups")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    user_id = re.search(r'<option value="(\d+)" selected>vcf-backup(?: \(disabled\))?</option>', page.text).group(1)
    response = client.post(
        "/vcf-backups/settings",
        data={
            "enabled": "on",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth0", "eth2"],
            "listen_addresses": ["192.168.49.1", "192.168.50.1"],
            "port": "22",
            "sftp_user_id": user_id,
            "chroot_enabled": "on",
            "allow_password_auth": "on",
            "allow_public_key_auth": "on",
            "max_sessions": "4",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["listen_interfaces"] == ["eth2"]
    assert payload["listen_addresses"] == ["192.168.50.1"]
    assert "# Listen interfaces: eth2" in payload["config_preview"]
    assert "# Service listener targets: 192.168.50.1:22" in payload["config_preview"]


def test_vcf_backups_disabled_disables_default_backup_user(client):
    """Verify that vcf backups disabled disables default backup user.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    login(client)
    page = client.get("/vcf-backups")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    user_id = re.search(r'<option value="(\d+)" selected>vcf-backup(?: \(disabled\))?</option>', page.text).group(1)
    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": "Backup-user1!", "confirm_password": "Backup-user1!", "csrf": csrf},
    )
    assert reset.status_code in {200, 303}

    disabled_service = client.post(
        "/vcf-backups/settings",
        data={
            "listen_interface": "eth2",
            "port": "22",
            "sftp_user_id": user_id,
            "chroot_enabled": "on",
            "allow_password_auth": "on",
            "allow_public_key_auth": "on",
            "max_sessions": "4",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert disabled_service.status_code == 200
    with SessionLocal() as db:
        backup_user = db.execute(select(User).where(User.username == "vcf-backup")).scalar_one()
        assert backup_user.enabled is False
        assert backup_user.os_sync_status == "pending"
    review = client.get("/appliance-apply/review")
    local_users_unit = next(unit for unit in review.json()["units"] if unit["id"] == "local_users")
    assert local_users_unit["label"] == "Local Users"
    assert "pending OS passwords" in " ".join(local_users_unit["summary"])


def test_vcf_backups_apply_task_captures_sftp_config(client):
    """Verify that vcf backups apply task captures sftp config.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import re

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/vcf-backups")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    user_id = re.search(r'<option value="(\d+)" selected>vcf-backup(?: \(disabled\))?</option>', page.text).group(1)
    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": "Backup-user1!", "confirm_password": "Backup-user1!", "csrf": csrf},
    )
    assert reset.status_code in {200, 303}
    settings_response = client.post(
        "/vcf-backups/settings",
        data={
            "enabled": "on",
            "listen_interface": "eth2",
            "port": "22",
            "sftp_user_id": user_id,
            "chroot_enabled": "on",
            "allow_password_auth": "on",
            "allow_public_key_auth": "on",
            "max_sessions": "4",
            "csrf": csrf,
        },
    )
    assert settings_response.status_code == 200
    page = client.get("/vcf-backups")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_backups"})

    assert_apply_redirect(response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "vcf-backups" in (job.result or "")
        assert "internal-sftp" in (job.result or "")


def test_appliance_apply_unit_keeps_raw_config_for_helper_staging():
    """Verify that appliance apply unit keeps raw config for helper staging."""
    from atlaso.app.ui import make_appliance_apply_unit

    unit = make_appliance_apply_unit(
        unit_id="vcf_backups",
        label="VCF Backups",
        page_url="/vcf-backups",
        context={},
        summary=["service enabled"],
        validation_errors=[],
        config_path="/etc/ssh/sshd_config.d/atlaso-vcf-backups.conf",
        config_preview="Match User vcf-backup\n  PasswordAuthentication yes\n  ForceCommand internal-sftp -d /backups\n",
        baseline=None,
    )

    assert "PasswordAuthentication yes" in unit["raw_config_preview"]
    assert "[redacted sensitive line]" in unit["config_preview"]
    assert "PasswordAuthentication yes" not in unit["config_preview"]


def test_appliance_apply_unit_separates_secret_staging_from_snapshot_change_marker():
    """Verify that appliance apply unit separates secret staging from snapshot change marker."""
    from atlaso.app.ui import _redact_task_value, make_appliance_apply_unit

    current = make_appliance_apply_unit(
        unit_id="ldap",
        label="Managed LDAP",
        page_url="/ldap",
        context={},
        summary=["1 user"],
        validation_errors=[],
        config_path="/var/lib/atlaso/apply/ldap/atlaso-ldap.json",
        config_preview='{"payload_b64":"[pending]","password":"[pending]"}',
        raw_config_preview='{"payload_b64":"c2xhcGNhdC1wYXNzd29yZC1oYXNoZXM=","password":"VeryStrong1!Directory"}',
        snapshot_marker={"pending_password_user_ids": [7], "recovery_sha256": "archive-sha"},
        baseline=None,
    )
    baseline = {"snapshot_hash": current["snapshot_hash"], "config_preview": current["config_preview"]}
    rotated = make_appliance_apply_unit(
        unit_id="ldap",
        label="Managed LDAP",
        page_url="/ldap",
        context={},
        summary=["1 user"],
        validation_errors=[],
        config_path="/var/lib/atlaso/apply/ldap/atlaso-ldap.json",
        config_preview='{"payload_b64":"[pending]","password":"[pending]"}',
        raw_config_preview='{"payload_b64":"bmV3LXNsYXBjYXQtYXJjaGl2ZQ==","password":"AnotherStrong1!Directory"}',
        snapshot_marker={"pending_password_user_ids": [7], "recovery_sha256": "new-archive-sha"},
        baseline=baseline,
    )

    assert current["raw_config_preview"] != current["config_preview"]
    assert "c2xhcGNhdC" not in current["config_preview"]
    assert "VeryStrong1!Directory" not in current["config_preview"]
    assert "payload_b64" in current["config_preview"]
    assert "[redacted]" in current["config_preview"]
    assert rotated["changed"] is True
    assert _redact_task_value({"payload_b64": "c2xhcGNhdC1wYXNzd29yZC1oYXNoZXM="}) == {"payload_b64": "[redacted]"}


def test_disabled_ldap_apply_keeps_staged_user_password_pending(monkeypatch, tmp_path):
    """Verify that disabled ldap apply keeps staged user password pending.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from types import SimpleNamespace

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.models import LdapSettings, LdapUser
    from atlaso.app.services.ldap import (
        clear_pending_ldap_password,
        has_pending_ldap_password,
        stage_ldap_user_password,
    )
    from atlaso.app.ui import execute_appliance_apply_unit

    settings = LdapSettings(enabled=False)
    user = LdapUser(id=98765, uid="pending-user", surname="User", display_name="Pending User", enabled=True)
    stage_ldap_user_password(user, "VeryStrong1!Directory", settings)

    class SuccessfulLdapAdapter:
        """Represent successful ldap adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        @staticmethod
        def validate_ldap_config(path):
            """Validate ldap config.

            Args:
                path: Filesystem or URL path to read, validate, or update.

            Returns:
                The validate ldap config result.
            """
            return AdapterResult(["ldap", "validate", path], False)

        @staticmethod
        def apply_ldap_config(path):
            """Update ldap config.

            Args:
                path: Filesystem or URL path to read, validate, or update.

            Returns:
                The apply ldap config result.
            """
            return AdapterResult(["ldap", "apply", path], False)

    staged_path = tmp_path / "ldap" / "atlaso-ldap.json"
    monkeypatch.setattr("atlaso.app.ui.LDAP_STAGED_CONFIG_PATH", str(staged_path))
    unit = {
        "id": "ldap",
        "label": "Managed LDAP",
        "context": {"ldap_settings": settings, "ldap_organizations": [SimpleNamespace(users=[user])]},
        "raw_config_preview": "{}",
        "summary": ["service disabled"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/var/lib/atlaso/apply/ldap/atlaso-ldap.json",
        "config_preview": "{}",
        "config_diff": "",
    }
    try:
        result = execute_appliance_apply_unit(unit, adapter=SuccessfulLdapAdapter())
        assert result["success"] is True
        assert user.password_status == "pending_apply"
        assert has_pending_ldap_password(user) is True
        assert not staged_path.exists()
    finally:
        clear_pending_ldap_password(user)



def test_global_appliance_apply_tracks_baselines_diffs_and_skips(client):
    """Verify that global appliance apply tracks baselines diffs and skips.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep, Setting

    login(client)
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "appliance-apply-modal" in page.text
    assert 'class="button primary hidden" type="submit" data-appliance-apply-submit' in page.text
    assert "data-apply-submit-tracker" not in page.text
    direct = client.get("/ui/management/appliance-apply", follow_redirects=False)
    assert direct.status_code == 303
    assert direct.headers["location"] == "/ui/management/dashboard#appliance-apply-review"
    review = client.get("/appliance-apply/review")
    assert review.status_code == 200
    firewall_review = next(unit for unit in review.json()["units"] if unit["id"] == "firewall")
    assert firewall_review["has_baseline"] is False
    assert firewall_review["selected"] is True
    assert firewall_review["connection_warnings"] == []
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    empty_response = client.post("/appliance-apply", data={"csrf": csrf})
    assert empty_response.status_code == 422
    assert "Select at least one appliance change to submit." in empty_response.text

    baseline_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "firewall"}, follow_redirects=False)
    assert baseline_response.status_code == 303
    assert baseline_response.headers["location"].startswith("/ui/management/tasks?job_id=job_")
    with SessionLocal() as db:
        baseline = db.execute(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).scalar_one()
        assert '"firewall"' in baseline.value
        baseline_job = db.execute(select(Job).where(Job.type == "appliance-apply").order_by(Job.created_at.desc())).scalars().first()
        assert baseline_job is not None
        steps = db.scalars(select(JobStep).where(JobStep.job_id == baseline_job.id)).all()
        assert [(step.component_key, step.status) for step in steps] == [("firewall", "succeeded")]

    firewall_page = client.get("/firewall")
    csrf = firewall_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    group_response = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "create",
            "group_name": "Global apply clients",
            "group_entries": "192.168.50.0/24",
        },
    )
    assert group_response.status_code == 200

    created = client.post(
        "/firewall/rules",
        data={
            "name": "allow-global-apply-test",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "group:custom:global-apply-clients",
            "destination": "any",
            "destination_port": "8443",
            "interface_name": "eth2",
            "priority": "35",
            "enabled": "on",
            "description": "global apply diff",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    changed_review = client.get("/appliance-apply/review")
    assert changed_review.status_code == 200
    changed_firewall = next(unit for unit in changed_review.json()["units"] if unit["id"] == "firewall")
    assert "--- last-applied/firewall" in changed_firewall["config_diff"]
    assert "+++ current/firewall" in changed_firewall["config_diff"]
    assert "allow-global-apply-test" in changed_firewall["config_diff"]
    assert "/static/vendor/prism/prism-core.min.js" in page.text
    assert "/static/vendor/prism/prism-diff.min.js" in page.text
    assert "Prism.manual = true" in page.text
    assert "highlightConfigPreviews" in client.get("/static/app.js").text

    skipped_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"}, follow_redirects=False)
    assert skipped_response.status_code == 303
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply").order_by(Job.created_at.desc())).scalars().first()
        assert job is not None
        assert "skipped_changed_units" in (job.result or "")
        assert '"unit_id": "firewall"' in (job.result or "")


@pytest.mark.parametrize(
    ("selected_unit", "depot_user_status", "expected_units"),
    [
        ("public_services", "pending", ["local_users", "public_services"]),
        ("vcf_offline_depot", "pending", ["local_users", "vcf_offline_depot"]),
        ("public_services", "applied", ["public_services"]),
    ],
)
def test_depot_submission_includes_only_relevant_local_user_dependency(
    client,
    monkeypatch,
    selected_unit,
    depot_user_status,
    expected_units,
):
    """Verify that depot submission includes only relevant local user dependency.

    Args:
        client: Client used to invoke the external or application interface.
        monkeypatch: Pytest fixture used to replace dependencies.
        selected_unit: Selected unit supplied by the caller.
        depot_user_status: Depot user status supplied by the caller.
        expected_units: Expected units supplied by the caller.
    """
    import json
    from types import SimpleNamespace

    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep, User

    def unit(unit_id, label, *, changed, context=None):
        """Return unit.

        Args:
            unit_id: Stable identifier of the associated unit resource.
            label: Human-readable label used to identify the result.
            changed: Changed supplied to the test scenario.
            context: Operation context providing related state and metadata.
        """
        return {
            "id": unit_id,
            "label": label,
            "changed": changed,
            "context": context or {},
            "summary": [f"{label} desired state"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": f"/var/lib/atlaso/apply/{unit_id}.conf",
            "config_preview": f"{unit_id}=configured",
            "raw_config_preview": f"{unit_id}=configured",
            "config_diff": f"+{unit_id}=configured" if changed else "",
            "snapshot_hash": f"{unit_id}-snapshot",
        }

    depot_user = User(
        id=41,
        username=f"depot-dependency-{selected_unit}-{depot_user_status}",
        enabled=True,
        os_sync_status=depot_user_status,
        os_unlock_requested_at=None,
    )
    units = [
        unit(
            "local_users",
            "Local Users",
            changed=True,
            context={"local_users": [depot_user]},
        ),
        unit(
            "vcf_offline_depot",
            "VCF Offline Depot",
            changed=selected_unit == "vcf_offline_depot",
            context={
                "vcf_depot_settings": SimpleNamespace(
                    enabled=True,
                    allow_unauthenticated_access=False,
                    http_user_id=depot_user.id,
                )
            },
        ),
        unit("public_services", "Public Services", changed=selected_unit == "public_services"),
    ]
    started_jobs = []
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: units)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda job_id: started_jobs.append(job_id))
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": selected_unit},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert json.loads(job.result or "{}")["selected_units"] == expected_units
        steps = db.scalars(select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)).all()
        assert [step.component_key for step in steps] == expected_units
    assert started_jobs == [job.id]


@pytest.mark.parametrize(
    ("nts_server_enabled", "ca_changed", "ldap_changes_pending", "expected_units"),
    [
        (True, True, False, ["ca", "ntpd"]),
        (True, False, False, ["ca", "ntpd"]),
        (False, True, False, ["ntpd"]),
        (True, True, True, ["ca", "dnsmasq", "firewall", "ldap", "ntpd"]),
    ],
)
def test_nts_submission_includes_ca_material_dependency(
    client,
    monkeypatch,
    nts_server_enabled,
    ca_changed,
    ldap_changes_pending,
    expected_units,
):
    """Verify that nts submission includes ca material dependency.

    Args:
        client: Client used to invoke the external or application interface.
        monkeypatch: Pytest fixture used to replace dependencies.
        nts_server_enabled: Nts server enabled supplied by the caller.
        ca_changed: Ca changed supplied by the caller.
        ldap_changes_pending: Ldap changes pending supplied by the caller.
        expected_units: Expected units supplied by the caller.
    """
    import json
    from types import SimpleNamespace

    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep

    def unit(unit_id, label, *, changed, context=None):
        """Return unit.

        Args:
            unit_id: Stable identifier of the associated unit resource.
            label: Human-readable label used to identify the result.
            changed: Changed supplied to the test scenario.
            context: Operation context providing related state and metadata.
        """
        return {
            "id": unit_id,
            "label": label,
            "changed": changed,
            "context": context or {},
            "summary": [f"{label} desired state"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": f"/var/lib/atlaso/apply/{unit_id}.conf",
            "config_preview": f"{unit_id}=configured",
            "raw_config_preview": f"{unit_id}=configured",
            "config_diff": f"+{unit_id}=configured" if changed else "",
            "snapshot_hash": f"{unit_id}-snapshot",
        }

    units = [
        unit("ca", "Certificate Authority", changed=ca_changed),
        unit("dnsmasq", "DNS / DHCP", changed=ldap_changes_pending),
        unit("firewall", "Firewall", changed=ldap_changes_pending),
        unit(
            "ldap",
            "Managed LDAP",
            changed=ldap_changes_pending,
            context={"ldap_settings": SimpleNamespace(enabled=ldap_changes_pending)},
        ),
        unit(
            "ntpd",
            "NTP / NTS",
            changed=True,
            context={"ntp_settings": SimpleNamespace(nts_server_enabled=nts_server_enabled)},
        ),
    ]
    started_jobs = []
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: units)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda job_id: started_jobs.append(job_id))

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "ntpd"},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert json.loads(job.result or "{}")["selected_units"] == expected_units
        steps = db.scalars(select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)).all()
        assert [step.component_key for step in steps] == expected_units
    assert started_jobs == [job.id]


def test_appliance_apply_connection_warnings_detect_management_address_and_certificate_changes():
    """Verify that appliance apply connection warnings detect management address and certificate changes."""
    import json

    from atlaso.app.ui import (
        MANAGEMENT_CERTIFICATE_CONNECTION_WARNING,
        appliance_apply_connection_warnings,
    )

    previous_network = "\n".join(
        [
            "[physical_interfaces]",
            "interface=eth0",
            "  role=management",
            "  ipv4_method=static",
            "  ip_cidr=192.168.1.10/24",
            "  ipv6_cidr=",
        ]
    )
    current_network = previous_network.replace("192.168.1.10/24", "192.168.1.20/24")
    network_warnings = appliance_apply_connection_warnings(
        "network",
        current_network,
        {"config_preview": previous_network},
    )
    assert len(network_warnings) == 1
    assert "from 192.168.1.10/24 to 192.168.1.20/24" in network_warnings[0]
    assert "browser connection will be lost" in network_warnings[0]

    previous_network_gateway = previous_network + "\n  gateway=192.168.1.1"
    current_network_gateway = previous_network + "\n  gateway=192.168.1.254"
    gateway_warnings = appliance_apply_connection_warnings(
        "network",
        current_network_gateway,
        {"config_preview": previous_network_gateway},
    )
    assert len(gateway_warnings) == 1
    assert "management IPv4 gateway from 192.168.1.1 to 192.168.1.254" in gateway_warnings[0]

    previous_settings = json.dumps(
        {
            "management_https_enabled": True,
            "management_https_cert_path": "/etc/atlaso/https/certs/appliance-old.crt",
            "management_https_key_path": "/etc/atlaso/https/certs/appliance-old.key",
        }
    )
    current_settings = previous_settings.replace("appliance-old", "appliance-new")
    assert appliance_apply_connection_warnings(
        "appliance_settings",
        current_settings,
        {"config_preview": previous_settings},
    ) == [MANAGEMENT_CERTIFICATE_CONNECTION_WARNING]

    previous_ca = json.dumps(
        {
            "certificates": [
                {
                    "managed_owner": "appliance:https",
                    "common_name": "atlaso.example",
                    "fingerprint": "old-fingerprint",
                    "certificate_pem": "old-certificate",
                    "cert_path": "/etc/atlaso/https/certs/appliance.crt",
                    "key_path": "/etc/atlaso/https/certs/appliance.key",
                    "chain_path": "/etc/atlaso/https/certs/appliance-chain.pem",
                }
            ]
        }
    )
    current_ca = previous_ca.replace("old-fingerprint", "new-fingerprint").replace("old-certificate", "new-certificate")
    assert appliance_apply_connection_warnings(
        "ca",
        current_ca,
        {"config_preview": previous_ca},
    ) == [MANAGEMENT_CERTIFICATE_CONNECTION_WARNING]


def test_appliance_apply_carries_explicit_vcf_depot_id_refresh_intent_to_execution(client, monkeypatch):
    """Verify that appliance apply carries explicit vcf depot id refresh intent to execution.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    run_appliance_apply_job = ui.run_appliance_apply_job
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "selected_units": "vcf_offline_depot",
            "refresh_vcf_depot_software_depot_id": "true",
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    job_id = response.json()["job_id"]
    with SessionLocal() as db:
        submitted_job = db.get(Job, job_id)
        assert json.loads(submitted_job.result)["refresh_vcf_depot_software_depot_id"] is True

    received_refresh_intent: list[bool] = []

    def execute(unit, *, adapter=None, db=None):
        """Run operation.

        Args:
            unit: Unit supplied to the test scenario.
            adapter: Adapter supplied to the test scenario.
            db: Active database session supplied by the runner.


        Returns:
            The execute result.
        """
        received_refresh_intent.append(bool(unit.get("refresh_vcf_depot_software_depot_id")))
        return {
            "unit_id": unit["id"],
            "label": unit["label"],
            "success": True,
            "status": "valid",
            "dry_run": True,
            "commands": [],
            "summary": unit["summary"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": unit["config_path"],
            "config_preview": unit["config_preview"],
            "config_diff": unit["config_diff"],
        }

    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    run_appliance_apply_job(job_id)

    assert received_refresh_intent == [True]
    with SessionLocal() as db:
        completed_job = db.get(Job, job_id)
        assert completed_job.status == "succeeded"


def test_vcf_depot_software_id_task_queues_for_immediate_execution(client, monkeypatch):
    """Verify that vcf depot software id task queues for immediate execution.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import get_vcf_offline_depot_settings_row

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        get_vcf_offline_depot_settings_row(db).tool_archive_path = "/var/lib/atlaso/vcfDownloadTool/test.tar.gz"
        db.commit()
    started_jobs: list[str] = []
    monkeypatch.setattr(ui, "run_vcf_depot_software_id_job", lambda job_id: started_jobs.append(job_id))

    response = client.post(
        "/vcf-offline-depot/software-depot-id/generate",
        data={"csrf": csrf},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    queued = response.json()["task"]
    assert queued["status"] == "pending"
    assert queued["state"] == "pending"
    assert queued["type"] == "vcf-depot-software-id"
    assert queued["type_label"] == "VCFDT Software Depot ID"
    assert queued["can_start"] is False
    assert started_jobs == [queued["id"]]
    assert [step["label"] for step in queued["_children"]] == [
        "Stage VCF Download Tool",
        "Apply application properties",
        "Apply VMware CEIP preference",
        "Generate and read back Software Depot ID",
    ]


def test_vcf_depot_software_id_submission_rejects_active_profile_download(client, monkeypatch):
    """Verify that vcf depot software id submission rejects active profile download.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.ui import get_vcf_offline_depot_settings_row

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        get_vcf_offline_depot_settings_row(db).tool_archive_path = "/var/lib/atlaso/vcfDownloadTool/test.tar.gz"
        db.add(
            Job(
                id="job_active_vcfdt_download",
                type="vcf-depot-download",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=0,
                result="{}",
            )
        )
        db.commit()
    monkeypatch.setattr(ui, "run_vcf_depot_software_id_job", lambda _job_id: None)

    response = client.post(
        "/vcf-offline-depot/software-depot-id/generate",
        data={"csrf": csrf},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 409
    assert response.json()["job_id"] == "job_active_vcfdt_download"
    assert "VCF Depot Download" in response.json()["detail"]


def test_vcf_depot_appliance_apply_submission_rejects_active_software_id_task(client, monkeypatch):
    """Verify that vcf depot appliance apply submission rejects active software id task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_active_vcfdt_identity",
                type="vcf-depot-software-id",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=0,
                result="{}",
            )
        )
        db.commit()
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "vcf_offline_depot"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 409
    assert "job_active_vcfdt_identity" in response.json()["detail"]
    assert "VCFDT Software Depot ID" in response.json()["detail"]


def test_queued_vcf_depot_software_id_task_rejects_cancellation(client, monkeypatch):
    """Verify queued identity replacement remains guarded against a claim race.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.ui import get_vcf_offline_depot_settings_row

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        get_vcf_offline_depot_settings_row(db).tool_archive_path = "/var/lib/atlaso/vcfDownloadTool/test.tar.gz"
        db.commit()
    monkeypatch.setattr(ui, "run_vcf_depot_software_id_job", lambda _job_id: None)
    queued = client.post(
        "/vcf-offline-depot/software-depot-id/generate",
        data={"csrf": csrf},
        headers={"Accept": "application/json"},
    ).json()["task"]

    response = client.post(f"/tasks/{queued['id']}/cancel", data={"csrf": csrf})

    assert response.status_code == 409
    assert "cannot be cancelled" in response.json()["detail"]
    service_guide = Path("docs/services/vcf-offline-depot.md").read_text(encoding="utf-8")
    agent_policy = Path("docs/contribute/agent-policies.md").read_text(encoding="utf-8")
    assert "Software Depot ID tasks are non-cancellable" in service_guide
    assert "Software Depot ID identity tasks are non-cancellable" in agent_policy
    assert "queued identity task can be cancelled" not in service_guide
    assert "Pending identity tasks may be" not in agent_policy
    with SessionLocal() as db:
        job = db.get(Job, queued["id"])
        assert job.status == JobStatus.PENDING.value


def test_running_vcf_depot_software_id_task_rejects_cancellation(client, monkeypatch):
    """Verify that running vcf depot software id task rejects cancellation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.ui import get_vcf_offline_depot_settings_row

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        get_vcf_offline_depot_settings_row(db).tool_archive_path = "/var/lib/atlaso/vcfDownloadTool/test.tar.gz"
        db.commit()
    monkeypatch.setattr(ui, "run_vcf_depot_software_id_job", lambda _job_id: None)
    queued = client.post(
        "/vcf-offline-depot/software-depot-id/generate",
        data={"csrf": csrf},
        headers={"Accept": "application/json"},
    ).json()["task"]
    with SessionLocal() as db:
        job = db.get(Job, queued["id"])
        job.status = JobStatus.RUNNING.value
        db.commit()

    status_response = client.get(f"/tasks/{queued['id']}/status")
    cancel_response = client.post(f"/tasks/{queued['id']}/cancel", data={"csrf": csrf})

    assert status_response.status_code == 200
    assert status_response.json()["task"]["can_cancel"] is False
    assert cancel_response.status_code == 409
    assert "cannot be cancelled" in cancel_response.json()["detail"]
    with SessionLocal() as db:
        assert db.get(Job, queued["id"]).status == JobStatus.RUNNING.value


def test_running_vcf_depot_download_rejects_cancellation(client):
    """Verify that a running VCFDT profile process remains guarded until it exits.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="running-cancel-guard", profile_type="metadata", enabled=True)
        db.add(profile)
        db.flush()
        job_id = "job_running_vcfdt_download_cancel_guard"
        job = Job(
            id=job_id,
            type="vcf-depot-download",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            vcf_depot_operation=True,
            vcf_depot_profile_id=profile.id,
            task_config_json=json.dumps({"profile_id": profile.id}),
            result=json.dumps({"profile_id": profile.id, "profile_name": profile.name}),
        )
        db.add(job)
        db.commit()

    status_response = client.get(f"/tasks/{job_id}/status")
    cancel_response = client.post(f"/tasks/{job_id}/cancel", data={"csrf": csrf})

    assert status_response.status_code == 200
    assert status_response.json()["task"]["can_cancel"] is False
    assert cancel_response.status_code == 409
    assert "cannot be cancelled" in cancel_response.json()["detail"]
    with SessionLocal() as db:
        assert db.get(Job, job_id).status == JobStatus.RUNNING.value


def test_queued_vcf_depot_download_can_be_cancelled_before_claim(client):
    """Verify the atomic pending-only cancellation remains available.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile
    from atlaso.app.services.vcf_depot_downloads import enqueue_vcf_depot_download

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(
            name="pending-cancel-guard",
            profile_type="metadata",
            enabled=True,
            status="synced",
        )
        db.add(profile)
        db.flush()
        queued = enqueue_vcf_depot_download(
            db,
            profile=profile,
            actor="admin",
            trigger="manual",
            job_id="job_pending_vcfdt_download_cancel_guard",
        )
        job_id = queued.id
        profile_id = profile.id
        db.commit()

    cancel_response = client.post(f"/tasks/{job_id}/cancel", data={"csrf": csrf})

    assert cancel_response.status_code == 200
    assert cancel_response.json()["task"]["status"] == JobStatus.CANCELLED.value
    with SessionLocal() as db:
        assert db.get(Job, job_id).status == JobStatus.CANCELLED.value
        assert db.get(VcfDepotDownloadProfile, profile_id).status == "synced"
    refresh = client.get("/tasks/status", params={"task_type": "vcf-depot-download"})
    refreshed_state = next(
        state for state in refresh.json()["profile_start_states"] if state["profile_id"] == profile_id
    )
    assert refreshed_state["status"] == "synced"
    fallback = client.get("/vcf-offline-depot").text.split(
        'id="vcf-depot-profiles-fallback"', 1
    )[1].split("</table>", 1)[0]
    profile_markup = re.search(
        r"<tr>\s*<td>pending-cancel-guard</td>.*?</tr>", fallback, re.DOTALL
    )
    assert profile_markup is not None
    assert re.search(r"<td>\s*Succeeded\s*</td>", profile_markup.group())


def test_vcf_depot_software_id_runner_persists_raw_metadata_before_task_redaction(client, monkeypatch):
    """Verify that vcf depot software id runner persists raw metadata before task redaction.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    raw_command = ["vcf-download-tool", "credential-value"]
    raw_result = {
        "unit_id": "vcf_offline_depot",
        "label": "VCF Offline Depot",
        "success": True,
        "status": "succeeded",
        "dry_run": False,
        "commands": [
            {"command": ["atlaso-helper", "stage-tool"], "returncode": 0, "stdout": "staged", "stderr": ""},
            {"command": ["atlaso-helper", "apply-properties"], "returncode": 0, "stdout": "applied", "stderr": ""},
            {"command": ["atlaso-helper", "apply-ceip"], "returncode": 0, "stdout": "applied", "stderr": ""},
            {"command": raw_command, "returncode": 0, "stdout": '{"software_depot_id":"generated-id"}', "stderr": ""},
        ],
        "summary": ["software depot ID generated"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
    }
    persisted_commands: list[list[str]] = []
    monkeypatch.setattr(ui, "appliance_apply_status", lambda _db, _unit_id: {"id": "vcf_offline_depot"})
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", lambda _unit, **_kwargs: raw_result)
    def persist_readback(db, results):
        """Persist readback.

        Args:
            db: Active database session.
            results: Results supplied by the caller.
        """
        persisted_commands.append(results[0]["commands"][-1]["command"])
        ui.set_setting_value(db, ui.VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, "generated-id")

    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", persist_readback)
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_vcfdt_id_runner",
                type="vcf-depot-software-id",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=0,
                result=json.dumps({"state": "pending"}),
            )
        )
        db.commit()

    ui.run_vcf_depot_software_id_job("job_vcfdt_id_runner")

    assert persisted_commands == [raw_command]
    with SessionLocal() as db:
        completed = db.get(Job, "job_vcfdt_id_runner")
        assert completed.status == "succeeded"
        assert "credential-value" not in completed.result
        assert "Software Depot ID generated and saved." in completed.result
        assert "generated-id" in completed.result
        assert [step.status for step in completed.steps] == ["succeeded"] * 4


def test_vcf_depot_software_id_runner_fails_when_id_is_not_persisted(client, monkeypatch):
    """Verify that vcf depot software id runner fails when id is not persisted.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    raw_result = {
        "unit_id": "vcf_offline_depot",
        "label": "VCF Offline Depot",
        "success": True,
        "status": "succeeded",
        "commands": [
            {"returncode": 0},
            {"returncode": 0},
            {"returncode": 0},
            {"returncode": 0},
        ],
    }
    monkeypatch.setattr(ui, "appliance_apply_status", lambda _db, _unit_id: {"id": "vcf_offline_depot"})
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", lambda _unit, **_kwargs: raw_result)
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda _db, _results: None)
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_vcfdt_missing_id",
                type="vcf-depot-software-id",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=0,
                result=json.dumps({"state": "pending"}),
            )
        )
        db.commit()

    ui.run_vcf_depot_software_id_job("job_vcfdt_missing_id")

    with SessionLocal() as db:
        completed = db.get(Job, "job_vcfdt_missing_id")
        assert completed.status == JobStatus.FAILED.value
        assert "without a new persisted Software Depot ID" in completed.result
        assert completed.steps[-1].status == JobStatus.FAILED.value


def test_vcf_depot_software_id_startup_reconciles_runtime_identity_before_failing_jobs(client, monkeypatch):
    """Verify that vcf depot software id startup reconciles runtime identity before failing jobs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, Setting
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )
    from atlaso.app.ui import (
        SystemAdapter,
        recover_interrupted_vcf_depot_software_id_jobs,
        set_setting_value,
    )

    monkeypatch.setattr(
        SystemAdapter,
        "read_vcf_offline_depot_software_depot_id",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "vcf-offline-depot", "read-software-depot-id"],
            dry_run=False,
            stdout='{"software_depot_id":"runtime-id"}',
        ),
    )

    with SessionLocal() as db:
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, "previous-id")
        set_setting_value(db, VCF_DEPOT_TOKEN_VALUE_KEY, "token-fixture")
        set_setting_value(db, VCF_DEPOT_ACTIVATION_VALUE_KEY, "activation-fixture")
        db.add(
            Job(
                id="job_vcfdt_id_running",
                type="vcf-depot-software-id",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=30,
                result=json.dumps({"state": "running"}),
            )
        )
        db.commit()

        assert recover_interrupted_vcf_depot_software_id_jobs(db) == 1
        running = db.get(Job, "job_vcfdt_id_running")
        assert running.status == JobStatus.FAILED.value
        assert running.progress_percent == 100
        assert "restart" in (running.error or "")
        assert "reconciled" in (running.error or "")
        assert db.scalar(select(Setting.value).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)) == "runtime-id"
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)) is None
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_ACTIVATION_VALUE_KEY)) is None


def test_vcf_depot_software_id_startup_invalidates_unverifiable_runtime_identity(client, monkeypatch):
    """Verify that vcf depot software id startup invalidates unverifiable runtime identity.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, Setting
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )
    from atlaso.app.ui import (
        SystemAdapter,
        recover_interrupted_vcf_depot_software_id_jobs,
        set_setting_value,
    )

    monkeypatch.setattr(
        SystemAdapter,
        "read_vcf_offline_depot_software_depot_id",
        lambda _self: AdapterResult(
            command=["atlaso-helper", "vcf-offline-depot", "read-software-depot-id"],
            dry_run=False,
            stderr="readback unavailable",
            returncode=2,
        ),
    )

    with SessionLocal() as db:
        set_setting_value(db, VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY, "stale-id")
        set_setting_value(db, VCF_DEPOT_TOKEN_VALUE_KEY, "token-fixture")
        db.add(
            Job(
                id="job_vcfdt_id_unverifiable",
                type="vcf-depot-software-id",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=30,
                result=json.dumps({"state": "running"}),
            )
        )
        db.commit()

        assert recover_interrupted_vcf_depot_software_id_jobs(db) == 1
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY)) is None
        assert db.scalar(select(Setting).where(Setting.key == VCF_DEPOT_TOKEN_VALUE_KEY)) is None
        error = db.scalar(select(Setting.value).where(Setting.key == VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY))
        assert "could not be verified" in (error or "")


def test_successful_command_stderr_is_not_reported_as_task_failure():
    """Verify that successful command stderr is not reported as task failure."""
    from atlaso.app.ui import _task_failure_messages

    success = {"commands": [{"returncode": 0, "stderr": "nginx syntax is ok"}]}
    failure = {"commands": [{"returncode": 1, "stderr": "nginx syntax failed"}]}

    assert _task_failure_messages(success) == []
    assert _task_failure_messages(failure) == ["nginx syntax failed"]


def test_vcf_depot_software_id_metadata_survives_apply_output_redaction():
    """Verify that vcf depot software id metadata survives apply output redaction."""
    from atlaso.app.ui import apply_output_excerpt, helper_json_payload_with_key

    output = json.dumps(
        {
            "vcf_offline_depot": "software depot ID generated",
            "software_depot_id": "8c9506c6-7bdf-44d5-b2e9-50d829d66b99",
        }
    )

    redacted = apply_output_excerpt(output)

    assert helper_json_payload_with_key(redacted, "software_depot_id")["software_depot_id"] == (
        "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"
    )


def test_recover_interrupted_appliance_apply_jobs_marks_active_tasks_failed(client):
    """Verify that recover interrupted appliance apply jobs marks active tasks failed.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep
    from atlaso.app.ui import recover_interrupted_appliance_apply_jobs

    with SessionLocal() as db:
        db.add_all(
            [
                Job(
                    id="job_pending_apply",
                    type="appliance-apply",
                    status=JobStatus.PENDING.value,
                    created_by="admin",
                    progress_percent=0,
                    result=json.dumps({"selected_units": ["firewall"]}),
                ),
                Job(
                    id="job_running_apply",
                    type="appliance-apply",
                    status=JobStatus.RUNNING.value,
                    created_by="admin",
                    progress_percent=40,
                    result=json.dumps({"selected_units": ["vcf_offline_depot"]}),
                ),
                Job(
                    id="job_unrelated_download",
                    type="vcf-depot-download",
                    status=JobStatus.RUNNING.value,
                    created_by="admin",
                    progress_percent=40,
                    result="{}",
                ),
            ]
        )
        db.add_all(
            [
                JobStep(
                    id="job_pending_apply:firewall",
                    job_id="job_pending_apply",
                    component_key="firewall",
                    label="Firewall",
                    position=1,
                    status=JobStatus.PENDING.value,
                    result="{}",
                ),
                JobStep(
                    id="job_running_apply:vcf_offline_depot",
                    job_id="job_running_apply",
                    component_key="vcf_offline_depot",
                    label="VCF Offline Depot",
                    position=1,
                    status=JobStatus.RUNNING.value,
                    result="{}",
                ),
            ]
        )
        db.commit()

        assert recover_interrupted_appliance_apply_jobs(db) == 2

        apply_jobs = db.scalars(select(Job).where(Job.type == "appliance-apply").order_by(Job.id)).all()
        assert all(job.status == JobStatus.FAILED.value for job in apply_jobs)
        assert all(job.finished_at is not None for job in apply_jobs)
        assert all(job.progress_percent == 100 for job in apply_jobs)
        assert all("Review current appliance state" in (job.error or "") for job in apply_jobs)
        assert all(json.loads(job.result or "{}")["interrupted"] is True for job in apply_jobs)
        assert all(json.loads(job.result or "{}")["state"] == "failed" for job in apply_jobs)
        steps = db.scalars(select(JobStep).order_by(JobStep.id)).all()
        assert [(step.status, step.progress_percent) for step in steps] == [("skipped", 100), ("failed", 100)]
        unrelated = db.get(Job, "job_unrelated_download")
        assert unrelated is not None
        assert unrelated.status == JobStatus.RUNNING.value


def test_appliance_apply_master_steps_fail_fast_and_keep_successful_baselines(client, monkeypatch):
    """Verify that appliance apply master steps fail fast and keep successful baselines.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep, Setting

    units = [
        {
            "id": component,
            "label": label,
            "snapshot_hash": f"hash-{component}",
            "summary": [label],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": f"/tmp/{component}.conf",
            "config_preview": f"{component}=enabled",
            "config_diff": "",
            "context": {},
        }
        for component, label in [("network", "Network"), ("firewall", "Firewall"), ("dnsmasq", "DNS/DHCP")]
    ]
    result = {
        "selected_units": [unit["id"] for unit in units],
        "captured_units": [{"unit_id": unit["id"], "snapshot_hash": unit["snapshot_hash"], "summary": unit["summary"]} for unit in units],
        "skipped_changed_units": [],
        "units": [],
        "dry_run": True,
    }
    with SessionLocal() as db:
        job = Job(
            id="job_fail_fast_apply",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            progress_percent=0,
            result=json.dumps(result),
        )
        db.add(job)
        db.add_all(
            [
                JobStep(
                    id=f"{job.id}:{unit['id']}",
                    job=job,
                    component_key=unit["id"],
                    label=unit["label"],
                    position=index,
                    status=JobStatus.PENDING.value,
                    result=json.dumps({"summary": unit["summary"]}),
                )
                for index, unit in enumerate(units, start=1)
            ]
        )
        db.commit()

    executed = []

    def execute(unit, *, adapter=None, db=None):
        """Run operation.

        Args:
            unit: Unit supplied to the test scenario.
            adapter: Adapter supplied to the test scenario.
            db: Active database session supplied by the runner.


        Returns:
            The execute result.
        """
        executed.append(unit["id"])
        success = unit["id"] == "network"
        return {
            "unit_id": unit["id"],
            "label": unit["label"],
            "status": "succeeded" if success else "failed",
            "success": success,
            "dry_run": True,
            "commands": [],
            "summary": unit["summary"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": unit["config_path"],
            "config_preview": unit["config_preview"],
            "config_diff": "",
        }

    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: units)
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda _db, _results: None)
    monkeypatch.setattr(ui, "log_appliance_apply_failures", lambda _job_id, _results: None)
    monkeypatch.setattr(ui, "log_appliance_apply_submission", lambda *_args, **_kwargs: None)

    ui.run_appliance_apply_job("job_fail_fast_apply")

    assert executed == ["network", "firewall"]
    with SessionLocal() as db:
        job = db.get(Job, "job_fail_fast_apply")
        steps = db.scalars(select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)).all()
        baseline = db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1"))
        assert job.status == JobStatus.FAILED.value
        assert [step.status for step in steps] == ["succeeded", "failed", "skipped"]
        assert baseline is not None
        baseline_payload = json.loads(baseline.value)
        assert "network" in baseline_payload
        assert "firewall" not in baseline_payload
        assert "dnsmasq" not in baseline_payload


def test_successful_appliance_apply_baseline_uses_post_apply_snapshot(client, monkeypatch):
    """Verify that successful appliance apply baseline uses post apply snapshot.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep, Setting

    before = {
        "id": "vcf_offline_depot",
        "label": "VCF Offline Depot",
        "snapshot_hash": "hash-before",
        "summary": ["tool version not detected"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/tmp/vcf-offline-depot.conf",
        "config_preview": "tool_version=not detected",
        "config_diff": "",
        "context": {},
    }
    after = {
        **before,
        "snapshot_hash": "hash-after",
        "summary": ["tool version 9.1.0"],
        "config_preview": "tool_version=9.1.0",
    }
    result = {
        "selected_units": ["vcf_offline_depot"],
        "captured_units": [
            {
                "unit_id": "vcf_offline_depot",
                "snapshot_hash": before["snapshot_hash"],
                "summary": before["summary"],
            }
        ],
        "skipped_changed_units": [],
        "units": [],
        "dry_run": False,
    }
    with SessionLocal() as db:
        job = Job(
            id="job_post_apply_baseline",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            progress_percent=0,
            result=json.dumps(result),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:vcf_offline_depot",
                job=job,
                component_key="vcf_offline_depot",
                label="VCF Offline Depot",
                position=1,
                status=JobStatus.PENDING.value,
                result=json.dumps({"summary": before["summary"]}),
            )
        )
        db.commit()

    apply_completed = False

    def units(_db, **_kwargs):
        """Return units.

        Args:
            _db: Active database session used by the operation.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        return [after if apply_completed else before]

    def execute(unit, *, adapter=None, db=None):
        """Run operation.

        Args:
            unit: Unit supplied to the test scenario.
            adapter: Adapter supplied to the test scenario.
            db: Active database session supplied by the runner.


        Returns:
            The execute result.
        """
        nonlocal apply_completed
        apply_completed = True
        return {
            "unit_id": unit["id"],
            "label": unit["label"],
            "status": "succeeded",
            "success": True,
            "dry_run": False,
            "commands": [],
            "summary": unit["summary"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": unit["config_path"],
            "config_preview": unit["config_preview"],
            "config_diff": "",
        }

    monkeypatch.setattr(ui, "appliance_apply_units", units)
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda _db, _results: None)
    monkeypatch.setattr(ui, "log_appliance_apply_submission", lambda *_args, **_kwargs: None)

    ui.run_appliance_apply_job("job_post_apply_baseline")

    with SessionLocal() as db:
        baseline = db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1"))
        assert baseline is not None
        stored = json.loads(baseline.value)["vcf_offline_depot"]
        assert stored["snapshot_hash"] == "hash-after"
        assert stored["config_preview"] == "tool_version=9.1.0"
        assert stored["summary"] == ["tool version 9.1.0"]


@pytest.mark.parametrize("dry_run", [False, True])
def test_successful_esxi_pxe_apply_marks_network_boot_state_in_job_session(
    client,
    monkeypatch,
    dry_run,
):
    """Verify that successful esxi pxe apply marks network boot state in job session.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        dry_run: Whether to report planned actions without mutating host state.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.services.network_boot as network_boot
    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep, NetworkBootEnvironment
    from atlaso.app.services.network_boot import ensure_environment_rows

    previous_runtime_preview = json.dumps(
        {
            "kind": "atlaso-esxi-pxe",
            "schema_version": 1,
            "network_boot": {"schema_version": 1, "environments": []},
            "marker": "previous-real-apply",
        }
    )
    desired_preview = json.dumps(
        {
            "kind": "atlaso-esxi-pxe",
            "schema_version": 1,
            "network_boot": {"schema_version": 1, "environments": []},
            "marker": "current-desired-state",
        }
    )
    unit = {
        "id": "esxi_pxe",
        "label": "ESXi PXE",
        "snapshot_hash": "hash-esxi-pxe",
        "summary": ["boot services enabled"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/var/lib/atlaso/apply/esxi-pxe/atlaso-esxi-pxe.json",
        "config_preview": desired_preview,
        "config_diff": "",
        "context": {},
    }
    payload = {
        "selected_units": ["esxi_pxe"],
        "captured_units": [
            {
                "unit_id": "esxi_pxe",
                "snapshot_hash": unit["snapshot_hash"],
                "summary": unit["summary"],
            }
        ],
        "skipped_changed_units": [],
        "units": [],
        "dry_run": False,
    }
    with SessionLocal() as db:
        ui.save_appliance_apply_baselines(
            db,
            {
                "esxi_pxe": {
                    "config_preview": previous_runtime_preview,
                }
            },
        )
        states = {row.key: row for row in ensure_environment_rows(db)}
        states["memtest86plus"].enabled = True
        states["memtest86plus"].desired_version = "8.10"
        states["memtest86plus"].active_version = ""
        job = Job(
            id=f"job_network_boot_applied_state_{dry_run}",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            result=json.dumps(payload),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:esxi_pxe",
                job=job,
                component_key="esxi_pxe",
                label="ESXi PXE",
                position=1,
                status=JobStatus.PENDING.value,
                result="{}",
            )
        )
        db.commit()

    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: [unit])
    monkeypatch.setattr(
        ui,
        "execute_appliance_apply_unit",
        lambda *_args, **_kwargs: {
            "unit_id": "esxi_pxe",
            "label": "ESXi PXE",
            "status": "succeeded",
            "success": True,
            "dry_run": dry_run,
            "commands": [],
            "summary": unit["summary"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": unit["config_path"],
            "config_preview": unit["config_preview"],
            "config_diff": "",
        },
    )
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda *_args: None)
    monkeypatch.setattr(ui, "log_appliance_apply_submission", lambda *_args, **_kwargs: None)
    prune_calls: list[str] = []
    monkeypatch.setattr(
        network_boot,
        "prune_superseded_shredos_media",
        lambda _db: prune_calls.append("after-apply") or 0,
    )

    ui.run_appliance_apply_job(f"job_network_boot_applied_state_{dry_run}")

    with SessionLocal() as db:
        job = db.get(Job, f"job_network_boot_applied_state_{dry_run}")
        state = db.scalar(
            select(NetworkBootEnvironment).where(
                NetworkBootEnvironment.key == "memtest86plus"
            )
        )
        assert job is not None
        assert job.status == JobStatus.SUCCEEDED.value
        assert state is not None
        assert state.active_version == ("" if dry_run else "8.10")
        assert prune_calls == ([] if dry_run else ["after-apply"])
        baseline = ui.load_appliance_apply_baselines(db)["esxi_pxe"]
        assert baseline["config_preview"] == desired_preview
        assert baseline["runtime_config_preview"] == (
            previous_runtime_preview if dry_run else desired_preview
        )
        assert network_boot._applied_esxi_pxe_manifest(db)["marker"] == (
            "previous-real-apply" if dry_run else "current-desired-state"
        )


def test_appliance_apply_parent_cancel_finishes_current_step_and_skips_remaining(client, monkeypatch):
    """Verify that appliance apply parent cancel finishes current step and skips remaining.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    units = [
        {
            "id": component,
            "label": label,
            "snapshot_hash": f"hash-{component}",
            "summary": [label],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": f"/tmp/{component}.conf",
            "config_preview": component,
            "config_diff": "",
            "context": {},
        }
        for component, label in [("network", "Network"), ("firewall", "Firewall")]
    ]
    payload = {
        "selected_units": [unit["id"] for unit in units],
        "captured_units": [{"unit_id": unit["id"], "snapshot_hash": unit["snapshot_hash"]} for unit in units],
        "skipped_changed_units": [],
        "units": [],
        "dry_run": True,
    }
    with SessionLocal() as db:
        job = Job(id="job_cancel_apply", type="appliance-apply", status="pending", created_by="admin", result=json.dumps(payload))
        db.add(job)
        db.add_all(
            [
                JobStep(
                    id=f"{job.id}:{unit['id']}",
                    job=job,
                    component_key=unit["id"],
                    label=unit["label"],
                    position=index,
                    status="pending",
                    result="{}",
                )
                for index, unit in enumerate(units, start=1)
            ]
        )
        db.commit()

    def execute(unit, *, adapter=None, db=None):
        """Run operation.

        Args:
            unit: Unit supplied to the test scenario.
            adapter: Adapter supplied to the test scenario.
            db: Active database session supplied by the runner.


        Returns:
            The execute result.
        """
        with SessionLocal() as other_db:
            parent = other_db.get(Job, "job_cancel_apply")
            current = json.loads(parent.result or "{}")
            current["cancel_requested"] = True
            current["state"] = "cancellation-requested"
            parent.result = json.dumps(current)
            other_db.commit()
        return {
            "unit_id": unit["id"],
            "label": unit["label"],
            "status": "succeeded",
            "success": True,
            "dry_run": True,
            "commands": [],
            "summary": unit["summary"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": unit["config_path"],
            "config_preview": unit["config_preview"],
            "config_diff": "",
        }

    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: units)
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda _db, _results: None)
    monkeypatch.setattr(ui, "log_appliance_apply_submission", lambda *_args, **_kwargs: None)

    ui.run_appliance_apply_job("job_cancel_apply")

    with SessionLocal() as db:
        job = db.get(Job, "job_cancel_apply")
        steps = db.scalars(select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)).all()
        assert job.status == JobStatus.CANCELLED.value
        assert [step.status for step in steps] == ["succeeded", "skipped"]
        assert json.loads(job.result or "{}")["state"] == "cancelled"


def test_application_restart_removes_stale_secret_staging_inputs(client, monkeypatch, tmp_path):
    """Verify that application restart removes stale secret staging inputs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from starlette.testclient import TestClient

    from atlaso.app import ui
    from atlaso.app.main import create_app

    local_users_path = tmp_path / "apply" / "local-users" / "atlaso-users.json"
    ca_path = tmp_path / "apply" / "ca" / "atlaso-ca.json"
    ldap_path = tmp_path / "apply" / "ldap" / "atlaso-ldap.json"
    status_path = local_users_path.with_name(".atlaso-users.status-stale.json")
    atomic_temp_paths = [
        path.with_name(f".{path.name}.stale.tmp")
        for path in (local_users_path, ca_path, ldap_path, status_path)
    ]
    stale_paths = [local_users_path, ca_path, ldap_path, status_path, *atomic_temp_paths]
    for path in stale_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"password":"RestartSecret1!"}', encoding="utf-8")
        path.chmod(0o600)

    monkeypatch.setattr(ui, "LOCAL_USERS_STAGED_CONFIG_PATH", str(local_users_path))
    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(ca_path))
    monkeypatch.setattr(ui, "LDAP_STAGED_CONFIG_PATH", str(ldap_path))

    with TestClient(create_app()) as restarted_client:
        assert restarted_client.get("/openapi.json").status_code == 200

    assert all(not path.exists() for path in stale_paths)


def test_secret_staging_cleanup_repairs_ownership_before_unlink(monkeypatch, tmp_path):
    """Verify that secret staging cleanup repairs ownership before unlink.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult

    staged_paths = [
        tmp_path / "apply" / "local-users" / "atlaso-users.json",
        tmp_path / "apply" / "ca" / "atlaso-ca.json",
        tmp_path / "apply" / "ldap" / "atlaso-ldap.json",
    ]
    for path in staged_paths:
        path.parent.mkdir(parents=True)
        path.write_text("{}", encoding="utf-8")
    repairs: list[str] = []

    class RepairingAdapter:
        """Represent repairing adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        def prepare_apply_staging_path(self, path: str) -> AdapterResult:
            """Return prepare apply staging path.

            Args:
                path: Filesystem or URL path to read, validate, or update.
            """
            repairs.append(path)
            return AdapterResult(["atlaso-helper", "staging", "prepare", path], False)

    monkeypatch.setattr(ui, "LOCAL_USERS_STAGED_CONFIG_PATH", str(staged_paths[0]))
    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(staged_paths[1]))
    monkeypatch.setattr(ui, "LDAP_STAGED_CONFIG_PATH", str(staged_paths[2]))
    monkeypatch.setattr(ui, "SystemAdapter", RepairingAdapter)

    ui.cleanup_transient_secret_staging_files()

    assert repairs == [str(path) for path in staged_paths]
    assert all(not path.exists() for path in staged_paths)


def test_appliance_startup_initializes_factory_apply_baseline(monkeypatch, tmp_path):
    """Verify that appliance startup initializes factory apply baseline.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select
    from starlette.testclient import TestClient

    import atlaso.app.database as database
    from atlaso.app.config import get_settings
    from atlaso.app.models import AuditEvent, Job, JobStatus, Setting, User

    db_path = tmp_path / "atlaso-appliance-baseline.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    monkeypatch.setenv("ATLASO_ENVIRONMENT", "appliance")
    get_settings.cache_clear()
    database.engine.dispose()
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal.configure(bind=database.engine)

    from atlaso.app.main import create_app

    with TestClient(create_app(), base_url="http://127.0.0.1") as test_client:
        login(test_client)
        page = test_client.get("/ui/management/appliance-apply", follow_redirects=False)
        assert page.status_code == 303
        assert page.headers["location"] == "/ui/management/dashboard#appliance-apply-review"
        review = test_client.get("/appliance-apply/review")
        assert review.status_code == 200
        assert review.json()["initial_apply_required"] is True
        assert review.json()["units"]
        assert all(unit["selected"] is unit["valid"] for unit in review.json()["units"])

        with database.SessionLocal() as db:
            db.add(
                Job(
                    id="job_factory_initial_apply",
                    type="appliance-apply",
                    status=JobStatus.SUCCEEDED.value,
                    created_by="admin",
                    progress_percent=100,
                    result='{"selected_units": []}',
                )
            )
            db.commit()

        completed_review = test_client.get("/appliance-apply/review")
        assert completed_review.status_code == 200
        assert completed_review.json()["initial_apply_required"] is False
        assert completed_review.json()["units"] == []

    with database.SessionLocal() as db:
        baseline = db.execute(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).scalar_one()
        assert '"local_users"' in baseline.value
        assert '"vcf_private_registry"' in baseline.value
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        assert admin.os_sync_status == "applied"
        assert admin.os_password_applied_at is not None
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "initialize_factory_appliance_apply_baseline")).scalar_one()
        assert event.actor == "system"

    get_settings.cache_clear()


def test_factory_apply_baseline_skips_after_operator_activity(monkeypatch, tmp_path):
    """Verify that factory apply baseline skips after operator activity.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from sqlalchemy import select

    import atlaso.app.database as database
    from atlaso.app.audit import record_audit
    from atlaso.app.config import get_settings
    from atlaso.app.models import Setting
    from atlaso.app.seed import seed_initial_data
    from atlaso.app.ui import initialize_factory_appliance_apply_baseline

    db_path = tmp_path / "atlaso-appliance-edited.db"
    monkeypatch.setenv("ATLASO_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ATLASO_SECRET_KEY", "test-secret-key-with-enough-length")
    monkeypatch.setenv("ATLASO_BOOTSTRAP_ADMIN_PASSWORD", "atlaso-admin")
    monkeypatch.setenv("ATLASO_ENVIRONMENT", "appliance")
    get_settings.cache_clear()
    database.engine.dispose()
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    database.SessionLocal.configure(bind=database.engine)
    database.init_db()

    with database.SessionLocal() as db:
        seed_initial_data(db, include_examples=False)
        record_audit(db, actor="admin", action="update_appliance_settings", resource_type="settings")
        assert initialize_factory_appliance_apply_baseline(db) is False
        assert db.execute(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).scalar_one_or_none() is None

    get_settings.cache_clear()


def test_appliance_apply_runs_firewall_before_wan(client):
    """Verify that appliance apply runs firewall before wan.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import appliance_apply_units

    login(client)
    with SessionLocal() as db:
        unit_ids = [unit["id"] for unit in appliance_apply_units(db)]

    assert unit_ids.index("firewall") < unit_ids.index("wan")


def test_network_apply_config_includes_removed_vlan_targets_from_baseline():
    """Verify that network apply config includes removed vlan targets from baseline."""
    from atlaso.app.ui import (
        network_config_with_removed_vlans,
        network_vlan_entries_from_config,
        removed_network_vlan_entries,
    )

    baseline = {
        "config_preview": "\n".join(
            [
                "[physical_interfaces]",
                "interface=eth2",
                "  mode=trunk",
                "",
                "[vlan_interfaces]",
                "vlan=eth2.20",
                "  parent=eth2",
                "  vlan_id=20",
                "  ip_cidr=192.168.20.1/24",
                "  mtu=1500",
                "  role=access",
            ]
        )
    }
    current = "\n".join(
        [
            "[physical_interfaces]",
            "interface=eth2",
            "  mode=trunk",
            "",
            "[vlan_interfaces]",
            "",
        ]
    )

    removed = removed_network_vlan_entries(current, network_vlan_entries_from_config(baseline["config_preview"]))
    staged = network_config_with_removed_vlans(current, removed)

    assert removed == [{"name": "eth2.20", "parent": "eth2", "vlan_id": "20"}]
    assert "[removed_vlan_interfaces]" in staged
    assert "vlan=eth2.20" in staged
    assert "  parent=eth2" in staged
    assert "  vlan_id=20" in staged


def test_network_apply_removal_targets_include_successful_apply_history(client):
    """Verify that network apply removal targets include successful apply history.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow
    from atlaso.app.ui import (
        removed_network_vlan_entries,
        successful_network_apply_vlan_entries,
    )

    applied_preview = "\n".join(
        [
            "[physical_interfaces]",
            "interface=eth2",
            "  mode=trunk",
            "",
            "[vlan_interfaces]",
            "vlan=eth2.21",
            "  parent=eth2",
            "  vlan_id=21",
            "  ip_cidr=192.168.21.1/24",
            "  mtu=1500",
            "  role=access",
        ]
    )
    current_preview = "\n".join(
        [
            "[physical_interfaces]",
            "interface=eth2",
            "  mode=trunk",
            "",
            "[vlan_interfaces]",
            "",
        ]
    )
    with SessionLocal() as db:
        job = Job(
            id="job_network_history_vlan",
            type="appliance-apply",
            status=JobStatus.SUCCEEDED.value,
            created_by="admin",
            started_at=utcnow(),
            finished_at=utcnow(),
            progress_percent=100,
            result=json.dumps(
                {
                    "units": [
                        {
                            "unit_id": "network",
                            "success": True,
                            "dry_run": False,
                            "config_preview": applied_preview,
                        }
                    ]
                }
            ),
        )
        db.add(job)
        db.commit()
        applied = successful_network_apply_vlan_entries(db, {"config_preview": current_preview})
        removed = removed_network_vlan_entries(current_preview, applied)

    assert {"name": "eth2.21", "parent": "eth2", "vlan_id": "21"} in removed


def test_network_apply_history_retires_successfully_removed_vlans(client):
    """Verify that network apply history retires successfully removed vlans.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow
    from atlaso.app.ui import (
        removed_network_vlan_entries,
        successful_network_apply_vlan_entries,
    )

    applied_preview = "\n".join(
        [
            "[physical_interfaces]",
            "interface=eth2",
            "  mode=trunk",
            "",
            "[vlan_interfaces]",
            "vlan=eth2.21",
            "  parent=eth2",
            "  vlan_id=21",
            "  ip_cidr=192.168.21.1/24",
            "  mtu=1500",
            "  role=access",
        ]
    )
    current_preview = "\n".join(
        [
            "[physical_interfaces]",
            "interface=eth2",
            "  mode=trunk",
            "",
            "[vlan_interfaces]",
            "",
        ]
    )
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_network_history_vlan_created",
                type="appliance-apply",
                status=JobStatus.SUCCEEDED.value,
                created_by="admin",
                started_at=utcnow(),
                finished_at=utcnow(),
                progress_percent=100,
                result=json.dumps(
                    {
                        "units": [
                            {
                                "unit_id": "network",
                                "success": True,
                                "dry_run": False,
                                "config_preview": applied_preview,
                            }
                        ]
                    }
                ),
            )
        )
        db.add(
            Job(
                id="job_network_history_vlan_removed",
                type="appliance-apply",
                status=JobStatus.SUCCEEDED.value,
                created_by="admin",
                started_at=utcnow(),
                finished_at=utcnow(),
                progress_percent=100,
                result=json.dumps(
                    {
                        "units": [
                            {
                                "unit_id": "network",
                                "success": True,
                                "dry_run": False,
                                "config_preview": current_preview,
                                "removed_vlan_interfaces": [{"name": "eth2.21", "parent": "eth2", "vlan_id": "21"}],
                            }
                        ]
                    }
                ),
            )
        )
        db.commit()
        applied = successful_network_apply_vlan_entries(db, {"config_preview": current_preview})
        removed = removed_network_vlan_entries(current_preview, applied)

    assert {"name": "eth2.21", "parent": "eth2", "vlan_id": "21"} not in removed


def test_services_ui_records_dry_run_action(client):
    """Verify that services ui records dry run action.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json

    login(client)
    page = client.get("/services")
    assert page.status_code == 200
    assert "Services" in page.text
    assert "services-table" in page.text
    assert "services-fallback" in page.text
    assert "data-services=" in page.text
    assert "Service Boundary" in page.text
    assert "<th>Health</th>" not in page.text
    assert '<span class="status-pill warn">dry-run</span>' in page.text
    assert "Command shape" in page.text
    assert "systemctl restart dns" in page.text
    service_rows = json.loads(html.unescape(page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    assert all(row["service"] != "chronyd" for row in service_rows)
    assert "NTPD" not in page.text
    ntp_row = next(row for row in service_rows if row["service"] == "ntpd")
    assert ntp_row["display_name"] == "NTP / NTS"
    assert ntp_row["detail"] == "ntpd.service / UDP 123"
    ca_row = next(row for row in service_rows if row["service"] == "ca")
    assert ca_row["running"] is False
    assert ca_row["enabled"] is False
    vcf_backup_row = next(row for row in service_rows if row["service"] == "vcf-backups")
    assert vcf_backup_row["running"] is False
    assert vcf_backup_row["enabled"] is False
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/services/firewall/restart", data={"csrf": csrf})
    assert response.status_code == 200
    assert "Firewall restart recorded" in response.text
    assert "Firewall restart recorded as dry-run" in response.text
    assert "systemctl restart firewall" in response.text
    disabled = client.post("/services/firewall/disable", data={"csrf": csrf})
    rows = json.loads(html.unescape(disabled.text.split("data-services='", 1)[1].split("'", 1)[0]))
    firewall_row = next(row for row in rows if row["service"] == "firewall")
    assert firewall_row["enabled"] is False
    assert "health" not in firewall_row
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "initializeServicesTable" in js.text
    assert "submitServiceAction" in js.text
    assert "Check NTPsec source health" in js.text
    assert "openNTPsecSourceHealthModal" in js.text
    assert 'height: "100%"' in js.text
    assert 'height: "520px"' not in js.text
    assert 'title: "Health"' not in js.text
    assert "serviceHealthFormatter" not in js.text
    assert "openServiceActionMenu" not in js.text
    assert "serviceActionsFormatter" not in js.text
    assert 'title: "Startup"' in js.text
    assert 'editor: "tickCross"' in js.text
    assert 'service-state muted">disabled' in js.text
    css = client.get("/static/app.css")
    assert css.status_code == 200
    assert ".service-name-cell" in css.text
    assert ".services-workspace" in css.text
    assert ".services-table" in css.text


def test_services_and_esxi_page_show_enabled_esxi_pxe_boot_state(client):
    """Verify that services and esxi page show enabled esxi pxe boot state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_BIOS_BOOTFILE,
        ESXI_PXE_UEFI_BOOTFILE,
        ESXI_TFTP_ROOT,
        save_esxi_pxe_boot_settings,
    )

    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.enabled.is_(True)).order_by(DhcpScope.id)).scalars().first()
        assert scope is not None
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="esxi-pxe.atlaso.internal",
            dhcp_scope_ids=[scope.id],
            listen_interface=scope.interface_name,
            listen_address=scope.site_address,
            tftp_root=ESXI_TFTP_ROOT.as_posix(),
            bios_bootfile=ESXI_PXE_BIOS_BOOTFILE,
            uefi_bootfile=ESXI_PXE_UEFI_BOOTFILE,
            native_uefi_http_enabled=True,
        )
        db.commit()

    login(client)
    esxi_page = client.get("/esxi-pxe")
    assert esxi_page.status_code == 200
    assert '<span class="status-pill good">live</span>' in esxi_page.text

    services_page = client.get("/services")
    assert services_page.status_code == 200
    service_rows = json.loads(html.unescape(services_page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    esxi_row = next(row for row in service_rows if row["service"] == "esxi-pxe")
    assert esxi_row["running"] is True
    assert esxi_row["enabled"] is True
    assert esxi_row["detail"] == "dnsmasq TFTP/DHCP boot options and PXE HTTP files"

    token = create_api_token(client, ["read:services"])
    api_response = client.get("/api/v1/services/esxi-pxe", headers={"Authorization": f"Bearer {token}"})
    assert api_response.status_code == 200
    assert api_response.json()["running"] is True
    assert api_response.json()["enabled"] is True
    assert api_response.json()["health"] == "healthy"


def test_services_and_service_pages_derive_composite_runtime_status(client, monkeypatch):
    """Verify that services and service pages derive composite runtime status.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DhcpScope,
        KmsSettings,
        VcfBackupSettings,
        VcfOfflineDepotSettings,
    )

    def fake_service_status(self, unit: str):
        """Return fake service status.

        Args:
            unit: Unit supplied to the test scenario.
        """
        return AdapterResult(
            command=["systemctl", "status", unit],
            dry_run=False,
            stdout=json.dumps({"active": "active", "enabled": "enabled"}),
        )

    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()
    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.service_status", fake_service_status)
    monkeypatch.setattr("atlaso.app.api.v1.SystemAdapter.service_status", fake_service_status)

    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.enabled.is_(True)).order_by(DhcpScope.id)).scalars().first()
        assert scope is not None
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        ca_settings.listen_interface = scope.interface_name
        ca_settings.listen_address = scope.site_address
        ca_settings.root_certificate_pem = "present"
        ca_settings.root_private_key_encrypted = "present"
        db.add(ca_settings)
        kms_settings = db.execute(select(KmsSettings)).scalar_one()
        kms_settings.enabled = True
        db.add(kms_settings)
        backup_settings = db.execute(select(VcfBackupSettings)).scalar_one()
        backup_settings.enabled = False
        db.add(backup_settings)
        depot_settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        depot_settings.enabled = True
        db.add(depot_settings)
        db.commit()

    login(client)
    services_page = client.get("/services")
    assert services_page.status_code == 200
    service_rows = json.loads(html.unescape(services_page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    ca_row = next(row for row in service_rows if row["service"] == "ca")
    kms_row = next(row for row in service_rows if row["service"] == "kms")
    backup_row = next(row for row in service_rows if row["service"] == "vcf-backups")
    depot_row = next(row for row in service_rows if row["service"] == "repository")
    assert ca_row["running"] is True
    assert ca_row["enabled"] is True
    assert kms_row["running"] is True
    assert kms_row["enabled"] is True
    assert backup_row["running"] is True
    assert backup_row["enabled"] is False
    assert depot_row["running"] is True
    assert depot_row["enabled"] is True

    assert '<span class="status-pill good">live</span>' in client.get("/vsphere-key-providers").text
    assert '<span class="status-pill good">live</span>' in client.get("/vcf-offline-depot").text
    ca_page = client.get("/certificate-authority").text
    assert '<span class="status-pill muted">disabled</span>' not in ca_page
    assert '<span class="status-pill good">live</span>' in ca_page or '<span class="status-pill warn">needs attention</span>' in ca_page

    token = create_api_token(client, ["read:services"])
    assert client.get("/api/v1/services/ca", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True
    assert client.get("/api/v1/services/repository", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True
    assert client.get("/api/v1/services/vcf-backups", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True


def test_esx_storage_live_status_requires_rpcbind_only_for_nfs3(client, monkeypatch):
    """Verify that esx storage live status requires rpcbind only for nfs3.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxNfsShare, EsxStorageSettings, EsxStorageVolume

    def fake_service_status(self, unit: str):
        """Return fake service status.

        Args:
            unit: Unit supplied to the test scenario.
        """
        active = "inactive" if unit == "rpcbind.service" else "active"
        enabled = "disabled" if unit == "rpcbind.service" else "enabled"
        return AdapterResult(
            command=["systemctl", "is-active", unit, "&&", "systemctl", "is-enabled", unit],
            dry_run=False,
            stdout=json.dumps({"active": active, "enabled": enabled}),
        )

    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()
    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.service_status", fake_service_status)
    monkeypatch.setattr("atlaso.app.api.v1.SystemAdapter.service_status", fake_service_status)

    with SessionLocal() as db:
        settings = db.execute(select(EsxStorageSettings)).scalar_one_or_none()
        if settings is None:
            settings = EsxStorageSettings(enabled=True, hostname="nfs.atlaso.internal")
            db.add(settings)
        else:
            settings.enabled = True
        volume = EsxStorageVolume(
            name="rpcbind-health",
            source_type="mounted_ext4",
            stable_device_id="/dev/disk/by-uuid/rpcbind-health",
            filesystem_uuid="rpcbind-health",
            mount_path="/mnt/atlaso-esx-storage/rpcbind-health",
            state="mounted",
            applied=True,
        )
        db.add(volume)
        db.flush()
        share = EsxNfsShare(
            datastore_name="rpcbind-health",
            volume_id=volume.id,
            relative_path="datastore",
            preferred_nfs_version="3",
            interface_name="eth1",
            address_families="ipv4\nipv6",
            ipv4_clients="192.168.50.10/32",
            ipv6_clients="fd00:50::10/128",
            enabled=True,
        )
        db.add(share)
        db.commit()

    login(client)
    page = client.get("/services")
    service_rows = json.loads(html.unescape(page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    esx_row = next(row for row in service_rows if row["service"] == "esx-storage")
    assert esx_row["running"] is False
    assert esx_row["health"] == "degraded"
    assert "rpcbind.service is required" in esx_row["detail"]

    token = create_api_token(client, ["read:services"])
    api_row = client.get("/api/v1/services/esx-storage", headers={"Authorization": f"Bearer {token}"}).json()
    assert api_row["running"] is False
    assert api_row["health"] == "degraded"
    assert "rpcbind.service is required" in api_row["detail"]

    with SessionLocal() as db:
        share = db.execute(select(EsxNfsShare).where(EsxNfsShare.datastore_name == "rpcbind-health")).scalar_one()
        share.preferred_nfs_version = "4.1"
        db.commit()

    page = client.get("/services")
    service_rows = json.loads(html.unescape(page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    esx_row = next(row for row in service_rows if row["service"] == "esx-storage")
    assert esx_row["running"] is True
    assert esx_row["health"] == "healthy"


def test_services_dns_dhcp_rows_use_desired_enabled_state(client):
    """Verify that services dns dhcp rows use desired enabled state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, DnsSettings, ServiceState

    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        for service_name in ("dns", "dhcp"):
            service = db.execute(select(ServiceState).where(ServiceState.service == service_name)).scalar_one()
            service.running = False
            service.enabled = False
            service.health = "disabled"
        db.commit()

    login(client)
    page = client.get("/services")
    assert page.status_code == 200
    service_rows = json.loads(html.unescape(page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    dns_row = next(row for row in service_rows if row["service"] == "dns")
    dhcp_row = next(row for row in service_rows if row["service"] == "dhcp")
    assert dns_row["enabled"] is True
    assert dhcp_row["enabled"] is True
    assert dns_row["running"] is False
    assert dhcp_row["running"] is False

    token = create_api_token(client, ["read:services"])
    assert client.get("/api/v1/services/dns", headers={"Authorization": f"Bearer {token}"}).json()["enabled"] is True
    assert client.get("/api/v1/services/dhcp", headers={"Authorization": f"Bearer {token}"}).json()["enabled"] is True


def test_services_dns_dhcp_actions_update_desired_settings(client):
    """Verify that services dns dhcp actions update desired settings.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, DnsSettings, ServiceState

    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        for service_name in ("dns", "dhcp"):
            service = db.execute(select(ServiceState).where(ServiceState.service == service_name)).scalar_one()
            service.enabled = False
        db.commit()

    token = create_api_token(client, ["read:services", "write:services"])
    response = client.post("/api/v1/services/dns/disable", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert client.get("/api/v1/services/dns", headers={"Authorization": f"Bearer {token}"}).json()["enabled"] is False

    with SessionLocal() as db:
        assert db.execute(select(DnsSettings)).scalar_one().enabled is False

    login(client)
    page = client.get("/services")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/services/dhcp/disable", data={"csrf": csrf})
    assert response.status_code == 200
    service_rows = json.loads(html.unescape(response.text.split("data-services='", 1)[1].split("'", 1)[0]))
    dhcp_row = next(row for row in service_rows if row["service"] == "dhcp")
    assert dhcp_row["enabled"] is False

    with SessionLocal() as db:
        assert db.execute(select(DhcpSettings)).scalar_one().enabled is False


def test_services_live_dns_dhcp_runtime_uses_dnsmasq_systemd(client, monkeypatch):
    """Verify that services live dns dhcp runtime uses dnsmasq systemd.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, DnsSettings, ServiceState

    def fake_service_status(self, unit: str):
        """Return fake service status.

        Args:
            unit: Unit supplied to the test scenario.
        """
        active = "active" if unit == "dnsmasq.service" else "inactive"
        enabled = "enabled" if unit == "dnsmasq.service" else "disabled"
        return AdapterResult(
            command=["systemctl", "is-active", unit, "&&", "systemctl", "is-enabled", unit],
            dry_run=False,
            stdout=json.dumps({"active": active, "enabled": enabled}),
        )

    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()
    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.service_status", fake_service_status)
    monkeypatch.setattr("atlaso.app.api.v1.SystemAdapter.service_status", fake_service_status)

    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        for service_name in ("dns", "dhcp"):
            service = db.execute(select(ServiceState).where(ServiceState.service == service_name)).scalar_one()
            service.running = False
            service.enabled = False
            service.health = "disabled"
        db.commit()

    login(client)
    page = client.get("/services")
    assert page.status_code == 200
    service_rows = json.loads(html.unescape(page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    dns_row = next(row for row in service_rows if row["service"] == "dns")
    dhcp_row = next(row for row in service_rows if row["service"] == "dhcp")
    assert dns_row["running"] is True
    assert dns_row["enabled"] is True
    assert dhcp_row["running"] is True
    assert dhcp_row["enabled"] is True

    token = create_api_token(client, ["read:services"])
    assert client.get("/api/v1/services/dns", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True
    assert client.get("/api/v1/services/dhcp", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True


def test_services_live_ntp_status_uses_systemd(client, monkeypatch):
    """Verify that services live ntp status uses systemd.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html
    import json

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings

    def fake_service_status(self, unit: str):
        """Return fake service status.

        Args:
            unit: Unit supplied to the test scenario.
        """
        active = "active" if unit == "ntpd.service" else "inactive"
        enabled = "enabled" if unit == "ntpd.service" else "disabled"
        return AdapterResult(
            command=["systemctl", "is-active", unit, "&&", "systemctl", "is-enabled", unit],
            dry_run=False,
            stdout=json.dumps({"active": active, "enabled": enabled}),
        )

    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()
    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.service_status", fake_service_status)
    monkeypatch.setattr("atlaso.app.api.v1.SystemAdapter.service_status", fake_service_status)

    login(client)
    page = client.get("/services")
    assert page.status_code == 200
    service_rows = json.loads(html.unescape(page.text.split("data-services='", 1)[1].split("'", 1)[0]))
    ntp_row = next(row for row in service_rows if row["service"] == "ntpd")
    assert ntp_row["running"] is True
    assert ntp_row["enabled"] is True
    assert "health" not in ntp_row

    token = create_api_token(client, ["read:services"])
    api_response = client.get("/api/v1/services/ntpd", headers={"Authorization": f"Bearer {token}"})
    assert api_response.status_code == 200
    assert api_response.json()["running"] is True
    assert api_response.json()["enabled"] is True
    assert api_response.json()["health"] == "healthy"


def test_services_ui_hides_dry_run_badge_when_adapters_are_live(client, monkeypatch):
    """Verify that services ui hides dry run badge when adapters are live.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.config import get_settings

    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()
    login(client)

    page = client.get("/services")

    assert page.status_code == 200
    assert '<span class="status-pill good">live</span>' in page.text
    assert '<span class="status-pill warn">dry-run</span>' not in page.text
    assert "captured as dry-run command intent" not in page.text
    assert "Open Logs on a service row to capture a log preview." in page.text


def test_ca_settings_autosave_returns_json(client):
    """Verify that ca settings autosave returns json.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings

    login(client)
    page = client.get("/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/certificate-authority/settings",
        data={
            "enabled": "on",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth1", "eth2"],
            "listen_addresses": ["192.168.50.1", "10.0.0.99"],
            "root_common_name": "Atlaso Test Root CA",
            "organization": "Atlaso",
            "organizational_unit": "Lab",
            "country": "US",
            "state": "",
            "locality": "",
            "key_algorithm": "RSA",
            "key_size": "4096",
            "digest_algorithm": "sha256",
            "root_valid_days": "3650",
            "intermediate_valid_days": "1825",
            "publish_crl": "on",
            "storage_path": "/tmp/operator-edited-ca",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["listen_interfaces"] == ["eth2"]
    assert payload["listen_addresses"] == ["192.168.50.1"]
    assert "10.0.0.99" not in payload["config_preview"]
    assert "Atlaso Test Root CA" in client.get("/certificate-authority").text
    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        assert ca_settings.storage_path == "/etc/atlaso/ca"
        assert ca_settings.listen_interface == "eth2"
        assert ca_settings.listen_address == "192.168.50.1"


def test_ca_internal_material_apply_does_not_require_public_listen_interface(client):
    """Verify that ca internal material apply does not require public listen interface.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings

    with SessionLocal() as db:
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.enabled = True
        settings.listen_interface = ""
        settings.listen_address = ""
        db.commit()

    login(client)
    page = client.get("/certificate-authority")

    assert page.status_code == 200
    assert "CA service requires at least one listen interface." not in page.text
    assert "No interface address selected" in page.text
    review = client.get("/appliance-apply/review")
    ca_unit = next(unit for unit in review.json()["units"] if unit["id"] == "ca")
    assert ca_unit["validation_errors"] == []


def test_ca_apply_task_captures_current_desired_state(client):
    """Verify that ca apply task captures current desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "ca"})

    assert_apply_redirect(response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "Atlaso Internal Root CA" in (job.result or "")


def test_ca_live_apply_stages_decrypted_private_keys_without_leaking_job_output(client, monkeypatch, tmp_path):
    """Verify that ca live apply stages decrypted private keys without leaking job output.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from pathlib import Path

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, Job

    staged_path = tmp_path / "atlaso-ca.json"
    captured: dict[str, str] = {}

    def fake_validate_ca_config(self, config_path: str):
        """Return fake validate ca config.

        Args:
            config_path: Filesystem path containing the operation configuration.
        """
        captured["validate_payload"] = Path(config_path).read_text(encoding="utf-8")
        return AdapterResult(command=["atlaso-helper", "ca", "validate", config_path], dry_run=False, stdout="validated")

    def fake_apply_ca_config(self, config_path: str):
        """Return fake apply ca config.

        Args:
            config_path: Filesystem path containing the operation configuration.
        """
        captured["apply_payload"] = Path(config_path).read_text(encoding="utf-8")
        return AdapterResult(command=["atlaso-helper", "ca", "apply", config_path], dry_run=False, stdout="applied")

    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()
    monkeypatch.setattr("atlaso.app.ui.CA_STAGED_CONFIG_PATH", str(staged_path))
    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.validate_ca_config", fake_validate_ca_config)
    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.apply_ca_config", fake_apply_ca_config)

    with SessionLocal() as db:
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.enabled = True
        settings.listen_interface = "eth2"
        settings.listen_address = "192.168.50.1"
        db.commit()

    login(client)
    page = client.get("/certificate-authority")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "ca"})

    assert response.status_code == 200
    assert captured["validate_payload"] == captured["apply_payload"]
    assert "BEGIN PRIVATE KEY" in captured["apply_payload"]
    assert "[redacted]" not in captured["apply_payload"]
    assert not staged_path.exists()

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "BEGIN PRIVATE KEY" not in (job.result or "")


def test_appliance_apply_status_redacts_undecryptable_ca_private_key(client):
    """Verify that appliance apply status redacts undecryptable ca private key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings

    with SessionLocal() as db:
        settings = db.execute(select(CaSettings)).scalar_one()
        settings.root_private_key_encrypted = "not-a-valid-fernet-token"
        db.commit()

    login(client)
    response = client.get("/dns")

    assert response.status_code == 200
    assert "DNS Settings" in response.text
    assert "not-a-valid-fernet-token" not in response.text








def test_dns_validation_requires_dhcp_only_when_esxi_pxe_boot_enabled(client):
    """Verify that dns validation requires dhcp only when esxi pxe boot enabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.services.esxi_pxe import ESXI_PXE_BOOT_ENABLED_KEY

    login(client)
    with SessionLocal() as db:
        setting = db.execute(select(Setting).where(Setting.key == ESXI_PXE_BOOT_ENABLED_KEY)).scalar_one_or_none()
        if setting is None:
            setting = Setting(key=ESXI_PXE_BOOT_ENABLED_KEY, value="true")
            db.add(setting)
        else:
            setting.value = "true"
        db.commit()

    response = client.get("/dns")

    assert response.status_code == 200
    assert "ESXi PXE boot services require DHCP to be enabled so clients receive boot files." in response.text


def test_dns_apply_task_captures_current_desired_state(client):
    """Verify that dns apply task captures current desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, Job

    login(client)
    with SessionLocal() as db:
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        db.commit()
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "dnsmasq"})

    assert_apply_redirect(response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "dnsmasq" in (job.result or "")
        assert "atlaso.internal" in (job.result or "")














def test_dhcp_page_tolerates_stale_ipv6_esxi_pxe_scope_selection(client):
    """Verify that dhcp page tolerates stale ipv6 esxi pxe scope selection.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope
    from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

    login(client)
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname="esxi-pxe.atlaso.internal",
            listen_interface="eth2",
            listen_address="192.168.50.1",
            dhcp_scope_id=str(scope.id),
            dhcp_scope_ids=[str(scope.id)],
            tftp_root="/var/lib/atlaso/pxe/tftp",
            http_port=8080,
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="",
        )
        scope.address_family = "ipv6"
        scope.site_address = "fd00:50::1"
        scope.prefix_length = 64
        scope.range_expression = "fd00:50::100-fd00:50::200"
        db.add(scope)
        db.commit()

    page = client.get("/dhcp")

    assert page.status_code == 200
    assert "Generated PXE" in page.text


def test_dhcp_apply_task_captures_current_desired_state(client):
    """Verify that dhcp apply task captures current desired state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, Job

    login(client)
    with SessionLocal() as db:
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        db.commit()
    page = client.get("/dhcp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "dnsmasq"})

    assert_apply_redirect(response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "dnsmasq" in (job.result or "")
        assert "1 reservations" in (job.result or "")


















def test_vcf_helper_page_renders_domain_dropdown(client):
    """Verify that vcf helper page renders domain dropdown.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from pathlib import Path

    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post("/dns/zones", data={"domain": "vcf.internal", "csrf": csrf}, follow_redirects=False)
    assert created.status_code == 303

    response = client.get("/vcf-helper")

    assert response.status_code == 200
    assert "Generated VCF FQDNs" in response.text
    assert "DNS Boundary" not in response.text
    assert 'href="/ui/management/vcf-helper"' in response.text
    visible_workspace = response.text.split('<section class="split-workspace vcf-helper-workspace"', 1)[1].split("</section>", 1)[0]
    assert "VCF Certificate Trust" in visible_workspace
    assert "Review DNS" not in visible_workspace
    assert visible_workspace.count('class="info-band vcf-helper-action-band"') == 7
    assert "Import passwords into a vault" in visible_workspace
    assert 'id="vcf-helper-platform-title">SDDC Manager / VCF Installer</h3>' in visible_workspace
    assert 'id="vcf-helper-ldap-title">LDAP</h3>' in visible_workspace
    assert visible_workspace.count('class="vcf-helper-action-bands"') == 2
    assert "vcf-helper-action-arrow" not in visible_workspace
    assert "service-summary-grid" not in visible_workspace
    assert "Generated names" not in visible_workspace
    assert "Next IP hint" not in visible_workspace
    assert "<aside" not in visible_workspace
    assert "Deploy SDDC Manager" in visible_workspace
    assert "Configure VCF Offline Depot" in visible_workspace
    assert "Managed LDAP for VCF" in visible_workspace
    assert 'class="vcf-helper-action-wrap" data-help="SDDC Manager deployment becomes available' in visible_workspace
    assert 'class="vcf-helper-action-wrap" data-help="Enable VCF Offline Depot.' in visible_workspace
    assert 'class="alert warn"' not in visible_workspace
    assert 'data-vcf-fqdn-modal-open aria-haspopup="dialog" aria-controls="vcf-fqdn-modal"' in visible_workspace
    assert 'aria-controls="vcf-trust-modal"' in visible_workspace
    assert 'data-vcf-ldap-open aria-haspopup="dialog" aria-controls="vcf-ldap-modal"' in visible_workspace
    assert "Root CA subject" not in visible_workspace
    assert '<option value="atlaso.internal"' in response.text
    assert '<option value="vcf.internal"' in response.text
    assert 'name="target"' in response.text
    assert '<option value="vcf-9.1" selected>VCF 9.1</option>' in response.text
    assert '<option value="vvf-9.1" >VVF 9.1</option>' in response.text
    assert "data-target-components=" in response.text
    assert 'name="start_ipv4"' in response.text
    assert "data-dhcp-assignment=" in response.text
    assert "Automatic from DHCP zone" in response.text
    assert 'name="disk_provisioning"' in response.text
    assert "Thin provisioned" in response.text
    assert "Thick provisioned" in response.text
    assert "data-vcf-sddc-trust-mode-row" not in response.text
    assert 'name="power_on"' in response.text
    assert "Power on after deployment" in response.text
    assert "data-vcf-sddc-tls-confirmation" in response.text
    app_css = Path("atlaso/app/static/app.css").read_text()
    assert ".vcf-helper-workspace {\n  grid-template-columns: minmax(0, 1fr);" in app_css
    assert ".vcf-helper-action-bands {\n  display: grid;\n  grid-template-columns: repeat(2, minmax(0, 1fr));" in app_css
    assert 'type="checkbox" data-vcf-sddc-tls-confirm' in response.text
    assert "Confirm vSphere TLS fingerprint" in response.text
    sddc_modal = response.text.split('<dialog id="vcf-sddc-deploy-modal"', 1)[1].split("</dialog>", 1)[0]
    assert "HTTPS port" not in sddc_modal
    assert "vcf-sddc-wizard-rail" in response.text
    assert "data-vcf-target-depot-step-nav" in response.text
    assert 'data-vcf-target-depot-step="target"' in response.text
    assert 'data-vcf-target-depot-step="tls"' in response.text
    assert 'data-vcf-target-depot-step="api"' in response.text
    assert 'data-vcf-target-depot-step="depot"' in response.text
    assert 'data-vcf-target-depot-step="review"' in response.text
    assert 'data-vcf-target-depot-step="queue"' in response.text
    assert "data-vcf-target-depot-task" not in response.text
    assert "vCenter / ESXi" in response.text
    assert "Resources" in response.text
    assert "Address" in response.text
    assert "OVF properties" in response.text
    assert "Post deployment" in response.text
    assert "data-vcf-sddc-step-source" in response.text
    assert "data-vcf-sddc-step-destination" in response.text
    assert 'data-vcf-sddc-step="resources"' in response.text
    assert 'data-vcf-sddc-step="address"' in response.text
    assert 'data-vcf-sddc-step="properties"' in response.text
    assert 'data-vcf-sddc-step="followup"' in response.text
    assert "data-vcf-sddc-back" in response.text
    assert "data-vcf-sddc-next" in response.text
    assert "Starting IP / prefix" in response.text
    assert 'placeholder="192.168.50.100/24 or 2001:db8::100/64"' in response.text
    assert "Assigned IP" in response.text
    assert "Assigned IPv4" not in response.text
    assert 'name="network_prefix"' not in response.text
    assert "Delete generated records" in response.text
    app_js = Path("atlaso/app/static/app.js").read_text()
    assert "[data-vcf-fqdn-target]" in app_js
    assert 'submit.textContent = complete ? "Done" : "Create DNS records"' in app_js
    assert 'modal.close("done")' in app_js
    assert "[data-vcf-sddc-assignment-mode]" in app_js
    assert "applyDhcpAssignment" in app_js
    assert "disk_provisioning: form.elements.disk_provisioning.value" in app_js
    assert "[data-vcf-sddc-trust-mode-row]" not in app_js
    assert "showTlsConfirmation(data.fingerprint || \"\", handleDiscover)" in app_js
    assert "await action()" in app_js
    assert "parseEndpoint" in app_js
    assert 'next.textContent = "Next"' in app_js
    assert "power_on: shouldPowerOn" in app_js
    assert "add_dns: form.elements.add_dns.checked" in app_js
    assert 'wizard.showStep("resources", { unlock: true })' in app_js
    assert '{ id: "source", title: "vCenter / ESXi information"' in app_js
    assert "initializeVcfSddcDeployment" in app_js
    assert "initializeVcfTargetDepotHelper" in app_js
    assert "/vcf-helper/offline-depot/inspect-target" in app_js
    assert 'window.location.assign(managementUiPath(`/tasks?job_id=${encodeURIComponent(data.job_id || "")}`))' in app_js
    assert "const hasTargetDetails = Boolean(data.target?.appliance)" in app_js
    assert "tlsConfirm.checked = isConfirmedTls" in app_js
    assert 'return state === "tls" ? "tls" : state === "ready"' in app_js


def test_vcf_sddc_dhcp_assignment_uses_static_address_outside_scope(client):
    """Verify that vcf sddc dhcp assignment uses static address outside scope.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpReservation, DhcpScope, DhcpSettings, DnsRecord

    login(client)
    with SessionLocal() as db:
        settings = db.get(DhcpSettings, 1) or DhcpSettings(id=1)
        settings.enabled = True
        db.merge(settings)
        db.add(
            DhcpScope(
                name="VCF",
                address_family="ipv4",
                interface_name="eth2",
                site_address="10.88.0.1",
                prefix_length=24,
                range_expression="10.88.0.100-10.88.0.200",
                domain_name="atlaso.internal",
                dns_server="10.88.0.1",
                ntp_server="10.88.0.1",
                enabled=True,
            )
        )
        db.add(DnsRecord(hostname="used.atlaso.internal", record_type="A", address="10.88.0.2", enabled=True))
        db.add(DhcpReservation(hostname="reserved.atlaso.internal", mac_address="02:15:5d:88:00:03", ip_address="10.88.0.3", enabled=True))
        db.commit()

    response = client.get("/vcf-helper")

    assert response.status_code == 200
    payload = response.text.split("data-dhcp-assignment='", 1)[1].split("'", 1)[0]
    assignment = json.loads(html.unescape(payload))
    scope = next(row for row in assignment["scopes"] if row["name"] == "VCF")
    assert assignment["available"] is True
    assert scope["suggested_ipv4"] == "10.88.0.4"
    assert scope["netmask"] == "255.255.255.0"
    assert scope["gateway"] == "10.88.0.1"
    assert scope["dns_server"] == "10.88.0.1"
    assert scope["domain_name"] == "atlaso.internal"


def test_vcf_helper_renders_certificate_trust_modal(client):
    """Verify that vcf helper renders certificate trust modal.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from pathlib import Path

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.ui import get_ca_settings_row

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        db.commit()

    response = client.get("/vcf-helper")

    assert response.status_code == 200
    assert "VCF Certificate Trust" in response.text
    assert 'action="/ui/management/vcf-trust/root-ca"' in response.text
    assert 'name="snapshot_acknowledged"' not in response.text
    assert 'name="confirmed_tls_fingerprint"' in response.text
    assert "SHA-256 fingerprint" in response.text
    assert "data-vcf-trust-form" in response.text
    assert "data-vcf-trust-step-nav" in response.text
    assert 'name="api_username" value="admin@local"' in response.text
    assert 'data-vcf-trust-step="target"' in response.text
    assert 'data-vcf-trust-step="api"' in response.text
    assert 'data-vcf-trust-step="review"' in response.text
    assert "SSH" not in response.text.split('<dialog id="vcf-trust-modal"', 1)[1].split("</dialog>", 1)[0]
    assert "Latest trust task" not in response.text
    assert "VCF trust targets" not in response.text
    assert "data-vcf-trust-tls-confirmation" in response.text
    assert '<dialog id="vcf-trust-modal"' in response.text
    assert '<dialog id="vcf-trust-modal" class="confirm-modal wide-modal" aria-labelledby="vcf-trust-modal-title" open' not in response.text
    app_js = Path("atlaso/app/static/app.js").read_text()
    assert 'headers: { "X-Atlaso-VCF-Trust": "1" }' in app_js
    assert "/vcf-helper/trust-root-ca/inspect-target" in app_js
    assert "window.location.assign(payload.redirect || managementUiPath(`/tasks?job_id=" in app_js
    assert "After TLS confirmation" in app_js
    assert "previouslyConfirmedTls" in app_js
    assert "tlsCheckbox.checked = isConfirmedTls" in app_js
    assert "data-vcf-trust-auth-method" not in app_js

    legacy = client.get("/vcf-trust", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/ui/management/vcf-trust"


def test_vcf_trust_inspects_target_tls_without_persisting_target(client, monkeypatch):
    """Verify that vcf trust inspects target tls without persisting target.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfTrustTarget

    login(client)
    csrf = client.get("/vcf-helper").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", lambda _address, _port: "AA:BB")
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.inspect_vcf_trust_target", lambda *_args, **_kwargs: {"role": "VcfInstaller", "version": "9.1.0.0"})
    resolved_credentials = []
    original_resolver = ui._resolve_vcf_helper_credentials

    def track_resolver(*args, **kwargs):
        """Return track resolver.

        Args:
            *args: Additional positional arguments accepted by the callable.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        resolved_credentials.append(True)
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(ui, "_resolve_vcf_helper_credentials", track_resolver)

    awaiting = client.post(
        "/vcf-helper/trust-root-ca/inspect-target",
        json={
            "csrf": csrf,
            "address": "https://vcf-installer.example.test:8443",
            "api_username": "administrator@vsphere.local",
            "api_password": "api-secret",
        },
    )

    assert awaiting.status_code == 409
    assert awaiting.json()["fingerprint"] == "AA:BB"
    assert resolved_credentials == []

    response = client.post(
        "/vcf-helper/trust-root-ca/inspect-target",
        json={
            "csrf": csrf,
            "address": "https://vcf-installer.example.test:8443",
            "api_username": "administrator@vsphere.local",
            "api_password": "api-secret",
            "confirmed_tls_fingerprint": "AA:BB",
        },
    )

    assert response.status_code == 200
    assert resolved_credentials == [True]
    assert response.json() == {
        "status": "ready",
        "address": "vcf-installer.example.test",
        "port": 8443,
        "tls_fingerprint": "AA:BB",
        "appliance": {"role": "VcfInstaller", "version": "9.1.0.0"},
    }
    with SessionLocal() as db:
        assert db.execute(select(VcfTrustTarget)).scalars().all() == []


def test_vcf_trust_requires_tls_confirmation_then_queues_without_persisting_credentials(client, monkeypatch):
    """Verify that vcf trust requires tls confirmation then queues without persisting credentials.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, VcfTrustTarget
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.ui import get_ca_settings_row

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        db.commit()
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", lambda _address, _port: "AA:BB")
    queued = []
    monkeypatch.setattr(ui, "queue_vcf_trust_job", lambda job_id, target_id, credentials, ca: queued.append((job_id, target_id, credentials, ca)))
    resolved_credentials = []
    original_resolver = ui._resolve_vcf_helper_credentials

    def track_resolver(*args, **kwargs):
        """Return track resolver.

        Args:
            *args: Additional positional arguments accepted by the callable.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        resolved_credentials.append(True)
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(ui, "_resolve_vcf_helper_credentials", track_resolver)
    csrf = client.get("/vcf-helper").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    credentials = {
        "address": "vcf-installer.example.test",
        "api_username": "administrator@vsphere.local",
        "api_password": "api-super-secret",
        "csrf": csrf,
    }

    awaiting = client.post(
        "/vcf-trust/root-ca",
        data=credentials,
        headers={"X-Atlaso-VCF-Trust": "1"},
    )

    assert awaiting.status_code == 409
    assert awaiting.json()["status"] == "tls-confirmation-required"
    assert awaiting.json()["fingerprint"] == "AA:BB"
    assert resolved_credentials == []
    with SessionLocal() as db:
        assert db.execute(select(Job).where(Job.type == "vcf-ca-trust")).scalars().all() == []
        assert db.execute(select(VcfTrustTarget)).scalars().all() == []

    confirmed = client.post(
        "/vcf-trust/root-ca",
        data={
            **credentials,
            "confirmed_tls_fingerprint": "AA:BB",
        },
        headers={"X-Atlaso-VCF-Trust": "1"},
    )

    assert confirmed.status_code == 202
    assert resolved_credentials == [True]
    assert confirmed.json()["status"] == "queued"
    assert confirmed.json()["redirect"] == f"/tasks?job_id={confirmed.json()['job_id']}"
    assert len(queued) == 1
    assert queued[0][2].api_password == "api-super-secret"
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "vcf-ca-trust")).scalar_one()
        target = db.execute(select(VcfTrustTarget)).scalar_one()
        assert job.status == "pending"
        assert target.api_port == 443
        assert target.tls_fingerprint == "AA:BB"
        persisted = "\n".join([job.result or "", target.last_result, target.address])
        assert "super-secret" not in persisted

    second_port = client.post(
        "/vcf-trust/root-ca",
        data={
            **credentials,
            "address": "vcf-installer.example.test:8443",
            "confirmed_tls_fingerprint": "AA:BB",
        },
        headers={"X-Atlaso-VCF-Trust": "1"},
    )

    assert second_port.status_code == 202
    with SessionLocal() as db:
        targets = db.execute(select(VcfTrustTarget).order_by(VcfTrustTarget.api_port)).scalars().all()
        assert [(target.address, target.api_port) for target in targets] == [
            ("vcf-installer.example.test", 443),
            ("vcf-installer.example.test", 8443),
        ]


def test_vcf_trust_job_preserves_cancelled_state_at_progress_checkpoint(client, monkeypatch):
    """Verify that vcf trust job preserves cancelled state at progress checkpoint.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfTrustTarget
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.services.vcf_trust import VcfTrustCredentials, root_ca_info
    from atlaso.app.ui import get_ca_settings_row

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        ca = root_ca_info(settings)
        target = VcfTrustTarget(address="vcf-installer.example.test", api_port=443, tls_fingerprint="AA:BB")
        job = Job(id="job_vcf_trust_cancel", type="vcf-ca-trust", status=JobStatus.PENDING.value, created_by="admin")
        db.add(target)
        db.add(job)
        db.commit()
        target_id = target.id

    def fake_execute(*_args, progress, **_kwargs):
        """Handle fake execute.

        Args:
            progress: Progress supplied to the test scenario.
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        with SessionLocal() as db:
            job = db.get(Job, "job_vcf_trust_cancel")
            job.status = JobStatus.CANCELLED.value
            db.commit()
        progress(20, "checking-api")
        raise AssertionError("progress should raise before trust execution continues")

    monkeypatch.setattr(ui, "execute_vcf_trust", fake_execute)

    ui.run_vcf_trust_job(
        "job_vcf_trust_cancel",
        target_id,
        VcfTrustCredentials(api_username="admin", api_password="api"),
        ca,
    )

    with SessionLocal() as db:
        job = db.get(Job, "job_vcf_trust_cancel")
        target = db.get(VcfTrustTarget, target_id)
        assert job.status == JobStatus.CANCELLED.value
        assert job.progress_percent == 100
        assert "cancelled" in (job.result or "")
        assert target.last_result == "cancelled"


def test_vcf_target_depot_job_preserves_cancelled_state_at_progress_checkpoint(client, monkeypatch):
    """Verify that vcf target depot job preserves cancelled state at progress checkpoint.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.services.vcf_depot_target import LocalDepotEndpoint

    login(client)
    with SessionLocal() as db:
        job = Job(id="job_depot_cancel", type="vcf-offline-depot-target-config", status=JobStatus.PENDING.value, created_by="admin")
        db.add(job)
        db.commit()

    monkeypatch.setattr(
        ui,
        "_local_depot_endpoint",
        lambda _db: LocalDepotEndpoint(hostname="depot.atlaso.internal", port=443, url="https://depot.atlaso.internal", username="depot"),
    )

    def fake_configure(*_args, progress, **_kwargs):
        """Handle fake configure.

        Args:
            progress: Progress supplied to the test scenario.
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        with SessionLocal() as db:
            job = db.get(Job, "job_depot_cancel")
            job.status = JobStatus.CANCELLED.value
            db.commit()
        progress(55, "syncing-metadata")
        raise AssertionError("progress should raise before depot sync continues")

    monkeypatch.setattr(ui, "configure_target_depot", fake_configure)

    ui.run_vcf_target_depot_job(
        "job_depot_cancel",
        address="vcf-installer.example.test",
        port=443,
        api_username="admin",
        api_password="api",
        depot_password="depot",
        replace_existing=True,
        expected_fingerprint="AA:BB",
    )

    with SessionLocal() as db:
        job = db.get(Job, "job_depot_cancel")
        assert job.status == JobStatus.CANCELLED.value
        assert job.progress_percent == 100
        assert "cancelled" in (job.result or "")


def test_vcf_helper_generates_dns_records_with_component_descriptions(client):
    """Verify that vcf helper generates dns records with component descriptions.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "",
            "suffix": "",
            "start_ipv4": "192.168.210.10/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["created"]) == 17
    assert payload["created"][0] == {
        "host": "vc01",
        "host_label": "vc01",
        "fqdn": "vc01.atlaso.internal",
        "description": "vCenter",
        "address": "192.168.210.10",
        "record_type": "A",
    }
    with SessionLocal() as db:
        vc_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "vc01.atlaso.internal")).scalar_one()
        automation = db.execute(select(DnsRecord).where(DnsRecord.hostname == "auto-vip.atlaso.internal")).scalar_one()
        license_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "license.atlaso.internal")).scalar_one()
        assert vc_record.record_type == "A"
        assert vc_record.address == "192.168.210.10"
        assert vc_record.description == "vCenter"
        assert automation.description == "VCF Automation"
        assert license_record.description == "License Server"


def test_vcf_helper_vvf_target_generates_subset(client):
    """Verify that vcf helper vvf target generates subset.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "target": "vvf-9.1",
            "domain": "atlaso.internal",
            "prefix": "vvf",
            "suffix": "",
            "start_ipv4": "192.168.211.10/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert [row["host"] for row in payload["created"]] == ["vc01", "ops01", "vsp01", "fleetlcm", "shared01", "license"]
    assert [row["address"] for row in payload["created"]] == [
        "192.168.211.10",
        "192.168.211.11",
        "192.168.211.12",
        "192.168.211.13",
        "192.168.211.14",
        "192.168.211.15",
    ]
    with SessionLocal() as db:
        nsx = db.execute(select(DnsRecord).where(DnsRecord.hostname == "vvfnsx01.atlaso.internal")).scalar_one_or_none()
        vcenter = db.execute(select(DnsRecord).where(DnsRecord.hostname == "vvfvc01.atlaso.internal")).scalar_one()
        license_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "vvflicense.atlaso.internal")).scalar_one()
        assert nsx is None
        assert vcenter.description == "vCenter"
        assert license_record.description == "License Server"


def test_vcf_helper_shows_existing_address_record_addresses_in_preview(client):
    """Verify that vcf helper shows existing address record addresses in preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                DnsRecord(
                    hostname="vc01.atlaso.internal",
                    record_type="A",
                    address="192.168.219.55",
                    description="existing vCenter",
                    enabled=True,
                ),
                DnsRecord(
                    hostname="vc01.atlaso.internal",
                    record_type="AAAA",
                    address="2001:db8:219::55",
                    description="existing vCenter IPv6",
                    enabled=True,
                ),
            ]
        )
        db.commit()

    response = client.get("/vcf-helper")

    assert response.status_code == 200
    assert 'data-existing-address-records=' in response.text
    assert '"vc01.atlaso.internal": ["192.168.219.55", "2001:db8:219::55"]' in response.text
    assert "192.168.219.55" in response.text
    assert "2001:db8:219::55" in response.text


def test_vcf_helper_prefix_suffix_and_ip_collision_skips(client):
    """Verify that vcf helper prefix suffix and ip collision skips.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpReservation, DnsRecord

    login(client)
    with SessionLocal() as db:
        db.add(DnsRecord(hostname="pvc01a.atlaso.internal", record_type="A", address="192.168.220.90", description="manual", enabled=True))
        db.add(DnsRecord(hostname="occupied.atlaso.internal", record_type="A", address="192.168.220.10", description="manual", enabled=True))
        db.add(DhcpReservation(hostname="reserved.atlaso.internal", mac_address="02:00:00:00:22:11", ip_address="192.168.220.11", enabled=True))
        db.commit()

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "p",
            "suffix": "a",
            "start_ipv4": "192.168.220.10/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert [row["fqdn"] for row in payload["skipped"]] == ["pvc01a.atlaso.internal"]
    assert payload["skipped"][0]["address"] == "192.168.220.90"
    assert payload["created"][0]["fqdn"] == "pnsx01a.atlaso.internal"
    assert payload["created"][0]["address"] == "192.168.220.12"
    with SessionLocal() as db:
        skipped = db.execute(select(DnsRecord).where(DnsRecord.hostname == "pvc01a.atlaso.internal")).scalar_one()
        created = db.execute(select(DnsRecord).where(DnsRecord.hostname == "pnsx01a.atlaso.internal")).scalar_one()
        assert skipped.address == "192.168.220.90"
        assert skipped.description == "manual"
        assert created.address == "192.168.220.12"
        assert created.description == "NSX Manager cluster"


def test_vcf_helper_ipv6_generation_creates_aaaa_records_and_skips_collisions(client):
    """Verify that vcf helper ipv6 generation creates aaaa records and skips collisions.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        db.add(DnsRecord(hostname="v6vc01.atlaso.internal", record_type="AAAA", address="2001:db8:240::99", description="manual IPv6", enabled=True))
        db.add(DnsRecord(hostname="occupied6.atlaso.internal", record_type="AAAA", address="2001:db8:240::10", description="manual IPv6", enabled=True))
        db.commit()

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "v6",
            "suffix": "",
            "start_ipv4": "2001:db8:240::10/64",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["skipped"][0]["fqdn"] == "v6vc01.atlaso.internal"
    assert payload["skipped"][0]["address"] == "2001:db8:240::99"
    assert payload["created"][0]["fqdn"] == "v6nsx01.atlaso.internal"
    assert payload["created"][0]["record_type"] == "AAAA"
    assert payload["created"][0]["address"] == "2001:db8:240::11"
    with SessionLocal() as db:
        created = db.execute(select(DnsRecord).where(DnsRecord.hostname == "v6nsx01.atlaso.internal")).scalar_one()
        skipped = db.execute(select(DnsRecord).where(DnsRecord.hostname == "v6vc01.atlaso.internal")).scalar_one()
        assert created.record_type == "AAAA"
        assert created.address == "2001:db8:240::11"
        assert created.description == "NSX Manager cluster"
        assert skipped.address == "2001:db8:240::99"
        assert skipped.description == "manual IPv6"


def test_vcf_helper_insufficient_addresses_creates_nothing(client):
    """Verify that vcf helper insufficient addresses creates nothing.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import func, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        before = db.scalar(select(func.count()).select_from(DnsRecord))

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "edge",
            "suffix": "",
            "start_ipv4": "255.255.255.250/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 422
    assert "Not enough available IPv4 addresses remain in 255.255.255.0/24" in response.text
    with SessionLocal() as db:
        after = db.scalar(select(func.count()).select_from(DnsRecord))
        assert after == before
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "edgevc01.atlaso.internal")).scalar_one_or_none() is None


def test_vcf_helper_insufficient_ipv6_addresses_creates_nothing(client):
    """Verify that vcf helper insufficient ipv6 addresses creates nothing.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import func, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        before = db.scalar(select(func.count()).select_from(DnsRecord))

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "edge6",
            "suffix": "",
            "start_ipv4": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 422
    assert "Not enough available IPv6 addresses remain in ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127" in response.text
    with SessionLocal() as db:
        after = db.scalar(select(func.count()).select_from(DnsRecord))
        assert after == before
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "edge6vc01.atlaso.internal")).scalar_one_or_none() is None


def test_vcf_helper_rejects_network_or_broadcast_start_address(client):
    """Verify that vcf helper rejects network or broadcast start address.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import func, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        before = db.scalar(select(func.count()).select_from(DnsRecord))

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "boundary",
            "suffix": "",
            "start_ipv4": "192.168.230.0/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 422
    assert "must be a usable host address in 192.168.230.0/24" in response.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(DnsRecord)) == before


def test_vcf_helper_delete_removes_owned_records_and_preserves_skipped_existing(client):
    """Verify that vcf helper delete removes owned records and preserves skipped existing.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        db.add(
            DnsRecord(
                hostname="delvc01.atlaso.internal",
                record_type="A",
                address="192.168.231.90",
                description="manual record",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "domain": "atlaso.internal",
            "prefix": "del",
            "suffix": "",
            "start_ipv4": "192.168.231.10/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )
    assert created.status_code == 200
    assert len(created.json()["created"]) == 16
    assert len(created.json()["skipped"]) == 1

    deleted = client.post(
        "/vcf-helper/generated-fqdns/delete",
        data={
            "domain": "atlaso.internal",
            "prefix": "del",
            "suffix": "",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert deleted.status_code == 200
    payload = deleted.json()
    assert len(payload["deleted"]) == 16
    assert [row["fqdn"] for row in payload["preserved"]] == ["delvc01.atlaso.internal"]
    with SessionLocal() as db:
        manual = db.execute(select(DnsRecord).where(DnsRecord.hostname == "delvc01.atlaso.internal")).scalar_one()
        removed = db.execute(select(DnsRecord).where(DnsRecord.hostname == "delnsx01.atlaso.internal")).scalar_one_or_none()
        assert manual.address == "192.168.231.90"
        assert manual.description == "manual record"
        assert removed is None


def test_vcf_helper_delete_vvf_target_removes_only_subset(client):
    """Verify that vcf helper delete vvf target removes only subset.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vcf-helper/generated-fqdns",
        data={
            "target": "vcf-9.1",
            "domain": "atlaso.internal",
            "prefix": "vdel",
            "suffix": "",
            "start_ipv4": "192.168.233.10/24",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )
    assert created.status_code == 200
    assert len(created.json()["created"]) == 17

    deleted = client.post(
        "/vcf-helper/generated-fqdns/delete",
        data={
            "target": "vvf-9.1",
            "domain": "atlaso.internal",
            "prefix": "vdel",
            "suffix": "",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert deleted.status_code == 200
    assert [row["host"] for row in deleted.json()["deleted"]] == ["vc01", "ops01", "vsp01", "fleetlcm", "shared01", "license"]
    with SessionLocal() as db:
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "vdelvc01.atlaso.internal")).scalar_one_or_none() is None
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "vdelnsx01.atlaso.internal")).scalar_one() is not None


def test_vcf_helper_delete_recognizes_legacy_generated_records(client):
    """Verify that vcf helper delete recognizes legacy generated records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    with SessionLocal() as db:
        db.add(
            DnsRecord(
                hostname="legacyvc01.atlaso.internal",
                record_type="A",
                address="192.168.232.10",
                record_data_json="",
                description="vCenter",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns/delete",
        data={
            "domain": "atlaso.internal",
            "prefix": "legacy",
            "suffix": "",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 200
    assert [row["fqdn"] for row in response.json()["deleted"]] == ["legacyvc01.atlaso.internal"]
    with SessionLocal() as db:
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "legacyvc01.atlaso.internal")).scalar_one_or_none() is None


def test_vcf_helper_delete_removes_owned_aaaa_records(client):
    """Verify that vcf helper delete removes owned aaaa records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord
    from atlaso.app.services.dnsmasq import dump_dns_record_data

    login(client)
    with SessionLocal() as db:
        db.add(
            DnsRecord(
                hostname="ipv6delvc01.atlaso.internal",
                record_type="AAAA",
                address="2001:db8:232::10",
                record_data_json=dump_dns_record_data("AAAA", "2001:db8:232::10", {"source": "vcf_helper", "component": "vc01"}),
                description="vCenter",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vcf-helper/generated-fqdns/delete",
        data={
            "domain": "atlaso.internal",
            "prefix": "ipv6del",
            "suffix": "",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Helper": "1"},
    )

    assert response.status_code == 200
    assert response.json()["deleted"][0]["record_type"] == "AAAA"
    with SessionLocal() as db:
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "ipv6delvc01.atlaso.internal")).scalar_one_or_none() is None
















def test_vcf_sddc_inventory_requires_tls_confirmation_and_redacts_credentials(client, monkeypatch):
    """Verify that vcf sddc inventory requires tls confirmation and redacts credentials.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.services.vcf_sddc_deployment import OvaDescriptor, OvfProperty

    login(client)
    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    descriptor = OvaDescriptor(
        path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF/test.ova",
        relative_path="test.ova",
        filename="test.ova",
        size_bytes=10,
        vm_name="sddc-test",
        ovf_member="test.ovf",
        manifest_member="test.mf",
        networks=["Network 1"],
        properties=[OvfProperty("ROOT_PASSWORD", "string", "Root", "secret", "", "", True, True)],
        files=[],
    )
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.inspect_ova", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.vsphere_inventory", lambda *_args, **_kwargs: {"resource_pools": [], "datastores": [], "folders": [], "hosts": [], "networks": []})
    resolved_credentials = []
    original_resolver = ui._resolve_vcf_helper_credentials

    def track_resolver(*args, **kwargs):
        """Return track resolver.

        Args:
            *args: Additional positional arguments accepted by the callable.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        resolved_credentials.append(kwargs["purpose"])
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(ui, "_resolve_vcf_helper_credentials", track_resolver)
    payload = {"csrf": csrf, "address": "vc.example", "port": 443, "username": "admin", "password": "top-secret", "ova_path": descriptor.path}

    confirmation = client.post("/vcf-helper/sddc-manager/inventory", json=payload)
    assert confirmation.status_code == 409
    assert confirmation.json()["fingerprint"] == "AA:BB"
    assert resolved_credentials == []

    deploy_confirmation = client.post("/vcf-helper/sddc-manager/deploy", json=payload)
    assert deploy_confirmation.status_code == 409
    assert deploy_confirmation.json()["fingerprint"] == "AA:BB"
    assert resolved_credentials == []

    ready = client.post("/vcf-helper/sddc-manager/inventory", json={**payload, "confirmed_tls_fingerprint": "AA:BB"})
    assert ready.status_code == 200
    assert resolved_credentials == ["sddc_inventory"]
    assert "top-secret" not in ready.text
    assert ready.json()["ova"]["properties"][0]["password"] is True


def test_vcf_target_depot_resolves_credentials_only_after_tls_confirmation(client, monkeypatch):
    """Verify that vcf target depot resolves credentials only after tls confirmation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

    login(client)
    csrf = client.get("/vcf-helper").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    local = {
        "available": True,
        "reasons": [],
        "hostname": "depot.atlaso.internal",
        "port": 443,
        "url": "https://depot.atlaso.internal",
        "username": "atlaso",
    }
    monkeypatch.setattr(ui, "local_vcf_depot_target_context", lambda _db: local)
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr(
        "atlaso.app.routers.ui.vcf_workflows.inspect_target_depot",
        lambda *_args, **_kwargs: {
            "appliance": {"role": "VcfInstaller", "version": "9.1.0.0"},
            "depot": {},
        },
    )
    resolved_credentials = []
    original_resolver = ui._resolve_vcf_helper_credentials

    def track_resolver(*args, **kwargs):
        """Return track resolver.

        Args:
            *args: Additional positional arguments accepted by the callable.
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        resolved_credentials.append(kwargs["purpose"])
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(ui, "_resolve_vcf_helper_credentials", track_resolver)
    payload = {
        "csrf": csrf,
        "address": "vcf-installer.example.test",
        "api_username": "admin@local",
        "api_password": "api-secret",
        "depot_password": "depot-secret",
    }

    inspect_confirmation = client.post("/vcf-helper/offline-depot/inspect-target", json=payload)
    assert inspect_confirmation.status_code == 409
    assert inspect_confirmation.json()["fingerprint"] == "AA:BB"
    assert resolved_credentials == []

    configure_confirmation = client.post("/vcf-helper/offline-depot/configure", json=payload)
    assert configure_confirmation.status_code == 409
    assert configure_confirmation.json()["fingerprint"] == "AA:BB"
    assert resolved_credentials == []

    ready = client.post(
        "/vcf-helper/offline-depot/inspect-target",
        json={**payload, "confirmed_tls_fingerprint": "AA:BB"},
    )
    assert ready.status_code == 200
    assert resolved_credentials == ["offline_depot_inspect"]
    assert ready.json()["status"] == "ready"
    assert ready.json()["tls_fingerprint"] == "AA:BB"
    assert "api-secret" not in ready.text
    assert "depot-secret" not in ready.text


def test_vcf_sddc_deploy_job_persists_no_passwords(client, monkeypatch):
    """Verify that vcf sddc deploy job persists no passwords.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import json

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.vcf_sddc_deployment import OvaDescriptor, OvfProperty

    login(client)
    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    descriptor = OvaDescriptor(
        path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF/test.ova",
        relative_path="test.ova",
        filename="test.ova",
        size_bytes=10,
        vm_name="sddc-test",
        ovf_member="test.ovf",
        manifest_member="test.mf",
        networks=["Network 1"],
        properties=[
            OvfProperty("ROOT_PASSWORD", "string", "Root", "", "", "", True, True),
            OvfProperty("LOCAL_USER_PASSWORD", "string", "Local", "", "", "", True, True),
            OvfProperty("vami.hostname", "string", "FQDN", "", "", "", False, True),
        ],
        files=[],
    )
    queued = {}
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.inspect_ova", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(ui, "queue_vcf_sddc_deployment_job", lambda job_id, **kwargs: queued.update({"job_id": job_id, **kwargs}))
    response = client.post(
        "/vcf-helper/sddc-manager/deploy",
        json={
            "csrf": csrf,
            "address": "vc.example",
            "port": 443,
            "username": "administrator",
            "password": "vsphere-secret",
            "confirmed_tls_fingerprint": "AA:BB",
            "ova_path": descriptor.path,
            "vm_name": "sddc-test",
            "properties": {"ROOT_PASSWORD": "root-secret", "LOCAL_USER_PASSWORD": "local-secret", "vami.hostname": "sddc.example"},
            "destination": {"resource_pool_id": "resgroup-1", "datastore_id": "datastore-1", "network_ids": {"Network 1": "network-1"}},
            "options": {"disk_provisioning": "thick"},
        },
    )
    assert response.status_code == 202
    assert queued["endpoint_password"] == "vsphere-secret"
    assert queued["disk_provisioning"] == "thick"
    assert queued["power_on"] is True
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        persisted = json.dumps(json.loads(job.result))
    assert "vsphere-secret" not in persisted
    assert "root-secret" not in persisted
    assert "local-secret" not in persisted
    assert "thick" in persisted
    assert "power_on" in persisted

    powered_off_dns = client.post(
        "/vcf-helper/sddc-manager/deploy",
        json={
            "csrf": csrf,
            "address": "vc.example",
            "port": 443,
            "username": "administrator",
            "password": "vsphere-secret",
            "confirmed_tls_fingerprint": "AA:BB",
            "ova_path": descriptor.path,
            "vm_name": "sddc-test-powered-off",
            "properties": {"ROOT_PASSWORD": "root-secret", "LOCAL_USER_PASSWORD": "local-secret", "vami.hostname": "sddc.example"},
            "destination": {"resource_pool_id": "resgroup-1", "datastore_id": "datastore-1", "network_ids": {"Network 1": "network-1"}},
            "options": {"power_on": False, "add_dns": True},
        },
    )
    assert powered_off_dns.status_code == 202
    assert queued["power_on"] is False
    assert queued["add_dns"] is True
    assert queued["apply_trust"] is False
    assert queued["configure_offline_depot"] is False

    rejected = client.post(
        "/vcf-helper/sddc-manager/deploy",
        json={
            "csrf": csrf,
            "address": "vc.example",
            "port": 443,
            "username": "administrator",
            "password": "vsphere-secret",
            "confirmed_tls_fingerprint": "AA:BB",
            "ova_path": descriptor.path,
            "vm_name": "sddc-test-powered-off-trust",
            "properties": {"ROOT_PASSWORD": "root-secret", "LOCAL_USER_PASSWORD": "local-secret", "vami.hostname": "sddc.example"},
            "destination": {"resource_pool_id": "resgroup-1", "datastore_id": "datastore-1", "network_ids": {"Network 1": "network-1"}},
            "options": {"power_on": False, "apply_trust": True},
        },
    )
    assert rejected.status_code == 422
    assert "require Power on" in rejected.json()["detail"]


def test_vcf_sddc_endpoint_address_parses_inline_port():
    """Verify that vcf sddc endpoint address parses inline port."""
    from atlaso.app import ui

    assert ui._split_vcf_endpoint_address_port("vc.example:8443") == ("vc.example", 8443)
    assert ui._split_vcf_endpoint_address_port("https://vc.example/sdk", None) == ("vc.example", 443)
    assert ui._split_vcf_endpoint_address_port("[2001:db8::10]:9443") == ("2001:db8::10", 9443)


def test_vcf_sddc_deploy_waits_on_ip_before_new_dns_name(client, monkeypatch):
    """Verify that vcf sddc deploy waits on ip before new dns name.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.services.vcf_sddc_deployment import OvaDescriptor

    login(client)
    with SessionLocal() as db:
        db.add(Job(id="job_sddc_ip_first", type="vcf-sddc-manager-deploy", status=JobStatus.PENDING.value, created_by="admin"))
        db.commit()

    descriptor = OvaDescriptor(
        path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF/test.ova",
        relative_path="test.ova",
        filename="test.ova",
        size_bytes=10,
        vm_name="sddc-test",
        ovf_member="test.ovf",
        manifest_member="test.mf",
        networks=[],
        properties=[],
        files=[],
    )
    waited_on = []
    monkeypatch.setattr(ui, "inspect_ova", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(ui, "deploy_ova", lambda *_args, **_kwargs: {"vm_name": "sddc-test", "guest_ip": "192.168.87.18"})
    monkeypatch.setattr(ui, "_wait_for_vcf_api", lambda address, *_args, **_kwargs: waited_on.append(address) or {"role": "SddcManager", "version": "9.1.0.0"})

    ui.run_vcf_sddc_deployment_job(
        "job_sddc_ip_first",
        ova_path=descriptor.path,
        endpoint="esxi.example.test",
        endpoint_username="root",
        endpoint_password="vsphere-secret",
        endpoint_fingerprint="AA:BB",
        destination={"resource_pool_id": "ha-root-pool", "datastore_id": "datastore1", "network_ids": {}},
        vm_name="sddc-test",
        disk_provisioning="thin",
        power_on=True,
        property_values={
            "LOCAL_USER_PASSWORD": "local-secret",
            "vami.hostname": "sddcm.atlaso.internal",
            "ip0": "192.168.87.19",
        },
        add_dns=True,
        apply_trust=False,
        configure_offline_depot=False,
        depot_password="",
    )

    assert waited_on == ["192.168.87.18"]
    with SessionLocal() as db:
        job = db.get(Job, "job_sddc_ip_first")
        assert job.status == JobStatus.SUCCEEDED.value
        assert '"target": "192.168.87.18"' in (job.result or "")
        assert "sddcm.atlaso.internal" in (job.result or "")


def test_vcf_sddc_deploy_requires_ipv4_ova_properties(client, monkeypatch):
    """Verify that vcf sddc deploy requires ipv4 ova properties.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.services.vcf_sddc_deployment import OvaDescriptor, OvfProperty

    login(client)
    page = client.get("/vcf-helper")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    descriptor = OvaDescriptor(
        path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/SDDC_MANAGER_VCF/test.ova",
        relative_path="test.ova",
        filename="test.ova",
        size_bytes=10,
        vm_name="sddc-test",
        ovf_member="test.ovf",
        manifest_member="test.mf",
        networks=["Network 1"],
        properties=[
            OvfProperty("ROOT_PASSWORD", "string", "Root", "", "", "MinLen(15)", True, True),
            OvfProperty("LOCAL_USER_PASSWORD", "string", "Local", "", "", "MinLen(15)", True, True),
            OvfProperty("vami.hostname", "string", "FQDN", "", "", "", False, True),
            OvfProperty("ip_address_version", "string", "IP version", "", "IPv4", 'ValueMap{"IPv4","IPv4 and IPv6"}', False, True),
            OvfProperty("ip0", "string", "Network 1 IPv4 Address", "", "", "", False, True),
            OvfProperty("netmask0", "string", "Network 1 Subnet Mask", "", "", "", False, True),
            OvfProperty("gateway", "string", "Network Default IPv4 Gateway", "", "", "", False, True),
            OvfProperty("DNS", "string", "Domain Name Servers", "", "", "", False, True),
        ],
        files=[],
    )
    queued = {}
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr("atlaso.app.routers.ui.vcf_workflows.inspect_ova", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(ui, "queue_vcf_sddc_deployment_job", lambda job_id, **kwargs: queued.update({"job_id": job_id, **kwargs}))

    response = client.post(
        "/vcf-helper/sddc-manager/deploy",
        json={
            "csrf": csrf,
            "address": "vc.example",
            "port": 443,
            "username": "administrator",
            "password": "vsphere-secret",
            "confirmed_tls_fingerprint": "AA:BB",
            "ova_path": descriptor.path,
            "vm_name": "sddc-test",
            "properties": {
                "ROOT_PASSWORD": "RootPassword123!",
                "LOCAL_USER_PASSWORD": "LocalPassword123!",
                "vami.hostname": "sddc.example",
                "ip_address_version": "IPv4",
            },
            "destination": {"resource_pool_id": "resgroup-1", "datastore_id": "datastore-1", "network_ids": {"Network 1": "network-1"}},
            "options": {},
        },
    )

    assert response.status_code == 422
    assert "Network 1 IPv4 Address" in response.json()["detail"]
    assert "Domain Name Servers" in response.json()["detail"]
    assert queued == {}


def test_recover_interrupted_vcf_helper_jobs_discards_transient_work(client):
    """Verify that recover interrupted vcf helper jobs discards transient work.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.ui import recover_interrupted_vcf_helper_jobs

    with SessionLocal() as db:
        job = Job(id="job_interrupted_vcf", type="vcf-sddc-manager-deploy", status="running", created_by="admin", result='{"state":"uploading-ova"}')
        db.add(job)
        db.commit()
        assert recover_interrupted_vcf_helper_jobs(db) == 1
        db.refresh(job)
        assert job.status == "failed"
        assert "Transient credentials were discarded" in job.error

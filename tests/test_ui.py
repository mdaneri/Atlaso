def login(client):
    page = client.get("/login")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def assert_apply_redirect(response):
    assert response.status_code == 200
    assert response.url.path == "/tasks"
    assert response.history
    assert response.history[0].status_code == 303
    assert response.history[0].headers["location"].startswith("/tasks?job_id=job_")
    assert "Appliance Apply" in response.text


def create_api_token(client, scopes):
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "test token", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_login_and_dashboard_render(client):
    from pathlib import Path

    login(client)
    root = client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/dashboard"
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "Atlaso" in response.text
    assert "Routes &amp; WAN Simulation" in response.text
    assert "VCF Offline Depot" in response.text
    assert "HTTPS Repository" not in response.text
    assert "Users" in response.text
    assert "LDAP / Users" not in response.text
    assert 'href="/monitor"' in response.text
    nav = response.text.split('<nav class="nav-stack"', 1)[1].split("</nav>", 1)[0]
    for section in ["Overview", "Appliance Setup", "Core Services", "Identity &amp; Trust", "VCF Workflows", "Operations"]:
        assert section in nav
    expected_nav_order = [
        "/dashboard",
        "/monitor",
        "/settings",
        "/physical-interfaces",
        "/vlan-interfaces",
        "/routes-wan",
        "/firewall",
        "/dns",
        "/ntp",
        "/dhcp",
        "/authentication",
        "/users",
        "/ldap",
        "/certificate-authority",
        "/kms",
        "/esxi-pxe",
        "/esx-storage",
        "/vcf-helper",
        "/vcf-offline-depot",
        "/vcf-private-registry",
        "/vcf-backups",
        "/services",
        "/tasks",
        "/logs",
        "/audit-log",
        "/appliance-update",
        "/backup-restore",
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
    server_time_response = client.get("/server-time")
    assert server_time_response.status_code == 200
    assert server_time_response.json()["label"].startswith("Server ")
    app_js = Path("atlaso/app/static/app.js").read_text()
    assert "function initializeServerTime()" in app_js
    assert 'window.setInterval(sync, 60000)' in app_js
    assert "data-account-menu" in response.text
    assert 'aria-label="Open account menu for admin"' in response.text
    assert "About" in response.text
    assert "Sign out (admin)" in response.text
    assert 'action="/appliance/power/reboot"' in response.text
    assert 'action="/appliance/power/shutdown"' in response.text
    assert 'data-confirm-title="Reboot Atlaso appliance?"' in response.text
    assert 'data-confirm-title="Shut down Atlaso appliance?"' in response.text
    assert 'id="about-modal"' in response.text
    assert 'class="about-brand-mark" src="/static/brand/atlaso-icon.svg"' in response.text
    assert '<span class="role-chip">admin</span>' not in response.text
    assert 'href="/logs"' in response.text
    assert 'href="/audit-log"' in response.text
    assert "cdn.tailwindcss.com" not in response.text
    assert "unpkg.com/htmx" not in response.text
    assert 'body class="bg-slate-100 text-slate-900"' not in response.text
    assert "/static/brand/atlaso-icon.svg" in response.text
    assert 'class="management-info-footnote"' in response.text
    from atlaso import __version__

    assert f"Atlaso {__version__}" in response.text
    assert 'href="/api/docs"' in response.text
    assert "Python " in response.text
    assert '<link rel="icon" href="/favicon.ico" type="image/x-icon">' in response.text
    assert '<link rel="manifest" href="/manifest.webmanifest">' in response.text
    assert '<meta name="theme-color"' not in response.text
    assert "/static/pwa.js?v=atlaso-brand-20260725-1" in response.text
    assert "Everything your virtualization lab needs." in response.text
    assert "Infrastructure • Storage • Identity • Networking • Lifecycle" in response.text
    assert "simplifying deployment, maintenance, and validation" in response.text
    assert "LF</span>" not in response.text
    assert "/static/vendor/prism/prism-core.min.js" in response.text
    assert "/static/vendor/prism/prism-diff.min.js" in response.text


def test_web_terminal_requires_login_and_renders_admin_only_unavailable_state(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    unauthenticated = client.get("/terminal", follow_redirects=False)
    assert unauthenticated.status_code == 303
    assert unauthenticated.headers["location"] == "/login?next=/terminal"

    login(client)
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.web_terminal_access = False
        db.commit()
    response = client.get("/terminal")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "Appliance Web Terminal" in response.text
    assert "Terminal status for admin" in response.text
    assert "No shell starts until the requirement below is resolved." in response.text
    assert "Passwordless local SSH as admin" not in response.text
    assert "Web terminal access is disabled in Appliance Settings." in response.text
    assert '"detail":' not in response.text
    assert "/static/vendor/xterm/xterm.js?v=5.5.0" in response.text
    assert "/static/terminal.js?v=atlaso-vault-uri-20260727-2" in response.text
    assert "data-terminal-connect" not in response.text
    assert "data-terminal-disconnect" not in response.text

    dashboard = client.get("/dashboard")
    assert 'href="/terminal"' in dashboard.text
    assert dashboard.text.count('href="/terminal"') == 1
    assert '<a class="account-menu-item" href="/terminal"' not in dashboard.text
    assert dashboard.text.index("Operations") < dashboard.text.index('href="/terminal"') < dashboard.text.index('href="/services"')


def test_disabled_web_terminal_page_accepts_only_management_listener(client, monkeypatch):
    from types import SimpleNamespace

    from atlaso.app import web_terminal

    allowed_addresses = []

    def capture_listener(_headers, _client_host, addresses):
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
    response = client.get("/terminal")

    assert response.status_code == 200
    assert allowed_addresses == ["192.168.49.1"]
    assert "Web terminal access is disabled in Appliance Settings." in response.text


def test_public_web_terminal_uses_public_shell_and_explicit_user_access(client, monkeypatch):
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
        dry_run = False

        def authenticate_local_user(self, username: str, password: str) -> AdapterResult:
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

    login_page = client.get("/login?next=/terminal", headers={"host": "192.168.87.32"})
    assert login_page.status_code == 200
    assert "Sign in to Web Terminal" in login_page.text
    assert 'class="public-portal-shell"' in login_page.text
    assert 'class="app-shell"' not in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        headers={"host": "192.168.87.32"},
        data={"username": "test", "password": "Test-user1!", "csrf": csrf, "next": "/terminal"},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    assert signed_in.headers["location"] == "/terminal"

    terminal = client.get("/terminal", headers={"host": "192.168.87.32"})
    assert terminal.status_code == 200
    assert "Passwordless local SSH as test" in terminal.text
    assert 'class="public-portal-shell"' in terminal.text
    assert 'class="app-shell"' not in terminal.text
    assert "Back to Public Services" not in terminal.text
    assert 'action="/logout"' in terminal.text
    assert 'name="next" value="/terminal"' in terminal.text

    with SessionLocal() as db:
        user = db.get(User, user_id)
        user.web_terminal_access = False
        db.commit()
    denied = client.get("/terminal", headers={"host": "192.168.87.32"})
    assert denied.status_code == 403
    assert "Web SSH access is not enabled" in denied.text
    logout = client.post(
        "/logout",
        headers={"host": "192.168.87.32"},
        data={"csrf": csrf, "next": "/terminal"},
        follow_redirects=False,
    )
    assert logout.status_code == 303
    assert logout.headers["location"] == "/login?next=/terminal"


def test_web_terminal_uses_one_use_ticket_and_bridges_websocket_input(client, monkeypatch):
    import threading
    from types import SimpleNamespace

    from sqlalchemy import select

    from atlaso.app import web_terminal
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, User

    class FakeChannel:
        def __init__(self):
            self.closed = False
            self.sent = []
            self.output_sent = False
            self.finished = threading.Event()

        def recv(self, _size):
            if not self.output_sent:
                self.output_sent = True
                return b"shell ready\r\n"
            self.finished.wait(timeout=2)
            return b""

        def sendall(self, data):
            self.sent.append(data)
            self.closed = True
            self.finished.set()

        def resize_pty(self, **_kwargs):
            return None

        def close(self):
            self.closed = True
            self.finished.set()

    class FakeTransport:
        def close(self):
            return None

    channel = FakeChannel()
    open_count = 0

    def open_channel(*_args):
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

    page = client.get("/terminal")
    assert page.status_code == 200
    assert "data-terminal-reconnect" in page.text
    assert "data-terminal-copy" in page.text
    assert "data-terminal-download" in page.text
    assert "data-terminal-connect" not in page.text
    assert "data-terminal-disconnect" not in page.text
    csrf = page.text.split('data-csrf="', 1)[1].split('"', 1)[0]
    ticket_response = client.post(
        "/terminal/tickets",
        data={"csrf": csrf, "browser_session_id": "browser_session_1234"},
    )
    assert ticket_response.status_code == 200
    assert ticket_response.headers["cache-control"] == "no-store"
    ticket = ticket_response.json()["ticket"]

    with client.websocket_connect("/terminal/ws", headers={"origin": "http://testserver"}) as websocket:
        websocket.send_json({"type": "authenticate", "ticket": ticket})
        first_ready = websocket.receive_json()
        assert first_ready["type"] == "ready"
        assert first_ready["resumed"] is False
        assert websocket.receive_bytes() == b"shell ready\r\n"

        reload_ticket = client.post(
            "/terminal/tickets",
            data={"csrf": csrf, "browser_session_id": "browser_session_1234"},
        )
        assert reload_ticket.status_code == 200
        with client.websocket_connect("/terminal/ws", headers={"origin": "http://testserver"}) as reloaded_websocket:
            reloaded_websocket.send_json({"type": "authenticate", "ticket": reload_ticket.json()["ticket"]})
            reload_ready = reloaded_websocket.receive_json()
            assert reload_ready["type"] == "ready"
            assert reload_ready["resumed"] is True
            assert reloaded_websocket.receive_bytes() == b"shell ready\r\n"

        conflict = client.post(
            "/terminal/tickets",
            data={"csrf": csrf, "browser_session_id": "other_browser_1234"},
        )
        assert conflict.status_code == 409
        assert conflict.json()["error_code"] == "TERMINAL_SESSION_ACTIVE"

        takeover = client.post(
            "/terminal/tickets",
            data={"csrf": csrf, "browser_session_id": "other_browser_1234", "takeover": "true"},
        )
        assert takeover.status_code == 200
        with client.websocket_connect("/terminal/ws", headers={"origin": "http://testserver"}) as moved_websocket:
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
    favicon = client.get("/favicon.ico")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/x-icon")
    terminal_js = client.get("/static/terminal.js")
    assert 'JSON.stringify({ type: "input", data })' in terminal_js.text
    assert 'data === "\\u0004" ? "exit\\r" : data' not in terminal_js.text


def test_appliance_power_action_creates_task_before_scheduling(client, monkeypatch):
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job, JobStatus
    from atlaso.app.ui import SystemAdapter

    observed: list[tuple[str, str]] = []

    def fake_schedule(_self, action: str) -> AdapterResult:
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
    assert response.headers["location"].startswith("/tasks?job_id=job_")
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
    from pathlib import Path

    app_css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    menu_css = app_css.split(".account-menu {", 1)[1].split(".inline-help-row", 1)[0]

    assert "var(--panel)" not in menu_css
    assert "var(--primary)" not in menu_css
    assert menu_css.count("background: var(--surface);") == 2
    assert "border-color: var(--accent);" in menu_css


def test_appliance_shutdown_task_reports_helper_failure(client, monkeypatch):
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
                result=json.dumps(
                    {
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
    assert 'href="/tasks"' in page.text
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
    assert 'headers: { Accept: "application/json" }' in app_js
    assert 'setApplianceUpdateActionsDisabled(true);' in app_js
    assert 'row.getElement().classList.toggle("task-grid-new-task"' in tasks_table_js
    assert "task-grid-new-badge" in tasks_table_js
    assert 'height: page.dataset.taskGridHeight || "100%"' in tasks_table_js
    assert 'query.set("filters", JSON.stringify(params.filters || params.filter || []));' in app_js
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
    manifest = client.get("/manifest.webmanifest")
    assert manifest.status_code == 200
    assert manifest.headers["content-type"].startswith("application/manifest+json")
    assert manifest.headers["cache-control"] == "no-cache"
    manifest_json = manifest.json()
    assert manifest_json["name"] == "Atlaso"
    assert manifest_json["short_name"] == "Atlaso"
    assert manifest_json["start_url"] == "/dashboard"
    assert manifest_json["scope"] == "/"
    assert manifest_json["display"] == "standalone"
    assert manifest_json["background_color"] == "#071A3A"
    assert manifest_json["theme_color"] == "#1769E0"
    assert manifest_json["icons"][0]["src"] == "/static/brand/atlaso-app-icon-dark-192.png"
    assert manifest_json["icons"][1]["src"] == "/static/brand/atlaso-app-icon-dark-512.png"
    assert manifest_json["icons"][0]["purpose"] == "any maskable"

    service_worker = client.get("/service-worker.js")
    assert service_worker.status_code == 200
    assert service_worker.headers["content-type"].startswith("application/javascript")
    assert service_worker.headers["cache-control"] == "no-cache"
    assert service_worker.headers["service-worker-allowed"] == "/"
    assert "ATLASO_CACHE" in service_worker.text
    assert "atlaso-pwa-v178" in service_worker.text
    assert 'fetch(asset, { cache: "reload" })' in service_worker.text
    assert ".catch(() => undefined)" in service_worker.text
    assert 'request.mode === "navigate"' in service_worker.text
    assert 'caches.match("/static/offline.html")' in service_worker.text
    assert 'request.method !== "GET"' in service_worker.text
    assert 'url.pathname.startsWith("/ca/downloads/")' in service_worker.text
    assert 'url.pathname.startsWith("/certificate-authority/downloads/")' in service_worker.text
    assert 'url.pathname.startsWith("/api/")' in service_worker.text
    assert "hasDownloadLikePath(url)" in service_worker.text
    assert "accept.includes(\"text/html\") && !hasDownloadLikePath(url)" in service_worker.text
    assert "/static/vendor/codemirror/atlaso-codemirror.min.js" in service_worker.text
    assert "/static/app.css?v=atlaso-ui-foundation-20260727-3" in service_worker.text
    assert "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-4" in service_worker.text
    assert "/static/app.js?v=atlaso-oidc-admin-20260727-6" in service_worker.text

    registration = client.get("/static/pwa.js")
    assert registration.status_code == 200
    assert 'navigator.serviceWorker.register("/service-worker.js")' in registration.text

    offline = client.get("/static/offline.html")
    assert offline.status_code == 200
    assert "Appliance connection unavailable" in offline.text
    assert "/static/app.css?v=atlaso-ui-foundation-20260727-3" in offline.text


def test_shared_ui_pattern_shell_and_wizard_contracts(client):
    import re
    from pathlib import Path

    templates = Path("atlaso/app/templates")
    base = (templates / "base.html").read_text(encoding="utf-8")
    public_base = (templates / "public_portal_base.html").read_text(encoding="utf-8")
    for shell, app_asset in (
        (base, "/static/app.js?v=atlaso-vaults-20260727-14"),
        (public_base, "/static/app.js?v=atlaso-oidc-admin-20260727-6"),
    ):
        assert shell.index("/static/vendor/tabulator/tabulator.min.js") < shell.index(
            "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-4"
        )
        assert shell.index(
            "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-4"
        ) < shell.index(app_asset)

    wizard_templates = [
        templates / "automation.html",
        templates / "esx_storage.html",
        templates / "partials" / "vcf_trust_modal.html",
        templates / "partials" / "vcf_sddc_deploy_modal.html",
        templates / "partials" / "vcf_target_depot_modal.html",
    ]
    wizard_markup = "\n".join(
        path.read_text(encoding="utf-8") for path in wizard_templates
    )
    assert len(re.findall(r"<form\b[^>]*\bdata-atlaso-wizard(?:\s|>)", wizard_markup)) == 6
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


def test_every_existing_tabulator_uses_the_shared_grid_foundation(client):
    import re

    app_js = client.get("/static/app.js").text
    create_grid = "window.AtlasoUiPatterns.createGrid({"

    assert app_js.count(create_grid) == 39
    assert app_js.count('pattern: "direct-edit"') == 25
    assert app_js.count('pattern: "read-only"') == 8
    assert app_js.count('pattern: "wizard-backed"') == 6
    assert "new Tabulator(" not in app_js
    assert "new window.Tabulator(" not in app_js
    assert "atlaso-legacy-tabulator: #117" not in app_js

    def function_block(name):
        start = app_js.index(f"function {name}(")
        match = re.search(r"\n(?:async )?function ", app_js[start + 1:])
        end = len(app_js) if match is None else start + 1 + match.start()
        return app_js[start:end]

    single_grid_patterns = {
        "initializeDhcpLeasesTable": "read-only",
        "initializeCaProfilesTable": "direct-edit",
        "initializeCaCertificatesTable": "read-only",
        "initializeFirewallRulesTable": "direct-edit",
        "initializeManagedFirewallRulesTable": "direct-edit",
        "initializeServicesTable": "direct-edit",
        "initializeUsersTable": "direct-edit",
        "initializeKmsClientsTable": "direct-edit",
        "initializeKmsKeysTable": "direct-edit",
        "initializeNTPsecUpstreamsTable": "direct-edit",
        "initializeRoutesWanRoutingTable": "direct-edit",
        "initializeRoutesWanNatTable": "direct-edit",
        "initializeRoutesWanRoutesTable": "direct-edit",
        "initializeRoutesWanPoliciesTable": "direct-edit",
        "initializePhysicalInterfacesTable": "direct-edit",
        "initializeOidcGroupMappingsTable": "direct-edit",
        "initializeVlanInterfacesTable": "direct-edit",
        "initializeDnsRecordsTableElement": "direct-edit",
        "initializeDhcpScopesTable": "direct-edit",
        "initializeDhcpOptionsTable": "direct-edit",
        "initializeDhcpReservationsTable": "direct-edit",
        "initializeEsxiPxeHostsTable": "direct-edit",
        "initializeVcfRegistryBundlesTable": "direct-edit",
        "initializeVcfDepotProfilesTable": "direct-edit",
        "initializeVcfDepotTasksTable": "read-only",
        "initializeTasksPage": "read-only",
        "initializeAuditEventsTable": "read-only",
        "renderApplianceApplyTask": "read-only",
    }
    for name, pattern in single_grid_patterns.items():
        block = function_block(name)
        assert block.count(create_grid) == 1, name
        assert block.count(f'pattern: "{pattern}"') == 1, name

    ldap_block = function_block("initializeLdapDirectoryTables")
    assert ldap_block.count(create_grid) == 2
    assert ldap_block.count('pattern: "direct-edit"') == 2

    automation_block = function_block("initializeAutomationTables")
    assert automation_block.count(create_grid) == 3
    assert automation_block.count('pattern: "direct-edit"') == 1
    assert automation_block.count('pattern: "read-only"') == 1
    assert automation_block.count('pattern: "wizard-backed"') == 1

    storage_block = function_block("initializeEsxStorageTables")
    assert storage_block.count(create_grid) == 2
    assert storage_block.count('pattern: "wizard-backed"') == 2

    tasks_block = function_block("initializeTasksPage")
    assert "atlasoTasksReopenSelected = shouldOpenSelected;" in tasks_block
    assert "if (!atlasoTasksTable) {" in tasks_block


def test_reported_template_accessibility_contracts():
    from pathlib import Path

    templates = Path("atlaso/app/templates")
    appliance_update = (templates / "appliance_update.html").read_text(encoding="utf-8")
    logs = (templates / "logs.html").read_text(encoding="utf-8")
    ldap = (templates / "ldap.html").read_text(encoding="utf-8")
    esxi_pxe = (templates / "esxi_pxe.html").read_text(encoding="utf-8")
    vcf_depot = (templates / "vcf_offline_depot.html").read_text(encoding="utf-8")
    dns = (templates / "dns.html").read_text(encoding="utf-8")
    authentication = (templates / "authentication.html").read_text(encoding="utf-8")

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
    assert '<label class="file-upload-control compact-file-upload">' in vcf_depot
    assert '<div class="dns-authority-records" role="list">' in dns
    assert '<dl class="dns-authority-records">' not in dns
    assert '<div class="error-list" role="list" data-oidc-provider-validation-errors>' in authentication
    assert '<ul class="error-list">' not in authentication


def test_monitor_page_renders_and_data_endpoint(client):
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
    assert "data-monitor-disk-activity-table" in page.text
    assert "<th>Device</th><th>Read/s</th><th>Write/s</th>" in page.text
    assert "swagger-link-icon" in page.text
    assert "/static/app.css?v=atlaso-vaults-20260727-6" in page.text
    assert "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-4" in page.text
    assert "/static/app.js?v=atlaso-vaults-20260727-14" in page.text
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
    assert "function renderMonitorDiskActivityTable(tbody, rows)" in app_js
    assert "payload.disk_devices" in app_js
    assert 'zoomPercentInput?.addEventListener("input"' in app_js
    assert 'if (event.key === "Enter") event.currentTarget.blur();' in app_js
    assert "function monitorNearestChartTarget(interaction, pointerX, pointerY)" in app_js
    assert "interaction.hitSegments.forEach" in app_js
    assert 'canvas.addEventListener("click"' in app_js
    assert "interaction.pinned = Boolean(target);" in app_js
    assert "interaction.legendTargets.find" in app_js
    assert "interaction.highlightedField !== legendTarget.line.field" in app_js

    data = client.get("/monitor/data")
    assert data.status_code == 200, data.text
    payload = data.json()
    assert payload["window_hours"] == 6
    assert "summary" in payload
    assert "virtualization" in payload
    assert "cpu" in payload
    assert "cpu_cores" in payload
    assert "memory" in payload
    assert "network_totals" in payload
    assert "disk_devices" in payload
    assert "disks" in payload

    day_data = client.get("/monitor/data?hours=24")
    assert day_data.status_code == 200, day_data.text
    assert day_data.json()["window_hours"] == 24


def test_login_page_includes_pwa_metadata(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert '<link rel="manifest" href="/manifest.webmanifest">' in response.text
    assert '<meta name="theme-color"' not in response.text
    assert "/static/pwa.js?v=atlaso-brand-20260725-1" in response.text


def test_unauthenticated_ui_request_redirects_to_login(client):
    response = client.get("/certificate-authority", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/certificate-authority"


def test_ui_session_is_rejected_after_appliance_instance_changes(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.security import SESSION_APPLIANCE_INSTANCE_SETTING_KEY

    login(client)
    assert client.get("/dashboard").status_code == 200

    with SessionLocal() as db:
        setting = db.query(Setting).filter(Setting.key == SESSION_APPLIANCE_INSTANCE_SETTING_KEY).one()
        setting.value = "redeployed-appliance-instance"
        db.commit()

    response = client.get("/vlan-interfaces", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/vlan-interfaces"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"


def test_sidebar_appliance_apply_uses_bottom_pending_cta(client):
    login(client)
    response = client.get("/certificate-authority")

    assert response.status_code == 200
    assert 'class="sidebar-apply-link pending' in response.text
    assert 'href="/dashboard#appliance-apply-review"' in response.text
    assert "data-appliance-apply-sidebar" in response.text
    assert "data-appliance-apply-open" in response.text
    assert "data-appliance-apply-sidebar-title" in response.text
    assert "data-appliance-apply-sidebar-detail" in response.text
    assert "data-appliance-apply-sidebar-badge" in response.text
    assert "Review appliance changes" in response.text
    assert "pending unit" in response.text
    assert 'class="nav-link " href="/appliance-apply"' not in response.text


def test_dns_settings_derives_listen_addresses_from_selected_interface(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="eth9",
                mac_address="00:50:56:00:00:09",
                role="access",
                mode="access",
                ip_cidr="192.168.90.1/24",
                ipv6_cidr="2001:db8:90::1/64",
                admin_state="up",
                oper_state="up",
            )
        )
        db.commit()

    page = client.get("/dns")
    assert page.status_code == 200
    assert "Listen addresses" in page.text
    assert "Add listen address" not in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/dns/settings",
        data={
            "csrf": csrf,
            "enabled": "on",
            "listen_interfaces_present": "1",
            "listen_interfaces": "eth9",
            "upstream_servers": "1.1.1.1",
            "conditional_forwarders": "",
            "cache_size": "1000",
            "expand_hosts": "on",
            "authoritative": "on",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["listen_interfaces"] == ["eth9"]
    assert response.json()["listen_addresses"] == ["192.168.90.1", "2001:db8:90::1"]


def test_dns_listen_interface_menu_has_empty_state_when_no_interfaces_available(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        for interface in db.query(PhysicalInterface).all():
            interface.role = "unused"
            interface.mode = "access"
            interface.ip_cidr = ""
            interface.ipv6_cidr = ""
        for vlan in db.query(VlanInterface).all():
            vlan.enabled = False
        db.commit()

    page = client.get("/dns")
    assert page.status_code == 200
    assert 'data-tag-empty-message="No interfaces available."' in page.text
    assert 'data-tag-option=' not in page.text

    app_js = client.get("/static/app.js")
    assert "data-tag-empty" in app_js.text
    assert "visibleOptions" in app_js.text


def test_forget_missing_physical_interface_deletes_only_stale_rows(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        missing = PhysicalInterface(
            name="missing_eth7",
            mac_address="00:50:56:00:00:07",
            role="unused",
            mode="unused",
            admin_state="down",
            oper_state="missing",
        )
        db.add(missing)
        db.add(VlanInterface(name="missing_eth7.20", parent_interface="missing_eth7", vlan_id=20, enabled=False))
        active = PhysicalInterface(
            name="eth8",
            mac_address="00:50:56:00:00:08",
            role="access",
            mode="access",
            admin_state="up",
            oper_state="up",
        )
        db.add(active)
        db.commit()
        missing_id = missing.id
        active_id = active.id

    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    active_response = client.post(f"/physical-interfaces/{active_id}/forget", data={"csrf": csrf})
    assert active_response.status_code == 409
    response = client.post(f"/physical-interfaces/{missing_id}/forget", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    with SessionLocal() as db:
        assert db.get(PhysicalInterface, missing_id) is None
        assert db.query(VlanInterface).filter(VlanInterface.parent_interface == "missing_eth7").count() == 0
        assert db.get(PhysicalInterface, active_id) is not None


def test_forget_missing_first_service_interface_moves_dns_alias_to_next_target(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, PhysicalInterface
    from atlaso.app.ui import ensure_dns_for_vcf_registry, get_vcf_private_registry_settings_row

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                PhysicalInterface(
                    name="eth7",
                    mac_address="00:50:56:00:00:17",
                    role="access",
                    mode="access",
                    ip_cidr="10.7.0.1/24",
                    admin_state="up",
                    oper_state="up",
                ),
                PhysicalInterface(
                    name="eth8",
                    mac_address="00:50:56:00:00:18",
                    role="access",
                    mode="access",
                    ip_cidr="10.8.0.1/24",
                    admin_state="up",
                    oper_state="up",
                ),
            ]
        )
        settings = get_vcf_private_registry_settings_row(db)
        settings.enabled = True
        settings.hostname = "registry.atlaso.internal"
        settings.listen_interface = "eth7\neth8"
        settings.listen_address = "10.7.0.1\n10.8.0.1"
        ensure_dns_for_vcf_registry(db, settings, "admin")
        db.commit()
        eth7_id = db.execute(select(PhysicalInterface.id).where(PhysicalInterface.name == "eth7")).scalar_one()
        eth7 = db.get(PhysicalInterface, eth7_id)
        eth7.oper_state = "missing"
        db.commit()

    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(f"/physical-interfaces/{eth7_id}/forget", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    with SessionLocal() as db:
        settings = get_vcf_private_registry_settings_row(db)
        assert settings.listen_interface == "eth8"
        assert settings.listen_address == "10.8.0.1"
        canonical = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry.atlaso.internal", DnsRecord.record_type == "CNAME")
        ).scalar_one()
        assert canonical.address == "registry-10-8-0-1.atlaso.internal"
        assert db.execute(select(DnsRecord).where(DnsRecord.hostname == "registry-10-7-0-1.atlaso.internal")).scalar_one_or_none() is None
        target = db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "registry-10-8-0-1.atlaso.internal", DnsRecord.record_type == "A")
        ).scalar_one()
        assert target.address == "10.8.0.1"


def test_service_dns_target_naming_converts_owned_records_between_ip_and_interface(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsRecord, PhysicalInterface
    from atlaso.app.ui import ensure_dns_for_vcf_registry, get_vcf_private_registry_settings_row

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
    from types import SimpleNamespace

    from atlaso.app import ui

    attempts = {"count": 0}
    repairs: list[str] = []

    def fake_write(path, config_preview):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise PermissionError("blocked")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config_preview, encoding="utf-8")

    class FakeAdapter:
        def prepare_apply_staging_path(self, path):
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


def test_appliance_apply_status_api_tracks_autosaved_desired_state(client):
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

    applied = client.get("/appliance-apply/status")
    assert applied.status_code == 200
    applied_dns = next(unit for unit in applied.json()["units"] if unit["id"] == "dnsmasq")
    assert applied_dns["changed"] is False

    apply_page = client.get("/appliance-apply", follow_redirects=False)
    assert apply_page.status_code == 303
    assert apply_page.headers["location"] == "/dashboard#appliance-apply-review"


def test_settings_page_renders_autosave_validation_and_preview(client, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings

    monkeypatch.setattr("atlaso.app.ui.socket.gethostname", lambda: "runtime.atlaso.internal")

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        db.commit()

    response = client.get("/settings")

    assert response.status_code == 200
    assert 'action="/settings"' in response.text
    assert 'data-autosave-status-id="appliance-settings-autosave-status"' in response.text
    assert response.text.count('class="help-icon"') >= 2
    assert 'textarea name="external_dns_servers"' not in response.text
    assert 'input type="hidden" name="external_dns_servers"' in response.text
    assert "Appliance Settings has pending appliance changes" in response.text
    assert "Validation" in response.text
    assert "runtime.atlaso.internal" in response.text
    assert "core.atlaso.internal" in response.text
    assert "Management UI HTTPS" in response.text
    assert "Root SSH login" in response.text
    assert "VMware Product Preferences" in response.text
    assert "VMware CEIP participation" in response.text
    assert 'action="/settings/vmware-ceip"' in response.text
    assert 'name="vmware_ceip_enabled"' in response.text
    assert 'data-vmware-ceip-pill' in response.text
    assert 'data-vmware-ceip-status' in response.text
    assert 'action="/settings/vmware-ceip" method="post" data-autosave-form data-appliance-settings' in response.text
    assert "Service DNS target names" in response.text
    assert response.text.count('class="settings-inline-field"') >= 2
    assert 'select name="service_dns_target_naming"' in response.text
    assert '<option value="ip" selected>IP address</option>' in response.text
    assert "Operational Logging" in response.text
    assert "External NTP servers" not in response.text
    assert 'textarea name="ntp_servers"' not in response.text
    assert 'action="/settings/logging"' in response.text
    assert 'select name="level"' in response.text
    assert 'input class="switch-input" type="checkbox" name="syslog_enabled"' in response.text
    assert "Syslog host" in response.text
    assert "data-appliance-settings-root-ssh" in response.text
    assert "/var/lib/atlaso/apply/appliance-settings/atlaso-settings.json" in response.text
    assert "resolver_mode" in response.text
    assert "root_ssh_enabled" in response.text
    assert "vmware_ceip_enabled" in response.text
    assert 'data-config-preview-open' in response.text
    assert 'data-appliance-settings-preview' in response.text
    assert 'class="validation-preview-source language-json"' in response.text
    assert 'class="settings-list validation-settings-list"' in response.text
    app_css = client.get("/static/app.css")
    assert ".validation-settings-list div" in app_css.text
    assert "grid-template-columns: minmax(0, 130px) minmax(0, 1fr);" in app_css.text
    assert "overflow-wrap: anywhere;" in app_css.text
    assert ".settings-inline-field" in app_css.text
    assert "grid-template-columns: 160px minmax(0, 1fr);" in app_css.text


def test_vmware_ceip_autosave_updates_global_policy_and_pending_preview(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, AuditEvent

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings/vmware-ceip",
        data={"vmware_ceip_enabled": "on", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["vmware_ceip_enabled"] is True
    assert payload["fqdn"] == "core.atlaso.internal"
    assert payload["management_interface"]["name"] == "eth0"
    assert payload["resolver_mode"] in {"dhcp", "external", "local_dns"}
    assert '"vmware_ceip_enabled": true' in payload["config_preview"]
    with SessionLocal() as db:
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.action == "update_vmware_ceip_policy")
        ).scalar_one()
        assert settings.vmware_ceip_enabled is True
        assert audit.detail == "enabled=true"

    status = client.get("/appliance-apply/status").json()
    unit = next(item for item in status["units"] if item["id"] == "appliance_settings")
    assert unit["changed"] is True
    updated_page = client.get("/settings")
    assert 'data-vmware-ceip-pill class="status-pill good">CEIP on</span>' in updated_page.text
    assert "Appliance Settings has pending appliance changes" in updated_page.text


def test_settings_autosave_enables_passwordless_terminal_on_management_interface(client):
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


def test_validation_rails_use_modal_config_previews(client):
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
        "/kms": ["data-kms-config-preview"],
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


def test_logging_settings_autosave_updates_preferences(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Setting
    from atlaso.app.operational_logging import (
        LOGGING_LEVEL_KEY,
        LOGGING_SYSLOG_ENABLED_KEY,
        LOGGING_SYSLOG_FACILITY_KEY,
        LOGGING_SYSLOG_HOST_KEY,
        LOGGING_SYSLOG_LEVEL_KEY,
        LOGGING_SYSLOG_PORT_KEY,
        LOGGING_SYSLOG_PROTOCOL_KEY,
    )

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings/logging",
        data={
            "level": "DEBUG",
            "syslog_enabled": "on",
            "syslog_host": "127.0.0.1",
            "syslog_port": "5514",
            "syslog_protocol": "udp",
            "syslog_facility": "local4",
            "syslog_level": "WARNING",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "saved"
    assert payload["logging_preferences"]["level"] == "DEBUG"
    assert payload["logging_preferences"]["syslog_enabled"] is True
    assert payload["logging_preferences"]["syslog_host"] == "127.0.0.1"
    assert payload["logging_preferences"]["syslog_port"] == 5514
    assert payload["logging_preferences"]["syslog_protocol"] == "udp"
    assert payload["logging_preferences"]["syslog_facility"] == "local4"
    assert payload["logging_preferences"]["syslog_level"] == "WARNING"

    with SessionLocal() as db:
        values = {row.key: row.value for row in db.execute(select(Setting)).scalars().all()}
        assert values[LOGGING_LEVEL_KEY] == "DEBUG"
        assert values[LOGGING_SYSLOG_ENABLED_KEY] == "true"
        assert values[LOGGING_SYSLOG_HOST_KEY] == "127.0.0.1"
        assert values[LOGGING_SYSLOG_PORT_KEY] == "5514"
        assert values[LOGGING_SYSLOG_PROTOCOL_KEY] == "udp"
        assert values[LOGGING_SYSLOG_FACILITY_KEY] == "local4"
        assert values[LOGGING_SYSLOG_LEVEL_KEY] == "WARNING"
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "update_operational_logging_settings")).scalar_one()
        assert event.resource_type == "logging"


def test_logging_settings_requires_syslog_host_when_enabled(client):
    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/settings/logging",
        data={
            "level": "INFO",
            "syslog_enabled": "on",
            "syslog_host": "",
            "syslog_port": "514",
            "syslog_protocol": "udp",
            "syslog_facility": "local0",
            "syslog_level": "INFO",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 422
    assert response.json()["message"] == "External syslog host is required when syslog forwarding is enabled."


def test_settings_page_shows_external_dns_editor_when_local_dns_is_disabled(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = False
        db.commit()

    response = client.get("/settings")

    assert response.status_code == 200
    assert "External DNS servers" in response.text
    assert 'textarea name="external_dns_servers"' in response.text
    assert "Local DNS is disabled. External DNS servers are required" in response.text


def test_settings_page_hides_ntp_editor_when_ntp_is_enabled(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NtpSettings

    login(client)
    with SessionLocal() as db:
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = True
        db.add(ntp_settings)
        db.commit()

    response = client.get("/settings")

    assert response.status_code == 200
    assert "External NTP servers" not in response.text
    assert 'textarea name="ntp_servers"' not in response.text
    assert 'input type="hidden" name="ntp_servers"' not in response.text
    assert '  "ntp_servers": [' not in response.text


def test_settings_autosave_updates_appliance_identity_dns_without_ntp(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, NtpSettings, DnsRecord, DnsSettings

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
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, NtpSettings, DnsSettings
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
        status = appliance_apply_status(db, "appliance_settings")
        assert status["changed"] is False
        assert "ntp_servers" not in status["config_preview"]


def test_ntp_page_autosave_updates_desired_state_and_preview(client, monkeypatch):
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
    assert "NTS-KE ntp.atlaso.internal:4460" in client.get("/ntp").text
    js = client.get("/static/app.js")
    assert js.status_code == 200
    assert "initializeNtpSettings" in js.text
    assert "initializeNTPsecUpstreamsTable" in js.text
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
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, NtpSettings
    from atlaso.app.services.ntp import ntp_upstream_sources, dump_ntp_upstream_sources

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


def test_ntp_validation_rejects_enabled_service_without_bind_or_upstreams(client):
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


def test_settings_fqdn_rename_removes_only_old_app_owned_record(client):
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
    from atlaso.app.services.appliance_settings import parse_resolvectl_dns_servers

    output = """
Global:
Link 2 (eth0): 127.0.0.1 ::1 192.168.167.2 2001:4860:4860::8888 fe80::1%eth0 192.168.167.2
"""

    assert parse_resolvectl_dns_servers(output) == ["192.168.167.2", "2001:4860:4860::8888", "fe80::1"]


def test_settings_management_dhcp_allows_empty_external_dns(client, monkeypatch):
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


def test_dns_page_uses_management_dhcp_dns_when_upstreams_are_empty(client, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, PhysicalInterface

    login(client)
    monkeypatch.setattr("atlaso.app.services.appliance_settings.observed_management_dhcp_dns_servers", lambda interface_name: ["127.0.0.1", "::1", "192.168.167.2"])
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.upstream_servers = ""
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.host_ip_cidr = "192.168.167.219/24"
        db.commit()

    page = client.get("/dns")
    assert 'placeholder="DHCP: 192.168.167.2"' in page.text
    assert "<code>192.168.167.2</code>" in page.text
    assert 'placeholder="DHCP: 127.0.0.1' not in page.text
    assert "<code>127.0.0.1</code>" not in page.text
    assert "<code>::1</code>" not in page.text
    assert ">192.168.167.2</textarea>" not in page.text
    assert "server=192.168.167.2" in page.text
    assert "server=127.0.0.1" not in page.text
    assert "server=::1" not in page.text

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/settings",
        data={
            "enabled": "on",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "upstream_servers": "",
            "conditional_forwarders": "",
            "cache_size": "1000",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["observed_dhcp_upstream_servers"] == ["192.168.167.2"]
    assert payload["effective_upstream_servers"] == ["192.168.167.2"]
    assert "server=192.168.167.2" in payload["config_preview"]


def test_settings_management_https_requires_ca_managed_certificate(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, CaCertificate, CaSettings, DnsSettings

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


def test_appliance_settings_apply_task_records_dry_run_helper_commands(client, caplog):
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
    assert "completed status=succeeded selected_units=appliance_settings" in caplog.text
    assert "unit=appliance_settings status=succeeded" in caplog.text
    assert "atlaso-helper appliance-settings validate" in caplog.text
    assert "Appliance Settings" in apply_response.text
    assert "data-apply-progress-modal" not in apply_response.text
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "appliance_settings" in (job.result or "")
        assert "atlaso-helper appliance-settings validate" in (job.result or "")
        assert "atlaso-helper appliance-settings apply" in (job.result or "")
        assert "apply.atlaso.internal" in (job.result or "")


def test_appliance_apply_failure_renders_command_details(client, monkeypatch):
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    import atlaso.app.ui as ui_module

    base_system_adapter = ui_module.SystemAdapter
    monkeypatch.setattr(ui_module, "stage_appliance_apply_config", lambda path, _config: path)

    class FailingApplianceSettingsAdapter(base_system_adapter):
        def __init__(self) -> None:
            super().__init__(dry_run=False)

        def read_dhcp_leases(self) -> AdapterResult:
            return AdapterResult(command=["atlaso-helper", "dnsmasq", "leases"], dry_run=True, stdout="")

        def validate_appliance_settings_config(self, config_path: str) -> AdapterResult:
            return AdapterResult(
                command=["atlaso-helper", "appliance-settings", "validate", config_path],
                dry_run=False,
                stdout="validation ok",
            )

        def apply_appliance_settings_config(self, config_path: str) -> AdapterResult:
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
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    import atlaso.app.ui as ui_module

    base_system_adapter = ui_module.SystemAdapter
    monkeypatch.setattr(ui_module, "stage_appliance_apply_config", lambda path, _config: path)

    class ValidationFailingApplianceSettingsAdapter(base_system_adapter):
        def __init__(self) -> None:
            super().__init__(dry_run=False)

        def read_dhcp_leases(self) -> AdapterResult:
            return AdapterResult(command=["atlaso-helper", "dnsmasq", "leases"], dry_run=True, stdout="")

        def validate_appliance_settings_config(self, config_path: str) -> AdapterResult:
            return AdapterResult(
                command=["atlaso-helper", "appliance-settings", "validate", config_path],
                dry_run=False,
                stderr="hostname validation failed",
                returncode=2,
            )

        def apply_appliance_settings_config(self, config_path: str) -> AdapterResult:
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
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent

    login(client)
    page = client.get("/backup-restore")
    assert page.status_code == 200
    assert "Download settings backup" in page.text
    assert "Restore settings backup" in page.text
    assert "Factory reset settings" in page.text
    assert "LDAP Directory Recovery" in page.text
    assert "not part of the normal settings backup" in page.text
    assert 'action="/backup-restore/ldap/export"' in page.text
    assert 'action="/backup-restore/ldap/import"' in page.text
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
    assert payload["schema_version"] == 1
    assert "appliance_settings" in payload["data"]
    assert "dns_records" in payload["data"]
    assert "users" not in payload["data"]
    assert "api_tokens" not in payload["data"]
    assert "audit_events" not in payload["data"]
    assert "jobs" not in payload["data"]

    with SessionLocal() as db:
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "export_settings_backup")).scalar_one()
        assert event.resource_type == "settings_backup"


def test_settings_archive_round_trips_management_ipv6_gateway(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.settings_archive import export_settings_archive, restore_settings_archive

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


def test_settings_archive_round_trips_authoritative_dns_policy(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings
    from atlaso.app.services.settings_archive import export_settings_archive, restore_settings_archive

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


def test_settings_restore_and_factory_reset_clear_staged_ldap_recovery(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapRecoveryArchive
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS
    from atlaso.app.services.settings_archive import export_settings_archive, factory_reset_desired_state, restore_settings_archive

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


def test_esxi_kickstart_api_hides_raw_content_from_read_only_tokens(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart

    write_token = create_api_token(client, ["read:esxi-pxe", "write:esxi-pxe"])
    created = client.post(
        "/api/v1/esxi-pxe/kickstarts",
        headers={"Authorization": f"Bearer {write_token}"},
        json={
            "name": "Secure ESXi",
            "description": "secret-bearing ks",
            "content": "install --firstdisk\nnetwork --bootproto=dhcp\nrootpw MySecretPassword\nreboot\n%firstboot\n%end\n",
            "enabled": True,
        },
    )

    assert created.status_code == 201, created.text
    kickstart_id = created.json()["id"]
    assert created.json()["content"] and "MySecretPassword" in created.json()["content"]
    with SessionLocal() as db:
        row = db.execute(select(EsxiKickstart).where(EsxiKickstart.id == kickstart_id)).scalar_one()
        assert "MySecretPassword" in row.content
        assert row.content_hash

    read_token = create_api_token(client, ["read:esxi-pxe"])
    fetched = client.get(f"/api/v1/esxi-pxe/kickstarts/{kickstart_id}", headers={"Authorization": f"Bearer {read_token}"})
    preview = client.get(f"/api/v1/esxi-pxe/kickstarts/{kickstart_id}/preview", headers={"Authorization": f"Bearer {read_token}"})
    download = client.get(f"/api/v1/esxi-pxe/kickstarts/{kickstart_id}/download", headers={"Authorization": f"Bearer {read_token}"})

    assert fetched.status_code == 200
    assert fetched.json()["content"] is None
    assert "MySecretPassword" not in fetched.text
    assert "rootpw ********" in fetched.json()["redacted_preview"]
    assert preview.status_code == 200
    assert "MySecretPassword" not in preview.text
    assert download.status_code == 403


def test_esxi_pxe_ui_create_apply_and_job_redaction(client):
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, EsxiKickstart, Job

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    assert "ESXi Kickstarts" in page.text
    assert 'data-codemirror-language="atlaso-kickstart"' in page.text
    host_tab = page.text.index('data-tab-target="esxi-pxe-hosts-panel"')
    kickstart_tab = page.text.index('data-tab-target="esxi-pxe-editor-panel"')
    iso_tab = page.text.index('data-tab-target="esxi-pxe-isos-panel"')
    assert host_tab < kickstart_tab < iso_tab
    assert '<button class="tab-button active" type="button" role="tab" data-tab-target="esxi-pxe-hosts-panel"' in page.text
    assert 'id="esxi-pxe-hosts-panel" class="tab-panel active" role="tabpanel">' in page.text
    assert 'id="esxi-pxe-editor-panel" class="tab-panel" role="tabpanel" hidden' in page.text
    assert 'aria-label="Kickstart for default ESXi PXE host"' in page.text
    assert 'aria-label="Installer ISO for default ESXi PXE host"' in page.text
    assert 'aria-label="Enable default ESXi PXE host"' in page.text
    assert "# Sample scripted installation file" in page.text
    assert "vmaccepteula" in page.text
    assert "rootpw vmware01!" in page.text
    assert "install --firstdisk --overwritevmfs" in page.text
    assert "# install --firstdisk --overwritevmfs --dpupcislots=&lt;PCIeSlotID&gt;" in page.text
    assert "network --bootproto=dhcp --device=vmnic0" in page.text
    assert "%post --interpreter=python --ignorefailure=true" in page.text
    assert "stampFile.write(time.asctime())" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

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


def test_esxi_pxe_iso_upload_and_host_selection(client, monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace

    from sqlalchemy import select

    import atlaso.app.services.esxi_pxe as esxi_pxe
    import atlaso.app.ui as ui_module
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiPxeHost, Job

    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    monkeypatch.setattr(esxi_pxe, "ESXI_INSTALLER_ISO_ROOT", iso_root)

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    assert str(iso_root) in page.text
    assert iso_root.is_dir()
    assert 'data-esxi-iso-upload' in page.text
    assert 'data-esxi-iso-upload-progress' in page.text
    assert "Choose an ISO to upload." in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    uploaded = client.post(
        "/esxi-pxe/isos/upload",
        data={"csrf": csrf},
        files={"iso_file": ("VMware-VMvisor-Installer-8.0U3.iso", b"iso bytes", "application/octet-stream")},
        follow_redirects=False,
    )
    assert uploaded.status_code == 303
    assert uploaded.headers["location"] == "/esxi-pxe#esxi-pxe-isos-panel"
    iso_path = iso_root / "VMware-VMvisor-Installer-8.0U3.iso"
    assert iso_path.read_bytes() == b"iso bytes"

    ajax_upload = client.post(
        "/esxi-pxe/isos/upload",
        data={"csrf": csrf},
        files={"iso_file": ("Nested-ESXi.iso", b"ajax iso bytes", "application/octet-stream")},
        headers={"X-Atlaso-Upload": "1"},
    )
    assert ajax_upload.status_code == 200
    assert ajax_upload.json()["status"] == "uploaded"
    assert ajax_upload.json()["relative_path"] == "Nested-ESXi.iso"

    original_get_settings = ui_module.get_settings
    monkeypatch.setattr(ui_module, "get_settings", lambda: SimpleNamespace(esxi_installer_iso_max_bytes=3))
    too_large = client.post(
        "/esxi-pxe/isos/upload",
        data={"csrf": csrf},
        files={"iso_file": ("Too-Large.iso", b"too large", "application/octet-stream")},
        headers={"X-Atlaso-Upload": "1"},
    )
    assert too_large.status_code == 413
    assert too_large.json()["status"] == "error"
    assert "too large" in too_large.json()["detail"].lower()
    monkeypatch.setattr(ui_module, "get_settings", original_get_settings)

    vcfdt_iso_path = iso_root / "VCFDT-Downloaded.iso"
    vcfdt_iso_path.write_bytes(b"vcfdt iso bytes")
    refreshed = client.get("/esxi-pxe")
    assert "VMware-VMvisor-Installer-8.0U3.iso" in refreshed.text
    assert "VCFDT-Downloaded.iso" in refreshed.text
    assert "Installer ISOs" in refreshed.text
    assert "Uploaded by user" in refreshed.text
    assert "Downloaded by VCFDT" in refreshed.text
    assert 'id="esxi-pxe-hosts-table"' in refreshed.text
    assert "Default / undefined MACs" in refreshed.text
    assert "host-create-form" not in refreshed.text
    csrf = refreshed.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    vcfdt_delete = client.post(
        "/esxi-pxe/isos/delete",
        data={"csrf": csrf, "installer_iso_path": str(vcfdt_iso_path)},
        follow_redirects=False,
    )
    assert vcfdt_delete.status_code == 303
    assert vcfdt_delete.headers["location"] == "/esxi-pxe#esxi-pxe-isos-panel"
    assert not vcfdt_iso_path.exists()
    host_response = client.post(
        "/esxi-pxe/hosts",
        data={
            "csrf": csrf,
            "hostname": "esxi-iso",
            "mac_address": "00:50:56:11:22:33",
            "installer_iso_path": str(iso_path),
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert host_response.status_code == 303
    host_page = client.get("/esxi-pxe")
    assert host_page.status_code == 200
    assert 'data-hosts=' in host_page.text
    assert "esxi-iso" in host_page.text
    with SessionLocal() as db:
        host = db.execute(select(EsxiPxeHost).where(EsxiPxeHost.hostname == "esxi-iso")).scalar_one()
        assert host.installer_iso_path == str(iso_path)
        host_id = host.id
    delete_response = client.post(
        "/esxi-pxe/isos/delete",
        data={"csrf": csrf, "installer_iso_path": str(iso_path)},
        follow_redirects=False,
    )
    assert delete_response.status_code == 303
    assert delete_response.headers["location"] == "/esxi-pxe#esxi-pxe-isos-panel"
    assert not iso_path.exists()
    with SessionLocal() as db:
        host = db.get(EsxiPxeHost, host_id)
        assert host.installer_iso_path == ""
    iso_path.write_bytes(b"iso bytes restored")
    host_response = client.post(
        "/esxi-pxe/hosts/" + str(host_id),
        data={
            "csrf": csrf,
            "hostname": "esxi-iso",
            "mac_address": "00:50:56:11:22:33",
            "installer_iso_path": str(iso_path),
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert host_response.status_code == 303

    api_token = create_api_token(client, ["read:esxi-pxe"])
    api_isos = client.get("/api/v1/esxi-pxe/isos", headers={"Authorization": f"Bearer {api_token}"})
    assert api_isos.status_code == 200
    assert {row["relative_path"] for row in api_isos.json()} >= {"VMware-VMvisor-Installer-8.0U3.iso", "Nested-ESXi.iso"}

    apply_page = client.get("/appliance-apply")
    apply_csrf = apply_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    applied = client.post("/appliance-apply", data={"csrf": apply_csrf, "selected_units": "esxi_pxe"})
    assert applied.status_code == 200
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply").order_by(Job.created_at.desc())).scalars().first()
        payload = json.loads(job.result or "{}")
        manifest = payload["units"][0]["config_preview"]
        manifest_payload = json.loads(manifest)
        assert "VMware-VMvisor-Installer-8.0U3.iso" in manifest
        assert manifest_payload["hosts"][0]["installer_iso_path"] == str(iso_path)


def test_esxi_pxe_default_host_settings_update_existing_rows(client, monkeypatch, tmp_path):
    import json

    from sqlalchemy import select

    import atlaso.app.services.esxi_pxe as esxi_pxe
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, Setting

    iso_root = tmp_path / "vcf-depot" / "PROD" / "COMP" / "ESX_HOST"
    iso_root.mkdir(parents=True)
    first_iso = iso_root / "First-ESXi.iso"
    second_iso = iso_root / "Second-ESXi.iso"
    first_iso.write_bytes(b"first")
    second_iso.write_bytes(b"second")
    monkeypatch.setattr(esxi_pxe, "ESXI_INSTALLER_ISO_ROOT", iso_root)

    with SessionLocal() as db:
        first_kickstart = EsxiKickstart(name="First", content="install", content_hash=esxi_pxe.content_hash("install"))
        second_kickstart = EsxiKickstart(name="Second", content="install", content_hash=esxi_pxe.content_hash("install"))
        db.add_all([first_kickstart, second_kickstart])
        db.flush()
        first_kickstart_id = first_kickstart.id
        second_kickstart_id = second_kickstart.id
        second_kickstart_hash = second_kickstart.content_hash

        first = esxi_pxe.save_esxi_pxe_default_host_settings(
            db,
            enabled=True,
            kickstart_id=first_kickstart_id,
            installer_iso_path=str(first_iso),
        )
        db.flush()
        second = esxi_pxe.save_esxi_pxe_default_host_settings(
            db,
            enabled=False,
            kickstart_id=second_kickstart_id,
            installer_iso_path=str(second_iso),
        )
        db.flush()

        rows = db.execute(select(Setting).where(Setting.key.like("esxi_pxe.default_host.%"))).scalars().all()
        manifest = json.loads(esxi_pxe.render_esxi_pxe_manifest([], [], default_host=second))

    assert first["enabled"] is True
    assert first["kickstart_id"] == first_kickstart_id
    assert second["enabled"] is False
    assert second["kickstart_id"] == second_kickstart_id
    assert second["installer_iso_path"] == str(second_iso)
    assert manifest["default_host"] == {
        "enabled": False,
        "kickstart_id": second_kickstart_id,
        "kickstart_name": "Second",
        "kickstart_http_path": f"/pxe/esxi/ks/{second_kickstart_hash[:12]}.cfg",
        "installer_iso_path": str(second_iso),
        "installer_iso_name": "Second-ESXi.iso",
    }
    assert len(rows) == 3
    assert {row.key for row in rows} == {
        esxi_pxe.ESXI_PXE_DEFAULT_HOST_ENABLED_KEY,
        esxi_pxe.ESXI_PXE_DEFAULT_HOST_KICKSTART_ID_KEY,
        esxi_pxe.ESXI_PXE_DEFAULT_HOST_INSTALLER_ISO_KEY,
    }


def test_esxi_pxe_default_host_edit_marks_appliance_apply_pending(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart
    from atlaso.app.services import esxi_pxe
    from atlaso.app.ui import appliance_apply_status, appliance_apply_units, update_appliance_apply_baselines

    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    with SessionLocal() as db:
        kickstart = EsxiKickstart(name="Baseline ESXi", content="install", content_hash=esxi_pxe.content_hash("install"))
        db.add(kickstart)
        db.flush()
        kickstart_id = kickstart.id
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
    with SessionLocal() as db:
        assert appliance_apply_status(db, "esxi_pxe")["changed"] is False

    current = client.get("/appliance-apply/status")
    assert current.status_code == 200
    current_pending_count = current.json()["pending_count"]

    response = client.post(
        "/esxi-pxe/default-host",
        data={"csrf": csrf, "enabled": "on", "kickstart_id": str(kickstart_id), "installer_iso_path": ""},
        follow_redirects=False,
    )
    assert response.status_code == 303

    pending = client.get("/appliance-apply/status")
    assert pending.status_code == 200
    assert pending.json()["pending_count"] > current_pending_count
    assert pending.json()["label"] == "Review appliance changes"
    with SessionLocal() as db:
        assert appliance_apply_status(db, "esxi_pxe")["changed"] is True


def test_esxi_kickstart_validation_rejects_duplicate_install_directives(client):
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


def test_esxi_kickstart_host_variables_render_from_mac_endpoint(client):
    import json

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

    rendered = client.get(f"/pxe/esxi/ks/{kickstart_file}?mac=01-00-50-56-aa-bb-cc")
    assert rendered.status_code == 200, rendered.text
    assert "install --firstdisk=mpx.vmhba0:C0:T0:L0" in rendered.text
    assert "--ip=192.168.50.150" in rendered.text
    assert "--gateway=192.168.50.1" in rendered.text
    assert "--netmask=255.255.255.0" in rendered.text
    assert "--nameserver=192.168.50.1" in rendered.text
    assert "ntpserver 192.168.50.1" in rendered.text

    assert client.get(f"/pxe/esxi/ks/{kickstart_file}").status_code == 400
    static_rendered = client.get(f"/pxe/esxi/ks/{static_kickstart_file}")
    assert static_rendered.status_code == 200, static_rendered.text
    assert "network --bootproto=dhcp" in static_rendered.text
    assert static_artifact_url.endswith(f"/pxe/esxi/ks/{static_kickstart_file}")
    assert "?mac=" not in static_artifact_url
    assert client.get(f"/pxe/esxi/ks/{kickstart_file}?mac=not-a-mac").status_code == 400
    assert client.get(f"/pxe/esxi/ks/{kickstart_file}?mac=01-00-50-56-aa-bb-dd").status_code == 404

    with SessionLocal() as db:
        host = db.execute(select(EsxiPxeHost).where(EsxiPxeHost.mac_address == "00:50:56:aa:bb:cc")).scalar_one()
        host.variables_json = json.dumps({})
        db.add(host)
        db.commit()
    unresolved = client.get(f"/pxe/esxi/ks/{kickstart_file}?mac=01-00-50-56-aa-bb-cc")
    assert unresolved.status_code == 400
    assert "custom.disk" in unresolved.text


def test_esxi_pxe_host_variables_api_and_manifest(client):
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
    kickstart_tab = 'data-tab-target="esxi-pxe-editor-panel" aria-controls="esxi-pxe-editor-panel" aria-selected="false">Kickstart Editor</button>'
    iso_tab = 'data-tab-target="esxi-pxe-isos-panel" aria-controls="esxi-pxe-isos-panel" aria-selected="false">Installer ISOs</button>'
    assert page.text.index(host_tab) < page.text.index(kickstart_tab) < page.text.index(iso_tab)
    assert 'id="esxi-pxe-hosts-panel" class="tab-panel active" role="tabpanel"' in page.text
    assert 'id="esxi-pxe-editor-panel" class="tab-panel" role="tabpanel" hidden' in page.text
    assert "Kickstart variables" in page.text
    assert "{{host.hostname}}" in page.text
    assert "{{dhcp.ntp_servers}}" in page.text
    assert "{{custom.install_disk}}" in page.text
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
        assert boot["effective_native_uefi_http_url"] == "http://192.168.50.1:8080/pxe/esxi/mboot.efi"
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
        assert "dhcp-boot=tag:sitea,tag:ipxe,tag:efi-x86_64,mboot.efi,esxi-pxe.atlaso.internal,192.168.50.1" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:ipxe,tag:!efi-x86_64,pxelinux.0,esxi-pxe.atlaso.internal,192.168.50.1" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:efi-x86_64,snponly.efi,esxi-pxe.atlaso.internal,192.168.50.1" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:!efi-x86_64,undionly.kpxe,esxi-pxe.atlaso.internal,192.168.50.1" in dns_preview
        assert "dhcp-boot=tag:sitea,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/mboot.efi" in dns_preview
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
    assert "dhcp-boot=tag:sitea,tag:ipxe,tag:efi-x86_64,mboot.efi,esxi-pxe.atlaso.internal,192.168.50.1" in dhcp_page.text
    assert "dhcp-boot=tag:sitea,tag:!ipxe,tag:efi-x86_64,snponly.efi,esxi-pxe.atlaso.internal,192.168.50.1" in dhcp_page.text
    assert "dhcp-boot=tag:sitea,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/mboot.efi" in dhcp_page.text
def test_esxi_pxe_multi_zone_host_reservations_and_grid_menu(client):
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
        assert "dhcp-boot=tag:sitea,tag:uefi-http,tag:uefi-http-x64,http://192.168.50.1:8080/pxe/esxi/mboot.efi" in dns_preview
        assert "dhcp-boot=tag:siteb,tag:uefi-http,tag:uefi-http-x64,http://10.1.1.1:8080/pxe/esxi/mboot.efi" in dns_preview

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
    host_grid_js = app_js.split("function initializeEsxiPxeHostsTable()", 1)[1].split("function initializeVcfBackupSettings()", 1)[0]
    assert "rowContextMenu" in host_grid_js
    assert "Delete host reference" in host_grid_js
    assert 'field: "ip_address"' in host_grid_js
    assert 'field: "variables_json"' in host_grid_js
    assert "<button" not in host_grid_js


def test_esxi_pxe_boot_settings_migrate_legacy_first_stage_defaults(client):
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


def test_esxi_kickstarts_round_trip_in_settings_archive(client):
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, EsxiPxeHost

    login(client)
    with SessionLocal() as db:
        kickstart = EsxiKickstart(
            name="Archive ESXi",
            content="install\nnetwork --bootproto=dhcp\nrootpw ArchiveSecret\nreboot\n%firstboot\n%end\n",
            content_hash="",
            rendered_content="install\nnetwork --bootproto=dhcp\nrootpw ArchiveSecret\nreboot\n%firstboot\n%end\n",
            enabled=True,
        )
        db.add(kickstart)
        db.flush()
        from atlaso.app.services.esxi_pxe import assign_kickstart_content, canonical_http_path

        assign_kickstart_content(kickstart, kickstart.content, max_bytes=262_144)
        kickstart.http_path = canonical_http_path(kickstart.id, kickstart.content_hash)
        db.add(
            EsxiPxeHost(
                hostname="esxi-archive",
                mac_address="00:50:56:aa:bb:cc",
                ip_address="192.168.50.150",
                kickstart_id=kickstart.id,
                installer_iso_path="/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/archive.iso",
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
    assert payload["data"]["esxi_pxe_hosts"][0]["installer_iso_path"].endswith("/archive.iso")
    assert payload["data"]["esxi_pxe_hosts"][0]["variables"] == {"rack": "r42"}

    with SessionLocal() as db:
        db.query(EsxiPxeHost).delete()
        db.query(EsxiKickstart).delete()
        db.commit()

    restored = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={"archive_file": ("atlaso-settings.json", exported.content, "application/json")},
    )

    assert restored.status_code == 200
    with SessionLocal() as db:
        restored_kickstart = db.execute(select(EsxiKickstart).where(EsxiKickstart.name == "Archive ESXi")).scalar_one()
        restored_host = db.execute(select(EsxiPxeHost).where(EsxiPxeHost.hostname == "esxi-archive")).scalar_one()
        assert restored_host.kickstart_id == restored_kickstart.id
        assert restored_host.ip_address == "192.168.50.150"
        assert restored_host.installer_iso_path.endswith("/archive.iso")
        assert restored_host.variables_json == '{"rack": "r42"}'


def test_esxi_pxe_drift_detection_uses_generated_filesystem_copy(client, monkeypatch, tmp_path):
    from sqlalchemy import select

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


def test_backup_restore_recreates_default_vcf_backup_user_from_settings_archive(client):
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

    assert restored.status_code == 200
    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "vcf-backup")).scalar_one()
        settings = db.execute(select(VcfBackupSettings)).scalar_one()
        assert settings.sftp_user_id == user.id
        assert user.enabled is False
        assert user.os_sync_status == "password_not_staged"


def test_backup_restore_factory_reset_resets_desired_state_and_stops_services(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        AuditEvent,
        CaCertificate,
        CaProfile,
        DhcpReservation,
        DhcpSettings,
        DhcpScope,
        DnsRecord,
        DnsSettings,
        FirewallRule,
        KmsClient,
        KmsKey,
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
        assert db.execute(select(KmsClient)).scalars().all() == []
        assert db.execute(select(KmsKey)).scalars().all() == []
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


def test_routes_wan_policy_form_renders(client):
    login(client)
    response = client.get("/routes-wan")
    assert response.status_code == 200
    assert "Routes &amp; WAN Simulation" in response.text
    assert "Managed Routes" in response.text
    assert "Routing Permissions" in response.text
    assert "NAT Rules" in response.text
    assert "WAN Policies" in response.text
    assert "Routes &amp; WAN Simulation has pending appliance changes" in response.text
    assert "Validation" in response.text
    assert "routes-wan-routes-table" in response.text
    assert "routes-wan-routing-table" in response.text
    assert "routes-wan-nat-table" in response.text
    assert "routes-wan-policies-table" in response.text
    assert "auto route-role" in response.text
    assert "explicit access" in response.text
    assert "management isolated" in response.text
    assert "No automatic route-role paths" in response.text
    assert "data-mode-options" not in response.text
    assert "<th>Mode</th>" not in response.text
    assert "+ Add route here" in client.get("/static/app.js").text
    assert "+ Add explicit access rule" in client.get("/static/app.js").text
    assert "+ Add NAT rule here" in client.get("/static/app.js").text
    assert "+ Add policy here" in client.get("/static/app.js").text
    assert "Europe WAN" in response.text
    assert "SiteA outbound WAN" in response.text
    assert "eth1.20" in response.text
    assert "tc qdisc replace" in response.text
    assert "table ip atlaso_nat" in response.text
    assert "Review appliance changes" in response.text


def test_routes_wan_rejects_route_wan_mode(client):
    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "10.21.0.0/24",
            "gateway": "",
            "interface_name": "eth1.20",
            "metric": "120",
            "wan_policy_id": "",
            "wan_mode": "route",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert "planned but not supported in v1" in response.text


def test_routes_wan_allows_ipv6_only_route_targets_but_not_nat_targets(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule, PhysicalInterface, Route

    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="eth6",
                mac_address="00:50:56:aa:bb:66",
                mode="access",
                role="services",
                ip_cidr="",
                ipv6_cidr="fd00:66::1/64",
                admin_state="up",
                oper_state="up",
            )
        )
        db.commit()

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    route_response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "2001:db8:66::/64",
            "gateway": "",
            "interface_name": "eth6",
            "metric": "120",
            "wan_policy_id": "",
            "wan_mode": "interface",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    nat_response = client.post(
        "/routes-wan/nat-rules",
        data={
            "name": "IPv6-only outbound",
            "source": "192.168.50.0/24",
            "outbound_interface": "eth6",
            "masquerade": "on",
            "priority": "110",
            "description": "",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert route_response.status_code == 303
    assert nat_response.status_code == 422
    assert "Choose an access physical interface" in nat_response.text
    mgmt_route_response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "10.49.0.0/24",
            "gateway": "",
            "interface_name": "eth0",
            "metric": "100",
            "wan_policy_id": "",
            "wan_mode": "interface",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert mgmt_route_response.status_code == 422
    assert "Choose an access physical interface" in mgmt_route_response.text
    with SessionLocal() as db:
        route = db.execute(select(Route).where(Route.interface_name == "eth6")).scalar_one()
        assert route.destination_cidr == "2001:db8:66::/64"
        assert db.execute(select(NatRule).where(NatRule.outbound_interface == "eth6")).scalar_one_or_none() is None


def test_routes_wan_autosave_endpoints_and_apply_task(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, NatRule, RoutingRule, WanPolicy

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    policy_response = client.post(
        "/routes-wan/policies",
        data={
            "name": "Metro WAN",
            "description": "short metro impairment",
            "latency_ms": "35",
            "jitter_ms": "5",
            "packet_loss_percent": "0.1",
            "bandwidth_mbit": "250",
            "corrupt_percent": "0",
            "duplicate_percent": "0",
            "reorder_percent": "0",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert policy_response.status_code == 303
    with SessionLocal() as db:
        policy = db.execute(select(WanPolicy).where(WanPolicy.name == "Metro WAN")).scalar_one()
        policy_id = str(policy.id)

    route_response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "10.20.0.0/24",
            "gateway": "",
            "interface_name": "eth1.20",
            "metric": "120",
            "wan_policy_id": policy_id,
            "wan_mode": "interface",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert route_response.status_code == 303
    nat_response = client.post(
        "/routes-wan/nat-rules",
        data={
            "name": "Metro outbound",
            "source": "192.168.50.0/24",
            "outbound_interface": "eth2",
            "masquerade": "on",
            "priority": "110",
            "description": "NAT through test WAN",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert nat_response.status_code == 303
    routing_response = client.post(
        "/routes-wan/routing-rules",
        data={
            "name": "SiteA to WAN",
            "source_interface": "eth1.20",
            "destination_interface": "eth2",
            "priority": "120",
            "description": "Allow SiteA toward WAN link",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert routing_response.status_code == 303
    management_routing_response = client.post(
        "/routes-wan/routing-rules",
        data={
            "name": "Bad management route",
            "source_interface": "eth1.20",
            "destination_interface": "eth0",
            "priority": "120",
            "description": "",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert management_routing_response.status_code == 422
    assert "non-management destination" in management_routing_response.text
    refreshed = client.get("/routes-wan")
    assert "Metro WAN" in refreshed.text
    assert "Metro outbound" in refreshed.text
    assert "SiteA to WAN" in refreshed.text
    assert "10.20.0.0/24" in refreshed.text
    assert "ip saddr 192.168.50.0/24 oifname &#34;eth2&#34; masquerade" in refreshed.text
    assert "ip rule add from 192.168.50.0/24 table 200" in refreshed.text
    assert "tc qdisc replace dev eth1.20" in refreshed.text
    with SessionLocal() as db:
        rule = db.execute(select(NatRule).where(NatRule.name == "Metro outbound")).scalar_one()
        assert rule.outbound_interface == "eth2"
        routing = db.execute(select(RoutingRule).where(RoutingRule.name == "SiteA to WAN")).scalar_one()
        assert routing.source_interface == "eth1.20"

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "wan"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "wan" in (job.result or "")
        assert "NAT rules" in (job.result or "")
        assert "explicit routing rules" in (job.result or "")
        assert "nft -f /etc/atlaso/nftables.d/atlaso-nat.nft" in (job.result or "")
        assert "ip rule add from 192.168.50.0/24 table 200" in (job.result or "")
        assert "tc qdisc replace dev eth1.20" in (job.result or "")


def test_api_token_create_and_revoke_ui(client):
    login(client)
    page = client.get("/authentication")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/authentication/api-tokens",
        data={"name": "UI token", "description": "test", "scopes": "read:dashboard", "csrf": csrf},
    )
    assert created.status_code == 200
    assert "Copy this bearer token now" in created.text
    assert "UI token" in created.text


def test_local_users_page_separates_ldap_authentication(client):
    login(client)
    authentication = client.get("/authentication")
    assert authentication.status_code == 200
    assert "Atlaso LDAP sign-in" in authentication.text
    assert "Managed VCF LDAP service" in authentication.text
    assert "managed separately" in authentication.text

    legacy = client.get("/ldap-users", follow_redirects=False)
    assert legacy.status_code == 303
    assert legacy.headers["location"] == "/ldap"

    users = client.get("/users")
    assert users.status_code == 200
    assert "Local Users" in users.text
    assert "Managed VCF directory users remain isolated" in users.text
    assert "users-table" in users.text
    assert "user-password-modal" in users.text
    assert "data-password-toggle" in users.text
    assert "Password Reset" not in users.text
    assert "Reset password" in users.text
    assert "Remove" in users.text
    assert "Password Policy" in users.text
    assert "Local Users has pending appliance changes" in users.text
    assert "Photon OS" in users.text
    assert "OS account" in users.text
    assert "Shell" in users.text
    assert "Web SSH" in users.text
    assert "Temp Password" not in users.text
    assert "admin" in users.text
    assert "vcf-backup" in users.text
    assert "vcf-depot" in users.text
    assert "data-roles=" in users.text
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/users",
        data={"username": "operator", "role": "viewer", "shell": "/bin/bash", "web_terminal_access": "true", "csrf": csrf},
        follow_redirects=True,
    )
    assert created.status_code == 200
    assert "operator" in created.text
    assert "/bin/bash" in created.text
    assert "allowed" in created.text
    assert "disabled" in created.text
    multi_role_created = client.post(
        "/users",
        data={"username": "multi-role", "roles": ["service-admin", "certificate-operator"], "shell": "/sbin/nologin", "csrf": csrf},
        follow_redirects=False,
    )
    assert multi_role_created.status_code == 303
    stale_role_created = client.post(
        "/users",
        data={"username": "demote-me", "role": "viewer", "roles": "admin", "shell": "/sbin/nologin", "csrf": csrf},
        follow_redirects=False,
    )
    assert stale_role_created.status_code == 303
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    with SessionLocal() as db:
        operator = db.execute(select(User).where(User.username == "operator")).scalar_one()
        assert operator.web_terminal_access is True
        multi_role_user = db.execute(select(User).where(User.username == "multi-role")).scalar_one()
        assert multi_role_user.roles_json == '["service-admin", "certificate-operator"]'
        demote_user = db.execute(select(User).where(User.username == "demote-me")).scalar_one()
        assert "admin" in demote_user.roles_json
        demote_user_id = demote_user.id
    demoted = client.post(
        f"/users/{demote_user_id}/edit",
        data={
            "username": "demote-me",
            "role": "viewer",
            "roles": "admin",
            "roles_text": "viewer",
            "shell": "/sbin/nologin",
            "csrf": csrf,
        },
    )
    assert demoted.status_code == 200
    assert demoted.json()["user"]["roles"] == ["viewer"]
    with SessionLocal() as db:
        demote_user = db.execute(select(User).where(User.username == "demote-me")).scalar_one()
        assert demote_user.roles_json == '["viewer"]'
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "userActionsFormatter" not in app_js.text
    assert "formatter: userActionsFormatter" not in app_js.text
    assert "openUserPasswordModal" in app_js.text
    assert "deleteUserFromMenu" in app_js.text
    assert "Unlock OS account" in app_js.text
    assert "disableUserFromMenu" in app_js.text
    assert "Disable user" in app_js.text
    users_table_js = app_js.text.split("function initializeUsersTable()", 1)[1].split("function initializeUserPasswordForm()", 1)[0]
    roles_column_js = users_table_js.split('title: "Roles"', 1)[1].split('title: "Shell"', 1)[0]
    assert 'field: "roles"' in roles_column_js
    assert 'editor: "list"' in roles_column_js
    assert "multiselect: true" in roles_column_js
    assert "syncUserRoleFields" in roles_column_js
    enabled_column_js = users_table_js.split('title: "Enabled"', 1)[1].split('title: "OS account"', 1)[0]
    assert "editor:" not in enabled_column_js
    assert "validatePasswordMatch" in app_js.text
    assert "initializeNonTabbableHelperControls" in app_js.text
    assert '".help-icon, .password-toggle"' in app_js.text
    assert 'control.setAttribute("tabindex", "-1")' in app_js.text
    assert 'field: "shell"' in app_js.text
    assert 'field: "web_terminal_access"' in app_js.text
    assert 'title: "Web SSH"' in app_js.text
    assert "Temp Password" not in app_js.text


def test_managed_ldap_page_creates_org_user_group_and_shows_secret_once(client):
    login(client)
    page = client.get("/ldap")
    assert page.status_code == 200
    assert "Managed LDAP for VCF Automation" in page.text
    assert 'class="split-workspace service-settings-workspace"' in page.text
    assert 'aria-label="Managed LDAP views"' not in page.text
    assert "LDAP Settings" in page.text
    main_panel_index = page.text.index('<div class="panel wide-panel">')
    settings_rail_index = page.text.index('<aside class="side-stack service-settings-column">')
    assert main_panel_index < settings_rail_index
    settings_rail = page.text[settings_rail_index:]
    assert settings_rail.index("LDAP Settings") < settings_rail.index("Validation")
    assert 'name="ldaps_enabled"' in page.text
    assert 'name="port"' in page.text
    assert 'name="ldap_enabled"' in page.text
    assert 'name="ldap_port"' in page.text
    assert "Management, unused, down, missing, trunk-only" in page.text
    assert "LDAPS / TCP 636 only" not in page.text
    assert "VCF Connections" not in page.text
    assert 'id="ldap-vcf-panel"' not in page.text
    assert "Recovery" not in page.text
    assert "Encrypted LDAP Recovery" not in page.text
    assert "/ldap/recovery/export" not in page.text
    assert "/ldap/recovery/import" not in page.text
    app_css = client.get("/static/app.css").text
    assert ".service-settings-workspace {\n  grid-template-columns: minmax(0, 1fr) 360px;" in app_css
    assert '.tabulator-cell[tabulator-field="uid"] .add-row-hint' in app_css
    assert ".zone-tabs .tab-button" in app_css
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    created = client.post(
        "/ldap/organizations",
        data={"name": "Org A", "slug": "org-a", "suffix_dn": "", "enabled": "on", "csrf": csrf},
    )
    assert created.status_code == 201, created.text
    assert "Copy this credential now" in created.text
    assert 'id="ldap-bind-secret-modal"' in created.text
    assert "data-ldap-bind-secret-auto-open" in created.text
    assert "data-ldap-bind-secret-close" in created.text
    assert "data-copy-value" in created.text
    assert "data-download-value" in created.text
    assert 'data-download-filename="vcf-bind-credential-org-a.txt"' in created.text
    assert "ldap-users-table" in created.text
    assert "ldap-groups-table" in created.text
    assert "data-ldap-organization-tabs" in created.text
    assert ">+ Organization</button>" in created.text
    assert 'id="ldap-organization-new"' in created.text
    assert "<summary>Create organization</summary>" not in created.text
    assert "<summary>Add user</summary>" not in created.text
    assert "<summary>Add group</summary>" not in created.text
    assert "Generate test directory" not in created.text
    assert 'name="user_count"' not in created.text
    assert 'name="group_count"' not in created.text
    organization_header = created.text.split('<div class="zone-head">', 1)[1].split('</div>\n          </div>', 1)[0]
    assert 'class="zone-actions"' in organization_header
    assert 'class="button tiny secondary" type="submit">Rotate bind credential</button>' in organization_header
    assert 'class="button tiny danger" type="submit">Delete organization</button>' in organization_header
    assert 'class="tab-buttons tool-tabs ldap-directory-resource-tabs"' in created.text
    assert "uid=vcf-bind,ou=service-accounts,dc=org-a,dc=ldap,dc=atlaso,dc=internal" in created.text
    assert "serviceAccount → employeeType" not in created.text

    organization_id = created.text.split('/ldap/organizations/', 1)[1].split("/", 1)[0]
    assert f'data-ldap-organization-id="{organization_id}"' in created.text
    assert 'data-tab-storage-key="atlaso:ldap:resource-tab"' in created.text
    app_js = client.get("/static/app.js").text
    assert "window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0)" in app_js
    assert 'target.closest("[data-download-value]")' in app_js
    assert 'document.addEventListener("DOMContentLoaded", () => initializeDownloadValueButtons())' in app_js
    assert 'const LDAP_ORGANIZATION_SELECTION_KEY = "atlaso:ldap:organization"' in app_js
    assert "function initializeLdapPageState()" in app_js
    ldap_page_state_js = app_js.split("function initializeLdapPageState()", 1)[1].split("function attachLdapGridState(", 1)[0]
    assert 'await fetch(link.href' in ldap_page_state_js
    assert 'currentPanel.replaceWith(document.importNode(nextCurrentPanel, true))' in ldap_page_state_js
    assert 'window.history[historyMethod]' in ldap_page_state_js
    assert 'window.addEventListener("popstate"' in ldap_page_state_js
    assert 'window.location.replace(validStoredLink.href)' not in ldap_page_state_js
    assert 'tabList.querySelectorAll(".tab-button")' in ldap_page_state_js
    assert 'newOrganizationPanel.setAttribute("hidden", "")' in ldap_page_state_js
    assert "initializeLdapDirectoryTables()" in ldap_page_state_js
    assert "initializeTabs()" in ldap_page_state_js
    assert "function attachLdapGridState(" in app_js
    assert "function redrawLdapDirectoryTables(" in app_js
    disabled_helper = client.get(f"/vcf-helper?ldap_vcf=1&ldap_organization_id={organization_id}")
    ldap_tile = disabled_helper.text.split("data-vcf-ldap-open", 1)[1].split(">", 1)[0]
    assert "disabled" in ldap_tile
    assert 'data-help="Enable Managed LDAP and at least one organization before using this helper."' in disabled_helper.text
    assert "Enable Managed LDAP first" in disabled_helper.text

    enabled = client.post(
        "/ldap/settings",
        data={"enabled": "on", "hostname": "ldap.atlaso.internal", "listen_interfaces_present": "1", "ldaps_enabled": "on", "port": "636", "ldap_port": "389", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
        follow_redirects=False,
    )
    assert enabled.status_code == 200
    enabled_payload = enabled.json()
    assert enabled_payload["saved"] is True
    assert enabled_payload["settings"]["enabled"] is True
    assert enabled_payload["service_status"]["label"] in {"live", "pending"}
    assert enabled_payload["appliance_apply_status"]["changed"] is True
    vcf_helper = client.get(f"/vcf-helper?ldap_vcf=1&ldap_organization_id={organization_id}")
    assert vcf_helper.status_code == 200
    assert "Managed LDAP for VCF Automation 9.1" in vcf_helper.text
    assert 'data-vcf-ldap-auto-open' in vcf_helper.text
    assert f'/ldap/organizations/{organization_id}/vcf-bundle.zip' in vcf_helper.text
    assert f'/ldap/organizations/{organization_id}/vcf/inspect' in vcf_helper.text
    assert f'/ldap/organizations/{organization_id}/vcf/configure' in vcf_helper.text
    assert "serviceAccount → employeeType" in vcf_helper.text
    assert "Load organization" not in vcf_helper.text
    assert "data-vcf-ldap-organization-form" in vcf_helper.text
    assert "data-vcf-ldap-organization-select" in vcf_helper.text
    vcf_ldap_modal = vcf_helper.text.split('<dialog id="vcf-ldap-modal"', 1)[1].split("</dialog>", 1)[0]
    assert vcf_ldap_modal.count('name="target_url"') == 1
    assert vcf_ldap_modal.count('name="vcf_organization_id"') == 1
    assert vcf_ldap_modal.count('name="username"') == 1
    assert vcf_ldap_modal.count('name="password"') == 1
    assert "Generate LDAP Test Directory" in vcf_helper.text
    assert "data-ldap-generate-open" in vcf_helper.text
    assert "Generate test directory" not in vcf_ldap_modal

    page = client.get("/ldap")
    assert "Copy this credential now" not in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    organization_id = page.text.split('/ldap/organizations/', 1)[1].split("/", 1)[0]
    user = client.post(
        f"/ldap/organizations/{organization_id}/users",
        data={
            "uid": "operator",
            "given_name": "VCF",
            "surname": "Operator",
            "display_name": "VCF Operator",
            "email": "operator@example.invalid",
            "password": "VeryStrong1!Directory",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert user.status_code == 303
    page = client.get(user.headers["location"])
    assert "operator" in page.text
    assert "pending apply" in page.text

    from sqlalchemy import select
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapUser

    with SessionLocal() as db:
        operator_id = db.execute(select(LdapUser.id).where(LdapUser.uid == "operator")).scalar_one()
    edited = client.post(
        f"/ldap/users/{operator_id}/edit",
        data={
            "uid": "operator",
            "given_name": "VCF",
            "surname": "Operator",
            "display_name": "VCF Directory Operator",
            "email": "operator@org-a.test",
            "telephone": "+1-555-010-1000",
            "enabled": "true",
            "csrf": csrf,
        },
        headers={"Accept": "application/json"},
    )
    assert edited.status_code == 200
    assert edited.json()["display_name"] == "VCF Directory Operator"
    grid_group = client.post(
        f"/ldap/organizations/{organization_id}/groups",
        data={"name": "Operators", "description": "VCF operators", "enabled": "false", "csrf": csrf},
        headers={"Accept": "application/json"},
    )
    assert grid_group.status_code == 201
    assert grid_group.json()["enabled"] is False

    app_js = client.get("/static/app.js").text
    ldap_grid_js = app_js.split("function initializeLdapDirectoryTables()", 1)[1].split("function initializeLdapPasswordModal()", 1)[0]
    assert "+ Add user here" in ldap_grid_js
    assert "+ Add group here" in ldap_grid_js
    assert "rowContextMenu" in ldap_grid_js
    assert 'label: "Reset password"' in ldap_grid_js
    assert 'label: "Delete user"' in ldap_grid_js
    assert 'label: "Edit membership"' in ldap_grid_js
    assert "function ldapGroupMembershipFormatter(cell)" in app_js
    assert "formatter: ldapGroupMembershipFormatter" in ldap_grid_js
    assert '<th>Type</th><th>Member</th>' in app_js
    assert "function updateCurrentPageApplyNotice(payload = {})" in app_js
    assert "updateCurrentPageApplyNotice(payload);" in app_js
    assert "function updatePageApplyNotice(status = {})" in app_js
    assert "if (payload.appliance_apply_status) updatePageApplyNotice(payload.appliance_apply_status);" in app_js
    assert "function updateLdapSettingsStatus(payload = {})" in app_js
    assert "if (!tableElement.isConnected || tableElement.offsetParent === null) return;" in app_js


def test_managed_ldap_generates_complete_synthetic_directory_once(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, LdapGroup, LdapOrganization, LdapSettings, LdapUser
    from atlaso.app.services.ldap import clear_pending_ldap_password, has_pending_ldap_password

    login(client)
    page = client.get("/ldap")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/ldap/organizations",
        data={"name": "Synthetic Org", "slug": "synthetic", "suffix_dn": "", "enabled": "on", "csrf": csrf},
    )
    organization_id = int(created.text.split('/ldap/organizations/', 1)[1].split("/", 1)[0])

    with SessionLocal() as db:
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = True
        db.commit()

    generated = client.post(
        f"/ldap/organizations/{organization_id}/generate-directory",
        data={"user_count": "6", "group_count": "3", "csrf": csrf},
    )
    assert generated.status_code == 201, generated.text
    assert "Generated credentials" in generated.text
    assert "uid,password,display_name,email,telephone" in generated.text
    assert "Generated passwords are displayed once" in generated.text
    assert "Created 6 users and 3 groups" in generated.text
    assert "Save the one-time CSV, then submit the Managed LDAP appliance change" in generated.text
    assert "Generate test directory" in generated.text
    assert "data-ldap-generate-auto-open" in generated.text
    generator_modal = generated.text.split('<dialog id="ldap-generate-modal"', 1)[1].split("</dialog>", 1)[0]
    assert "uid,password,display_name,email,telephone" in generator_modal
    assert 'class="language-csv" data-ldap-generated-credentials' in generator_modal
    assert 'data-download-filename="ldap-test-directory-synthetic.csv"' in generator_modal
    assert 'data-download-mime="text/csv;charset=utf-8"' in generator_modal
    assert "<textarea" not in generator_modal
    assert "data-copy-value" in generator_modal
    assert "data-download-value" in generator_modal
    assert generator_modal.count("data-ldap-generated-result") == 2
    assert "data-ldap-generate-user-count" in generator_modal
    assert ">Done</button>" in generator_modal
    assert "data-ldap-generate-close" in generator_modal
    assert "Generate directory entries" not in generator_modal
    assert "Recover missing passwords" not in generator_modal
    managed_ldap_modal = generated.text.split('<dialog id="vcf-ldap-modal"', 1)[1].split("</dialog>", 1)[0]
    assert "uid,password,display_name,email,telephone" not in managed_ldap_modal
    app_js = client.get("/static/app.js").text
    assert 'generateDialog.addEventListener("close", clearGeneratedResult)' in app_js
    assert 'querySelectorAll("[data-ldap-generate-close]")' in app_js
    assert 'generateDialog.querySelectorAll("[data-ldap-generated-result]")' in app_js
    assert 'window.history.replaceState(window.history.state, "", "/vcf-helper")' in app_js
    assert 'generateDialog.querySelector("[data-ldap-generate-user-count]")' in app_js

    with SessionLocal() as db:
        organization = db.get(LdapOrganization, organization_id)
        users = db.execute(select(LdapUser).where(LdapUser.organization_id == organization_id)).scalars().all()
        groups = db.execute(select(LdapGroup).where(LdapGroup.organization_id == organization_id)).scalars().all()
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "generate_ldap_directory")).scalar_one()
        assert organization is not None
        assert len(users) == 6
        assert len(groups) == 3
        assert all(user.given_name and user.surname and user.display_name and user.email and user.telephone for user in users)
        assert all(user.password_status == "pending_apply" for user in users)
        assert all(group.description and group.members for group in groups)
        assert event.detail == "users=6; groups=3"
        assert "Aa1!" not in event.detail

    refreshed = client.get(f"/ldap?organization_id={organization_id}")
    assert "uid\tpassword\tdisplay name\temail\ttelephone" not in refreshed.text

    with SessionLocal() as db:
        users = db.execute(select(LdapUser).where(LdapUser.organization_id == organization_id)).scalars().all()
        for user in users:
            clear_pending_ldap_password(user)
        db.commit()

    helper = client.get(f"/vcf-helper?ldap_organization_id={organization_id}")
    assert "Recover missing passwords (6)" in helper.text
    assert "Generates replacement passwords for enabled users whose one-time passwords are no longer staged" in helper.text
    helper_modal = helper.text.split('<dialog id="ldap-generate-modal"', 1)[1].split("</dialog>", 1)[0]
    assert "Cancel" in helper_modal
    assert "Generate directory entries" in helper_modal
    assert "Done" not in helper_modal
    modal_css = client.get("/static/app.css").text
    assert "width: min(920px, calc(100vw - 32px));" in modal_css
    assert "#ldap-generate-modal .confirm-modal-actions {\n  flex-wrap: nowrap;" in modal_css
    recovered = client.post(
        f"/ldap/organizations/{organization_id}/generate-directory",
        data={
            "user_count": "10",
            "group_count": "3",
            "action": "stage_missing",
            "csrf": csrf,
        },
    )
    assert recovered.status_code == 200, recovered.text
    assert "Staged replacement passwords for 6 existing enabled users" in recovered.text
    assert "Recover missing passwords (6)" not in recovered.text
    assert "uid,password,display_name,email,telephone" in recovered.text

    with SessionLocal() as db:
        users = db.execute(select(LdapUser).where(LdapUser.organization_id == organization_id)).scalars().all()
        event = db.execute(select(AuditEvent).where(AuditEvent.action == "stage_missing_ldap_passwords")).scalar_one()
        assert all(has_pending_ldap_password(user) for user in users)
        assert event.detail == "users=6"


def test_local_user_reset_modal_endpoint_and_remove(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    login(client)
    users = client.get("/users")
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/users",
        data={"username": "remove-me", "role": "viewer", "csrf": csrf},
        follow_redirects=False,
    )
    assert created.status_code == 303

    users = client.get("/users")
    payload = users.text.split("data-users='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    user_id = next(row["id"] for row in rows if row["username"] == "remove-me")
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": "New-temporary1!", "confirm_password": "New-temporary1!", "csrf": csrf},
        follow_redirects=False,
    )
    assert reset.status_code in {200, 303}

    with SessionLocal() as db:
        enabled_user = db.execute(select(User).where(User.username == "remove-me")).scalar_one()
        assert enabled_user.enabled is True

    disabled = client.post(f"/users/{user_id}/disable", data={"csrf": csrf})
    assert disabled.status_code == 200
    with SessionLocal() as db:
        disabled_user = db.execute(select(User).where(User.username == "remove-me")).scalar_one()
        assert disabled_user.enabled is False
        assert disabled_user.os_sync_status == "pending"

    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": "New-temporary1!", "confirm_password": "New-temporary1!", "csrf": csrf},
        follow_redirects=False,
    )
    assert reset.status_code in {200, 303}

    unlock = client.post(f"/users/{user_id}/unlock", data={"csrf": csrf})
    assert unlock.status_code == 200
    with SessionLocal() as db:
        staged_user = db.execute(select(User).where(User.username == "remove-me")).scalar_one()
        assert staged_user.os_unlock_requested_at is not None
        assert staged_user.os_sync_status == "pending"
    review = client.get("/appliance-apply/review")
    local_users_unit = next(unit for unit in review.json()["units"] if unit["id"] == "local_users")
    assert "1 unlock requests" in " ".join(local_users_unit["summary"])

    deleted = client.post(f"/users/{user_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert deleted.status_code == 303
    refreshed = client.get("/users")
    assert "remove-me" not in refreshed.text


def test_local_users_password_policy_staging_and_apply_redaction(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, User

    login(client)
    users = client.get("/users")
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    policy = client.post(
        "/users/password-policy",
        data={
            "csrf": csrf,
            "min_length": "14",
            "require_uppercase": "on",
            "require_lowercase": "on",
            "require_number": "on",
            "require_special": "on",
            "disallow_username": "on",
        },
    )
    assert policy.status_code == 200
    assert policy.json()["policy"]["min_length"] == 14

    created = client.post(
        "/users",
        data={"username": "sync-me", "role": "viewer", "csrf": csrf},
        follow_redirects=False,
    )
    assert created.status_code == 303
    users = client.get("/users")
    import html
    import json

    rows = json.loads(html.unescape(users.text.split("data-users='", 1)[1].split("'", 1)[0]))
    user_id = next(row["id"] for row in rows if row["username"] == "sync-me")

    weak = client.post(
        f"/users/{user_id}/password",
        data={"password": "short", "confirm_password": "short", "csrf": csrf},
    )
    assert weak.status_code == 400
    assert "Password must be at least 14 characters" in weak.text

    plaintext = "BridgeStrong1!"
    reset = client.post(
        f"/users/{user_id}/password",
        data={"password": plaintext, "confirm_password": plaintext, "csrf": csrf},
        follow_redirects=False,
    )
    assert reset.status_code == 303

    with SessionLocal() as db:
        user = db.execute(select(User).where(User.username == "sync-me")).scalar_one()
        assert not hasattr(user, "pending_os_password_encrypted")
        assert not hasattr(user, "password_hash")
        assert user.shell == "/sbin/nologin"
        assert user.enabled is True

    apply_page = client.get("/appliance-apply")
    assert apply_page.status_code == 200
    review = client.get("/appliance-apply/review")
    local_users_unit = next(unit for unit in review.json()["units"] if unit["id"] == "local_users")
    assert local_users_unit["label"] == "Local Users"
    assert "pending OS passwords" in " ".join(local_users_unit["summary"])
    assert plaintext not in review.text

    csrf = apply_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    applied = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "local_users"})
    assert applied.status_code == 200
    assert plaintext not in applied.text

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply").order_by(Job.created_at.desc())).scalars().first()
        assert job is not None
        assert "local-users" in (job.result or "")
        assert plaintext not in (job.result or "")
        user = db.execute(select(User).where(User.username == "sync-me")).scalar_one()
        assert not hasattr(user, "pending_os_password_encrypted")


def test_apply_status_reads_preserve_multiple_staged_service_user_passwords(client):
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User
    from atlaso.app.services.local_users import clear_pending_os_password, has_pending_os_password
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
    from sqlalchemy import select

    import atlaso.app.ui as ui_module
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, User

    base_system_adapter = ui_module.SystemAdapter

    class SuccessfulLocalUsersAdapter(base_system_adapter):
        def __init__(self) -> None:
            super().__init__(dry_run=False)

        def read_dhcp_leases(self) -> AdapterResult:
            return AdapterResult(command=["atlaso-helper", "dnsmasq", "leases"], dry_run=True, stdout="")

        def validate_local_users_config(self, config_path: str) -> AdapterResult:
            return AdapterResult(command=["atlaso-helper", "local-users", "validate", config_path], dry_run=False, stdout="validation ok")

        def apply_local_users_config(self, config_path: str) -> AdapterResult:
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
    assert staged_path.is_file()
    assert "BridgeStrong1!" not in applied.text

    with SessionLocal() as db:
        users = db.execute(select(User)).scalars().all()
        assert all(user.os_sync_status == "applied" for user in users)
        baseline = db.execute(select(Setting).where(Setting.key == "appliance_apply.baselines.v1")).scalar_one()
        assert "BridgeStrong1!" not in baseline.value
        assert '"password_pending": true' not in baseline.value


def test_audit_log_renders(client):
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
    assert "scrollbar-gutter: stable;" not in css.text
    assert "scrollbar-width: thin;" not in css.text
    assert "scrollbar-color:" not in css.text
    assert "overscroll-behavior:" not in css.text
    assert "::-webkit-scrollbar-thumb" in css.text
    assert "white-space: nowrap;" in css.text


def test_configure_logging_writes_main_app_log(tmp_path, monkeypatch):
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


def test_record_audit_writes_redacted_operational_log(client, tmp_path, monkeypatch):
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


def test_dns_and_dhcp_pages_render(client):
    import html
    import json

    login(client)
    dns = client.get("/dns")
    assert dns.status_code == 200
    assert "DNS Zones" in dns.text
    assert "dns-records-fallback" in dns.text
    assert "dnsmasq" in dns.text
    assert "core.atlaso.internal" in dns.text
    assert "<strong>Avoid .local for VCF.</strong>" not in dns.text
    assert "+ Domain" in dns.text
    assert "New Domain" in dns.text
    assert "Import Hosts" in dns.text
    assert "Import Zone File" in dns.text
    assert "Reverse Zones" in dns.text
    assert "Reverse/PTR" in dns.text
    assert "PTR records are generated automatically" in dns.text
    assert "zone-file-editor" in dns.text
    assert "dns-import-form" in dns.text
    assert "dns-import-controls" in dns.text
    assert "data-codemirror-editor" in dns.text
    assert 'data-codemirror-language="atlaso-hosts"' in dns.text
    assert 'data-codemirror-language="atlaso-zone"' in dns.text
    assert "Import zone file into atlaso.internal" in dns.text
    assert "relative hostnames are saved inside this domain" in dns.text
    assert 'data-domain="atlaso.internal"' in dns.text
    assert "A (IPv4)" in dns.text
    assert "AAAA (IPv6)" in dns.text
    assert "CNAME (alias)" in dns.text
    assert "ptr-record=" not in dns.text
    assert "1.49.168.192.in-addr.arpa" in dns.text
    assert 'name="listen_interfaces"' in dns.text
    assert 'data-derived-listen-addresses' in dns.text
    assert 'name="conditional_forwarders"' in dns.text
    assert "Conditional forwarders" in dns.text
    assert "domain=server1,server2" in dns.text
    assert "sddc.internal=192.168.10.10,192.168.10.11" in dns.text
    assert dns.text.count('data-tag-editor') >= 1
    assert dns.text.count('data-tag-menu-toggle') >= 1
    assert dns.text.count('data-tag-option=') >= 2
    assert 'data-tag-empty-message="No interfaces available."' in dns.text
    assert 'placeholder="Add interface..."' in dns.text
    assert 'placeholder="Add listen address..."' not in dns.text
    assert "eth1 - access / trunk" not in dns.text
    assert 'action="/dns/zones"' in dns.text
    assert 'action="/dns/zones/delete"' in dns.text
    assert "data-confirm-modal" in dns.text
    assert "Delete atlaso.internal?" in dns.text
    assert "It will not touch the appliance until global appliance apply runs." in dns.text
    assert 'action="/dns/zones/import"' in dns.text
    assert 'href="/dashboard#appliance-apply-review"' in dns.text
    assert "atlaso.internal or sitea.internal" in dns.text
    assert "Changes save automatically." in dns.text
    assert "Review appliance changes" in dns.text
    assert "Save desired state" not in dns.text
    assert "Save DNS" not in dns.text

    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "cellEdited" in app_js.text
    assert "rowContextMenu" in app_js.text
    assert "newDnsRecordRow" in app_js.text
    assert "rowHeight: 28" in app_js.text
    assert 'field: "host_label"' in app_js.text
    assert "dnsAddRowHintFormatter" in app_js.text
    assert "pendingNewDnsRecord" in app_js.text
    assert 'markNewRecordRow(row, "host_label")' in app_js.text
    assert "dnsRecordDomainFormatter" in app_js.text
    assert 'field: "domain", formatter: dnsRecordDomainFormatter' in app_js.text
    assert "dnsRecordCellEditable" in app_js.text
    assert app_js.text.count("editable: dnsRecordCellEditable") >= 5
    assert "+ Add record here" in app_js.text
    assert "initializeZoneEditors" in app_js.text
    assert "A (IPv4)" in app_js.text
    assert "AAAA (IPv6)" in app_js.text
    assert "CNAME (alias)" in app_js.text
    assert "reverseStatusFormatter" in app_js.text
    assert 'title: "Reverse/PTR"' in app_js.text
    assert 'newDnsRecordRow(domain, tableElement.dataset.suggestedIpv4 || "")' in app_js.text
    assert "suggested_ipv4: suggestedAddress" in app_js.text
    assert 'data.record_type !== "A" && data.address === data.suggested_ipv4' in app_js.text
    assert 'cell.getField() === "host_label"' in app_js.text
    assert "DNS_ACTIVE_ZONE_STORAGE_KEY" in app_js.text
    assert "initializeCodeMirrorEditors" in app_js.text
    assert "const atlasoDnsRecordTables = new WeakMap()" in app_js.text
    assert "function redrawDnsRecordTables" in app_js.text
    assert "atlasoDnsRecordTables.set(tableElement, table)" in app_js.text
    assert "redrawDnsRecordTables(panel)" in app_js.text
    assert "installCodeMirrorPlainTextFallback" in app_js.text
    assert 'textarea.dataset.codemirrorLanguage !== "atlaso-kickstart"' in app_js.text
    assert 'addEventListener("keydown"' in app_js.text
    assert "event.stopPropagation()" in app_js.text
    assert "data-tag-empty" in app_js.text
    assert "No options available." in app_js.text
    assert "AtlasoCodeMirror.setValue" in app_js.text
    assert "rememberDnsActiveZone(data.domain)" in app_js.text
    assert "dnsZoneTabButtonForDomain(storedDomain)" in app_js.text
    assert "initializeTagEditors" in app_js.text
    assert "initializeEsxiIsoUploadForms" in app_js.text
    assert "XMLHttpRequest" in app_js.text
    assert "X-Atlaso-Upload" in app_js.text
    assert 'rememberActiveTab("atlaso:esxi-pxe:active-tab", "esxi-pxe-isos-panel")' in app_js.text
    assert 'window.location.hash = "esxi-pxe-isos-panel"' in app_js.text
    assert "initializeEsxiPxeHostsTable" in app_js.text
    assert 'document.getElementById(hashTargetId)?.closest(".tab-panel")' in app_js.text
    assert 'querySelector(".tag-editor[data-service-bind-interface]")' in app_js.text
    assert 'querySelector(".tag-editor[data-service-bind-address]")' in app_js.text
    assert "initializeConfirmationModals" in app_js.text
    assert "requestConfirmation" in app_js.text
    assert "form[data-confirm-modal]" in app_js.text
    assert "confirm-modal" in app_js.text
    assert "initializeConfigPreviewActions" in app_js.text
    assert "[data-config-preview-open]" in app_js.text
    assert "openPreviewModal(button.dataset.previewTitle" in app_js.text
    assert "initializeAutosaveForms" in app_js.text
    assert "ATLASO_MUTATING_METHODS" in app_js.text
    assert "scheduleApplianceApplySidebarRefresh" in app_js.text
    assert 'fetch("/appliance-apply/status"' in app_js.text
    assert "function updateServerTime" in app_js.text
    assert "window.setInterval(load, 5000)" in app_js.text
    assert "initializeApplianceApplyProgress" in app_js.text
    assert "Submit appliance changes" in app_js.text
    assert "openApplianceApplyReview" in app_js.text
    assert "renderApplianceApplyTask" in app_js.text
    assert "const APPLIANCE_APPLY_SUCCESS_AUTO_CLOSE_MS = 15000;" in app_js.text
    assert "function clearApplianceApplyAutoClose()" in app_js.text
    assert "function scheduleApplianceApplyAutoClose(task)" in app_js.text
    assert 'task?.status !== "succeeded"' in app_js.text
    assert 'modal.dataset.taskStatus === "succeeded"' in app_js.text
    assert 'elements.modal.addEventListener("close", clearApplianceApplyAutoClose)' in app_js.text
    assert "scheduleApplianceApplyAutoClose(task);" in app_js.text
    assert "Management connection warning" in app_js.text
    assert "applyConnectionWarnings" in app_js.text
    assert 'elements.submit.classList.add("hidden")' in app_js.text
    assert 'elements.submit.classList.toggle("hidden", units.length === 0)' in app_js.text
    assert '{ title: "Status", field: "status", width: 150' in app_js.text
    assert 'applianceApplyModalTable?.on("rowClick"' in app_js.text
    assert 'atlasoTasksTable?.on("rowClick"' in app_js.text
    assert "data-appliance-apply-modal" in app_js.text
    assert "data-appliance-apply-connection-warning" in dns.text
    assert 'class="button primary hidden" type="submit" data-appliance-apply-submit' in dns.text
    assert "data-apply-submit-tracker" not in app_js.text
    assert "index === 0 ? \"Applying\"" not in app_js.text
    assert "initializeDhcpScopesTable" in app_js.text
    assert "autoSaveDhcpScope" in app_js.text
    assert "+ Add IP zone here" in app_js.text
    assert "isUniqueNewDhcpScopeName" in app_js.text
    assert "dhcpScopeCellEditable" in app_js.text
    assert "dhcpRangeFormatter" in app_js.text
    assert "dhcpRangeTooltipRows" in app_js.text
    assert "if (!String(data.name ?? \"\").trim())" in app_js.text
    assert 'if (data.address_family === "ipv6")' in app_js.text
    assert 'address_family: ""' in app_js.text
    assert 'interface_name: ""' in app_js.text
    assert 'lease_time: ""' in app_js.text
    assert 'if (!data.interface_name)' in app_js.text
    assert "isUniqueNewDhcpScopeName(data, existingScopeNames)" in app_js.text
    assert "cellMouseEnter" in app_js.text
    assert "dhcpScopeFamilyEditable" in app_js.text
    assert "if (!data.is_new)" in app_js.text
    assert "dhcpDefaultFamilyForInterface(scopeDefaults, data.interface_name || defaultInterface)" in app_js.text
    assert "applyDhcpScopeInterfaceDefaults" in app_js.text
    assert 'title: "Family"' in app_js.text
    assert "address_family" in app_js.text
    assert 'title: "NTP"' in app_js.text
    assert "domainOptions" in app_js.text
    assert "domainValues" in app_js.text
    assert "initializeDhcpOptionsTable" in app_js.text
    assert "autoSaveDhcpOption" in app_js.text
    assert "+ Add DHCP option here" in app_js.text
    assert "initializeDhcpReservationsTable" in app_js.text
    assert "autoSaveDhcpReservation" in app_js.text
    assert "+ Add reservation here" in app_js.text
    assert "dhcpReservationCellEditable" in app_js.text
    assert "dhcpReservationAddRowHintFormatter" in app_js.text
    assert "dhcpReservationHasHostname(data)" in app_js.text
    assert 'field: "zone_name"' in app_js.text
    assert 'title: "DNS name / FQDN"' in app_js.text
    assert "initializeCaSettings" in app_js.text
    assert "data-ca-config-preview" in app_js.text
    assert "data-ca-derived-address" not in app_js.text
    assert "initializeServiceBindEditors" in app_js.text
    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200
    assert ".tab-panel {\n  min-width: 0;\n}" in app_css.text
    assert ".dns-records-table {\n  width: 100%;\n  max-width: 100%;" in app_css.text
    assert ".dns-records-table .tabulator-tableholder {\n  overflow-x: auto;" in app_css.text
    assert "data-tag-single" in app_js.text
    assert "X-Atlaso-Autosave" in app_js.text
    assert "tag-editor:change" in app_js.text
    assert "data-tag-menu-toggle" in app_js.text
    assert 'data-action="save"' not in app_js.text

    app_css = client.get("/static/app.css")
    assert app_css.status_code == 200
    assert "margin: 0;" in app_css.text
    assert "background: var(--bg);" in app_css.text
    assert "color: var(--text);" in app_css.text
    assert ".add-row-hint" in app_css.text
    assert ".dhcp-range-tooltip" in app_css.text
    assert ".new-record-row-locked" in app_css.text
    assert ".new-record-row-pending" in app_css.text
    assert 'tabulator-field="host_label"' in app_css.text
    assert ".alert.warning" in app_css.text
    assert ".tag-editor" in app_css.text
    assert ".tag-add-button" in app_css.text
    assert ".tag-suggestions" in app_css.text
    assert ".tag-empty-option" in app_css.text
    assert ".autosave-status" in app_css.text
    assert ".appliance-apply-form" in app_css.text
    assert ".apply-change-set-panel" in app_css.text
    assert ".form-grid > label > .field-label" in app_css.text
    assert ".service-bind-editor" in app_css.text
    assert ".apply-submit-panel" in app_css.text
    assert ".config-diff code" in app_css.text
    assert "overflow-wrap: anywhere;" in app_css.text
    assert "white-space: pre-wrap;" in app_css.text
    assert ".page-apply-notice" in app_css.text
    assert ".apply-inline-tracker" in app_css.text
    assert ".apply-progress-modal" not in app_css.text
    assert ".apply-step-row" in app_css.text
    assert ".confirm-modal" in app_css.text
    assert ".confirm-modal::backdrop" in app_css.text
    assert ".appliance-apply-modal::backdrop" in app_css.text
    assert "-webkit-user-select: none;" in app_css.text
    assert "-webkit-backdrop-filter: blur(2px);" in app_css.text
    assert "backdrop-filter: blur(2px);" in app_css.text
    assert "background: var(--surface);" in app_css.text
    assert "width: min(1180px, calc(100vw - 40px));" in app_css.text
    assert "max-height: min(560px, 55vh);" in app_css.text
    assert ".section-head" in app_css.text
    assert ".dns-import-controls" in app_css.text
    assert "min-height: clamp(360px, 50vh, 640px) !important;" in app_css.text

    dhcp = client.get("/dhcp")
    assert dhcp.status_code == 200
    assert "DHCP IP Zones" in dhcp.text
    assert "Desired State" in dhcp.text
    assert "Generated PXE" in dhcp.text
    assert "Actual Leases" in dhcp.text
    assert 'id="dhcp-generated-pxe"' in dhcp.text
    assert 'id="dhcp-actual-leases"' in dhcp.text
    assert "api-client.atlaso.internal" in dhcp.text
    assert "atlaso-helper dnsmasq leases" in dhcp.text
    assert "dhcp-scopes-table" in dhcp.text
    assert "data-scope-defaults" in dhcp.text
    assert "data-domain-options" in dhcp.text
    assert 'data-domain-options=\'["atlaso.internal"]\'' in dhcp.text
    assert "atlaso.internal" in dhcp.text
    assert "dhcp-scopes-fallback" in dhcp.text
    assert "DHCP Options" in dhcp.text
    assert "dhcp-options-table" in dhcp.text
    assert "dhcp-options-fallback" in dhcp.text
    assert "dhcp-reservations-table" in dhcp.text
    assert "dhcp-reservations-fallback" in dhcp.text
    assert "DNS name / FQDN" in dhcp.text
    assert 'data-autosave-status-id="dhcp-settings-autosave-status"' in dhcp.text
    assert "Changes save automatically." in dhcp.text
    assert 'href="/dashboard#appliance-apply-review"' in dhcp.text
    assert "Review appliance changes" in dhcp.text
    assert "Save DHCP" not in dhcp.text
    assert "192.168.50.100" in dhcp.text
    assert "192.168.50.1" in dhcp.text
    reservation_payload = dhcp.text.split("data-reservations='", 1)[1].split("'", 1)[0]
    reservation_rows = json.loads(html.unescape(reservation_payload))
    assert reservation_rows
    assert all("zone_name" in row for row in reservation_rows)


def test_new_record_rows_lock_defaults_until_required_field(client):
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
    assert 'editor: "tickCross"' in firewall_block
    assert ".new-record-row-pending" in app_css.text
    assert ".new-record-primary-cell" in app_css.text

    def function_block(name, next_name):
        start = app_js.text.index(f"function {name}()")
        end = app_js.text.index(f"function {next_name}", start)
        return app_js.text[start:end]

    expected_blocks = [
        ("initializeFirewallRulesTable", "managedFirewallStatusFormatter", "name"),
        ("initializeKmsKeysTable", "initializeCaSettings", "name"),
        ("initializeEsxiPxeHostsTable", "initializeHostsFileEditor", "hostname"),
        ("initializeVcfDepotProfilesTable", "initializeVcfDepotSettings", "name"),
        ("initializeVcfRegistryBundlesTable", "initializeVcfRegistrySettings", "name"),
        ("initializeRoutesWanRoutesTable", "initializeRoutesWanPoliciesTable", "destination_cidr"),
        ("initializeRoutesWanRoutingTable", "initializeRoutesWanNatTable", "name"),
        ("initializeRoutesWanNatTable", "initializeRoutesWanRoutesTable", "name"),
        ("initializeRoutesWanPoliciesTable", "showNetworkMessage", "name"),
    ]
    for name, next_name, required_field in expected_blocks:
        block = function_block(name, next_name)
        assert "columns: lockNewRecordColumns([" in block, name
        assert f'], "{required_field}"),' in block, name
        assert f'markNewRecordRow(row, "{required_field}")' in block, name

    ca_certificates_block = function_block("initializeCaCertificatesTable", "initializeFirewallRulesTable")
    assert "columns: lockNewRecordColumns([" not in ca_certificates_block
    assert "+ Add certificate here" in ca_certificates_block
    assert "openCaCertificateModal" in ca_certificates_block

    dns_block = app_js.text[
        app_js.text.index("function initializeDnsRecordsTableElement"):
        app_js.text.index("function initializeDhcpScopesTable")
    ]
    assert 'markNewRecordRow(row, "host_label")' in dns_block


def test_dhcp_zone_defaults_follow_vlan_dns_and_interface_ntp_bindings(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NtpSettings, DnsSettings, PhysicalInterface

    with SessionLocal() as db:
        eth2_interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth2")).scalar_one()
        eth2_interface.ipv6_cidr = "fd00:50::1/64"
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dns_settings.listen_interface = "eth2\neth1.20"
        dns_settings.listen_address = "192.168.50.1\nfd00:50::1\n192.168.20.1"
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = True
        ntp_settings.listen_interface = "eth2"
        ntp_settings.listen_address = "192.168.50.1\nfd00:50::1"
        db.add_all([eth2_interface, dns_settings, ntp_settings])
        db.commit()

    login(client)
    page = client.get("/dhcp")

    assert page.status_code == 200
    payload = page.text.split("data-scope-defaults='", 1)[1].split("'", 1)[0]
    defaults = json.loads(html.unescape(payload))
    eth2 = next(item for item in defaults["interfaces"] if item["name"] == "eth2")
    eth1_vlan = next(item for item in defaults["interfaces"] if item["name"] == "eth1.20")
    assert eth2["ipv4_address"] == "192.168.50.1"
    assert eth2["ipv4_prefix"] == 24
    assert eth2["ipv6_address"] == "fd00:50::1"
    assert eth2["ipv6_prefix"] == 64
    assert eth2["dns_default"] == "192.168.50.1"
    assert eth2["ntp_default"] == "192.168.50.1"
    assert eth2["ipv4_dns_default"] == "192.168.50.1"
    assert eth2["ipv6_dns_default"] == "fd00:50::1"
    assert eth2["ipv4_ntp_default"] == "192.168.50.1"
    assert eth2["ipv6_ntp_default"] == "fd00:50::1"
    assert eth1_vlan["dns_default"] == "192.168.20.1"
    assert eth1_vlan["ipv4_dns_default"] == "192.168.20.1"
    assert eth1_vlan["ntp_default"] == ""
    assert "sitea" in defaults["existing_names"]
    assert defaults["default_domain"] == "atlaso.internal"
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "dhcpDefaultFamilyForInterface" in app_js.text
    assert 'rowData.dns_server = dnsDefault || "";' in app_js.text
    assert 'rowData.ntp_server = ntpDefault || "";' in app_js.text
    assert 'rowData.site_address = gateway || "";' in app_js.text
    assert 'rowData.prefix_length = Number.isInteger(prefix) ? prefix : "";' in app_js.text
    assert 'if ((data.is_new && field === "name") || ["interface_name", "address_family"].includes(field)) {' in app_js.text


def test_dns_new_record_row_suggests_next_available_ipv4(client):
    import html
    import json

    login(client)
    page = client.get("/dns")

    assert page.status_code == 200
    assert 'data-suggested-ipv4="192.168.50.2"' in page.text
    payload = page.text.split("data-records='", 1)[1].split("'", 1)[0]
    records = json.loads(html.unescape(payload))
    assert any(record["address"] == "192.168.49.1" for record in records)


def test_dns_ipv4_suggestion_falls_back_to_existing_a_record_network():
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


def test_dns_settings_badge_reflects_desired_state_not_runtime_state(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, ServiceState

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(DnsSettings)).scalar_one()
        settings.enabled = True
        service = db.execute(select(ServiceState).where(ServiceState.service == "dns")).scalar_one()
        service.enabled = False
        service.running = False
        service.health = "disabled"
        db.commit()

    page = client.get("/dns")
    settings_panel = page.text.split("<h2>DNS Settings</h2>", 1)[1].split("</form>", 1)[0]

    assert page.status_code == 200
    assert '<span class="status-pill good">enabled</span>' in settings_panel
    assert '<span class="status-pill muted">disabled</span>' not in settings_panel


def test_dhcp_leases_page_reflects_live_adapter_output(client, monkeypatch):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpReservation, DnsRecord, EsxiPxeHost

    def fake_read_dhcp_leases(self):
        return AdapterResult(
            command=["sudo", "-n", "/opt/atlaso/bin/atlaso-helper", "dnsmasq", "leases", "--real"],
            dry_run=False,
            stdout=(
                "1893456000 02:15:5d:00:20:40 192.168.50.140 live-client.atlaso.internal *\n"
                "1893456000 02:15:5d:00:20:41 192.168.1.110 stale-client.atlaso.internal *\n"
            ),
        )

    monkeypatch.setattr("atlaso.app.ui.SystemAdapter.read_dhcp_leases", fake_read_dhcp_leases)

    login(client)
    page = client.get("/dhcp")

    assert page.status_code == 200
    assert '<span class="status-pill good">live</span>' in page.text
    assert "sudo -n /opt/atlaso/bin/atlaso-helper dnsmasq leases --real" in page.text
    assert "live-client.atlaso.internal" in page.text
    assert "stale-client.atlaso.internal" not in page.text
    assert "192.168.1.110" not in page.text
    assert "dhcp-leases-table" in page.text
    assert "dhcp-leases-fallback" in page.text
    assert "data-leases=" in page.text
    lease_payload = page.text.split("data-leases='", 1)[1].split("'", 1)[0]
    lease_rows = json.loads(html.unescape(lease_payload))
    assert lease_rows == [
        {
            "status": "active",
            "hostname": "live-client.atlaso.internal",
            "ip_address": "192.168.50.140",
            "zone_name": "SiteA",
            "mac_address": "02:15:5d:00:20:40",
            "expires_at": "2030-01-01T00:00:00+00:00",
            "client_id": "",
        }
    ]
    assert "data-dhcp-lease-reservation" in page.text
    assert "data-dhcp-lease-pxe-host" in page.text
    assert "dhcp-lease-reservation-modal" in page.text
    assert "dhcp-lease-pxe-modal" in page.text
    assert "Create reservation" in page.text
    assert "Create PXE entry" in page.text
    assert "Deny DHCP for MAC" in page.text
    app_js = client.get("/static/app.js").text
    assert "initializeDhcpLeasesTable" in app_js
    assert "rowContextMenu" in app_js
    assert "openDhcpLeasePxeModal" in app_js
    assert "dhcpLeaseActionFormatter" not in app_js
    assert "openDhcpLeaseActionsMenu" not in app_js
    assert "Create PXE entry" in app_js
    assert "Deny DHCP for MAC" in app_js
    assert "initializeDhcpLeaseReservationActions" in app_js
    assert '<span class="status-pill warn">dry-run</span>' not in page.text

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dhcp/reservations",
        data={
            "hostname": "live-client.atlaso.internal",
            "mac_address": "02:15:5d:00:20:40",
            "ip_address": "192.168.50.140",
            "description": "Created from live DHCP lease 192.168.50.140.",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        reservation = db.execute(select(DhcpReservation).where(DhcpReservation.mac_address == "02:15:5d:00:20:40")).scalar_one()
        assert reservation.hostname == "live-client.atlaso.internal"
        assert reservation.ip_address == "192.168.50.140"
        assert reservation.enabled is True
        record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "live-client.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert record.address == "192.168.50.140"

    with SessionLocal() as db:
        from atlaso.app.models import DhcpScope
        from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

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
        db.commit()

    pxe_response = client.post(
        "/dhcp/leases/pxe-host",
        data={
            "hostname": "pxe-client.atlaso.internal",
            "mac_address": "02:15:5d:00:20:42",
            "ip_address": "192.168.50.142",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert pxe_response.status_code == 303
    assert pxe_response.headers["location"] == "/esxi-pxe#esxi-pxe-hosts"
    with SessionLocal() as db:
        host = db.execute(select(EsxiPxeHost).where(EsxiPxeHost.mac_address == "02:15:5d:00:20:42")).scalar_one()
        assert host.hostname == "pxe-client.atlaso.internal"
        assert host.ip_address == "192.168.50.142"
        assert host.enabled is True

    deny_response = client.post(
        "/dhcp/leases/deny",
        data={
            "hostname": "deny-client.atlaso.internal",
            "mac_address": "02:15:5d:00:20:43",
            "ip_address": "192.168.50.143",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert deny_response.status_code == 303
    with SessionLocal() as db:
        deny = db.execute(select(DhcpReservation).where(DhcpReservation.mac_address == "02:15:5d:00:20:43")).scalar_one()
        assert deny.enabled is False
        assert deny.description == "Deny DHCP for 02:15:5d:00:20:43."


def test_firewall_preview_derives_dns_dhcp_rule_from_dhcp_scope_vlan(client):
    import html
    import json
    import re

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, FirewallRule, VlanInterface

    with SessionLocal() as db:
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.interface_name = "eth2.50"
        scope.site_address = "192.168.50.1"
        scope.prefix_length = 24
        scope.enabled = True
        legacy_rule = db.execute(select(FirewallRule).where(FirewallRule.name == "sitea-dns-dhcp")).scalar_one()
        legacy_rule.interface_name = "eth1"
        if db.execute(select(VlanInterface).where(VlanInterface.name == "eth2.50")).scalar_one_or_none() is None:
            db.add(
                VlanInterface(
                    name="eth2.50",
                    parent_interface="eth2",
                    vlan_id=50,
                    ip_cidr="192.168.50.1/24",
                    role="services",
                    enabled=True,
                )
            )
        db.commit()

    login(client)
    firewall = client.get("/firewall")

    assert firewall.status_code == 200
    assert "Managed Service Rules" in firewall.text
    assert "Groups" in firewall.text
    assert "data-firewall-validation-refresh" in firewall.text
    assert "Add group" in firewall.text
    assert "No custom groups yet." in firewall.text
    assert 'data-source-group-select' not in firewall.text
    assert firewall.text.index('class="form-stack source-group-create-form"') < firewall.text.index('class="source-group-manager"')
    assert "eth2.50" in firewall.text
    assert "data-interfaces=" in firewall.text
    assert "&#34;eth2.50&#34;" in firewall.text
    assert "data-source-groups=" in firewall.text
    assert "data-groups=" in firewall.text
    editable_payload = re.search(r'id="firewall-rules-table"[^>]+data-rules=\'([^\']*)\'', firewall.text, re.S)
    managed_payload = re.search(r'id="managed-firewall-rules-table"[^>]+data-rules=\'([^\']*)\'', firewall.text, re.S)
    assert editable_payload is not None
    assert managed_payload is not None
    editable_rows = json.loads(html.unescape(editable_payload.group(1)))
    managed_rows = json.loads(html.unescape(managed_payload.group(1)))
    assert not any(row["name"] == "sitea-dns-dhcp" and row["interface_name"] == "eth1" for row in editable_rows)
    assert any(row["name"] == "sitea-dns-dhcp" and row["interface_name"] == "eth1" and row["managed_state"] == "replaced" for row in managed_rows)
    assert any(row["name"] == "sitea-dns-dhcp" and row["interface_name"] == "eth2.50" and row["managed_state"] == "generated" for row in managed_rows)
    assert any(row["name"] == "mgmt-console" and row["managed_state"] == "generated" and row["source_group_id"] == "any" and row["source_group_name"] == "Any" for row in managed_rows)
    generated_index = next(i for i, row in enumerate(managed_rows) if row["name"] == "sitea-dns-dhcp" and row["managed_state"] == "generated")
    replaced_index = next(i for i, row in enumerate(managed_rows) if row["name"] == "sitea-dns-dhcp" and row["managed_state"] == "replaced")
    assert replaced_index == generated_index + 1
    assert 'iifname &#34;eth2.50&#34; udp dport 67 accept comment &#34;sitea-dns-dhcp&#34;' in firewall.text
    assert 'iifname &#34;eth1&#34; ip saddr 192.168.50.0/24 udp dport { 53, 67 } accept comment &#34;sitea-dns-dhcp&#34;' not in firewall.text

    csrf = firewall.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    group_response = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "create",
            "group_name": "Managed clients",
            "group_entries": "any",
        },
    )
    assert group_response.status_code == 200

    group_response = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": "custom:managed-clients",
            "group_name": "Managed clients",
            "group_entries": "10.77.0.0/16",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert group_response.status_code == 200
    assert group_response.json()["status"] == "saved"
    assert group_response.json()["updated_at"]
    assert "config_preview" in group_response.json()

    rename_response = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "rename",
            "group_id": "custom:managed-clients",
            "group_name": "Managed client sources",
        },
    )
    assert rename_response.status_code == 200

    assignment_response = client.post(
        "/firewall/managed-rules/source-group",
        data={"csrf": csrf, "rule_name": "mgmt-console", "source_group_id": "custom:managed-clients"},
    )
    assert assignment_response.status_code == 200

    rule_response = client.post(
        "/firewall/rules",
        data={
            "csrf": csrf,
            "name": "grouped-custom",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "group:custom:managed-clients",
            "destination": "group:custom:managed-clients",
            "destination_port": "443",
            "interface_name": "eth2.50",
            "priority": "101",
            "enabled": "on",
        },
    )
    assert rule_response.status_code == 200

    updated_firewall = client.get("/firewall")
    assert "10.77.0.0/16" in updated_firewall.text
    assert "Managed client sources" in updated_firewall.text
    assert "data-source-group-rename" in updated_firewall.text
    source_group_manager = re.search(r'<div class="source-group-manager" data-source-group-manager>(.*?)</div>\s*<dialog id="firewall-rename-group-modal"', updated_firewall.text, re.S)
    assert source_group_manager is not None
    assert 'data-source-group-select' in source_group_manager.group(1)
    assert '<option value="any">' not in source_group_manager.group(1)
    assert 'iifname &#34;eth0&#34; ip saddr 10.77.0.0/16 tcp dport { 22, 80, 443 } accept comment &#34;mgmt-console&#34;' in updated_firewall.text
    assert 'iifname &#34;eth2.50&#34; ip saddr 10.77.0.0/16 ip daddr 10.77.0.0/16 tcp dport 443 accept comment &#34;grouped-custom&#34;' in updated_firewall.text
    assert 'iifname &#34;eth2.50&#34; udp dport 67 accept comment &#34;sitea-dns-dhcp&#34;' in updated_firewall.text

    apply_page = client.get("/appliance-apply")
    assert apply_page.status_code == 200
    review = client.get("/appliance-apply/review")
    units = {unit["id"]: unit for unit in review.json()["units"]}
    assert units["dnsmasq"]["label"] == "DNS/DHCP (dnsmasq)"
    assert units["firewall"]["label"] == "Firewall"
    assert "eth2.50" in units["firewall"]["config_preview"]


def test_dns_listen_options_include_access_and_vlans_not_trunks(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="eth9",
                mac_address="00:15:5d:00:00:99",
                role="unused",
                mode="access",
                ip_cidr="192.168.90.1/24",
            )
        )
        db.add(
            VlanInterface(
                name="eth1.60",
                parent_interface="eth1",
                vlan_id=60,
                ip_cidr="192.168.60.1/24",
                role="services",
                enabled=True,
            )
        )
        db.add(
            VlanInterface(
                name="eth1.70",
                parent_interface="eth1",
                vlan_id=70,
                ip_cidr="192.168.70.1/24",
                role="unused",
                enabled=True,
            )
        )
        db.commit()

    login(client)
    page = client.get("/dns")

    assert page.status_code == 200
    assert "eth2 - access / access / 192.168.50.1" in page.text
    assert "eth1.60 - VLAN 60 on eth1 / services / 192.168.60.1" in page.text
    assert "eth1 - access / trunk" not in page.text
    assert "eth9 - unused / access / 192.168.90.1" not in page.text
    assert "eth1.70 - VLAN 70 on eth1 / unused / 192.168.70.1" not in page.text
    assert 'data-tag-option="eth1.60"' in page.text
    assert 'data-tag-option="eth9"' not in page.text
    assert 'data-tag-option="eth1.70"' not in page.text
    assert 'data-tag-option="192.168.60.1"' not in page.text


def test_certificate_authority_page_renders(client):
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
    assert 'id="ca-certificate-modal"' in ca.text
    assert 'data-ca-certificate-modal-form' in ca.text
    assert "Complete certificate details before creating a request." in ca.text
    assert "Issued, CSR-based, and service-owned certificates are read-only." in ca.text
    assert "<th>Exports</th>" not in ca.text
    certificate_table_js = client.get("/static/app.js").text.split("function initializeCaCertificatesTable()", 1)[1].split("async function postKmsAction", 1)[0]
    assert 'label: "Edit request"' in certificate_table_js
    assert 'label: "Copy fingerprint"' in certificate_table_js
    assert 'action: (_event, row) => copyCaCertificateFingerprint(row)' in certificate_table_js
    assert 'label: "Export",' in certificate_table_js
    assert "menu: [" in certificate_table_js
    assert 'label: "Certificate"' in certificate_table_js
    assert 'label: "Certificate chain"' in certificate_table_js
    assert 'label: "Private key"' in certificate_table_js
    assert 'title: "Exports"' not in certificate_table_js
    assert re.search(
        r'title: "Status",\s+field: "status",\s+editable: false,\s+width: 80,',
        certificate_table_js,
    )
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
    assert 'href="/requests"' in ca.text
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
    assert 'href="/dashboard#appliance-apply-review"' in ca.text
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
    assert "/certificate-authority/downloads/root-ca.pem" in ca.text
    assert "/certificate-authority/downloads/ca-bundle.pem" in ca.text


def test_certificate_request_creation_is_atomic_and_issues_submitted_sans(client):
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

    page = client.get("/ca")
    assert page.status_code == 200
    assert "Atlaso Certificate Authority" in page.text
    assert "Photon appliance" in page.text
    assert 'class="brand" href="/"' in page.text
    assert "Atlaso Internal Root CA" in page.text
    assert "abc123" in page.text
    assert "ca-fingerprint-block" in page.text
    assert 'data-copy-value="abc123"' in page.text
    assert "Copy fingerprint" in page.text
    assert "ca.atlaso.internal" in page.text
    assert "/ca/downloads/root-ca.pem" in page.text
    assert 'href="/requests"' in page.text
    assert page.text.count('href="/requests"') == 1
    assert "public-link-panel" in page.text
    assert "Open request portal" not in page.text
    assert 'href="/ca/login"' in page.text
    assert "Trust Material" not in page.text
    assert "Appliance Information" not in page.text
    assert "https://github.com/mdaneri/Atlaso" in page.text
    assert 'href="https://192.168.167.10/"' in page.text
    assert ">Management<" in page.text
    assert 'href="https://192.168.167.10/api/docs"' in page.text
    assert ">Swagger<" in page.text
    assert 'href="https://www.python.org/"' in page.text
    assert "Python " in page.text
    assert "/certificate-authority" not in page.text
    assert "/appliance-apply" not in page.text

    login_page = client.get("/ca/login")
    assert login_page.status_code == 200
    assert "Sign in to user portal" in login_page.text
    assert "Use your Atlaso user account to continue." in login_page.text
    assert 'action="/ca/login"' in login_page.text
    assert 'name="next" value="/ca"' in login_page.text
    assert 'data-history-back' in login_page.text
    assert ">Cancel<" in login_page.text
    assert 'class="public-portal-shell"' in login_page.text
    assert "https://github.com/mdaneri/Atlaso" in login_page.text
    assert 'href="https://192.168.167.10/api/docs"' in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    login_response = client.post(
        "/ca/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf, "next": "/ca"},
        follow_redirects=False,
    )
    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/ca"

    signed_in_page = client.get("/ca")
    assert signed_in_page.status_code == 200
    assert "Sign out" in signed_in_page.text
    assert 'name="next" value="/ca"' in signed_in_page.text
    csrf = signed_in_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    logout_response = client.post("/requests/logout", data={"csrf": csrf, "next": "/ca"}, follow_redirects=False)
    assert logout_response.status_code == 303
    assert logout_response.headers["location"] == "/ca"

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
    assert 'href="/ca/login"' in ca_ip_home.text
    assert ">Login<" in ca_ip_home.text
    assert "https://github.com/mdaneri/Atlaso" in ca_ip_home.text
    assert 'href="https://192.168.167.10/"' in ca_ip_home.text
    assert ">Management<" in ca_ip_home.text
    assert 'href="https://192.168.167.10/api/docs"' in ca_ip_home.text
    assert ">Swagger<" in ca_ip_home.text
    assert 'href="https://www.python.org/"' in ca_ip_home.text
    assert 'href="/requests"' not in ca_ip_home.text
    assert "Request certificate" not in ca_ip_home.text
    assert ca_ip_home.text.index("https://github.com/mdaneri/Atlaso") > ca_ip_home.text.index('href="/ca/login"')
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
    assert management_ip_home.headers["location"] == "/login"

    root = client.get("/ca/downloads/root-ca.pem")
    assert root.status_code == 200
    assert "public-root" in root.text
    assert "PRIVATE KEY" not in root.text


def test_public_services_reject_terminal_listener_without_valid_management_https_certificate(client):
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


def test_public_service_home_is_scoped_to_called_ip(client, tmp_path, monkeypatch):
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
    assert 'href="https://ca.atlaso.internal/ca"' in page.text
    assert 'data-ip-href="https://192.168.87.32/ca"' in page.text
    assert 'href="https://depot.atlaso.internal:8443/PROD/"' in page.text
    assert 'data-ip-href="https://192.168.87.32:8443/PROD/"' in page.text
    assert 'href="http://esxi-pxe.atlaso.internal:8081/pxe/esxi/"' in page.text
    assert 'data-ip-href="http://192.168.87.32:8081/pxe/esxi/"' in page.text
    assert 'href="https://192.168.87.32/terminal"' in page.text
    assert 'data-ip-href="https://192.168.87.32/terminal"' in page.text
    assert "Appliance Information" not in page.text
    assert 'href="/ca/login"' in page.text
    assert ">Login<" in page.text
    assert "https://github.com/mdaneri/Atlaso" in page.text
    assert ">Management<" in page.text
    assert 'href="https://192.168.167.10/api/docs"' in page.text
    assert ">Swagger<" in page.text
    assert ">Open<" not in page.text
    assert 'href="/requests"' not in page.text
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
    assert 'action="/requests/login"' in requests_direct.text

    management_ip_home = client.get("/", headers={"host": "192.168.167.10"}, follow_redirects=False)
    assert management_ip_home.status_code == 303
    assert management_ip_home.headers["location"] == "/login"

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
    assert 'action="/PROD/login"' in depot_login.text
    assert 'name="next" value="/PROD/"' in depot_login.text

    from atlaso.app.adapters.system import AdapterResult

    authentication_calls: list[str] = []

    class DepotAuthenticationAdapter:
        dry_run = False

        def authenticate_local_user(self, username: str, password: str) -> AdapterResult:
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
        data={"username": "vcf-depot", "password": "Depot-user1!", "csrf": depot_csrf, "next": "/PROD/"},
        follow_redirects=False,
    )
    assert depot_signed_in.status_code == 303
    assert depot_signed_in.headers["location"] == "/PROD/"
    assert authentication_calls == ["vcf-depot"]
    assert client.get("/PROD/auth-check", headers={"host": "192.168.87.32"}).status_code == 204
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
    assert 'href="/PROD/COMP/"' in depot_browser.text

    depot_subdir = client.get("/PROD/COMP/", headers={"host": "192.168.87.32"})
    assert depot_subdir.status_code == 200
    assert 'href="/PROD/COMP/manifest.json"' in depot_subdir.text
    assert "../" in depot_subdir.text

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


def test_public_service_home_empty_state_for_non_management_ip(client):
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
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, Role, User, utcnow
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
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

    login_page = client.get("/requests")
    assert login_page.status_code == 200
    assert "Certificate Request Portal" in login_page.text
    assert "Sign in to user portal" in login_page.text
    assert "Use your Atlaso user account to continue." in login_page.text
    assert "Sign in to the appliance" not in login_page.text
    assert 'action="/requests/login"' in login_page.text
    assert 'action="/login"' not in login_page.text
    assert 'name="next" value="/requests"' in login_page.text
    assert 'data-history-back' in login_page.text
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    login_response = client.post(
        "/requests/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf, "next": "/requests"},
        follow_redirects=False,
    )
    assert login_response.status_code == 303
    assert login_response.headers["location"] == "/requests"

    console = client.get("/certificate-authority")
    assert console.status_code == 403

    page = client.get("/ca/requests")
    assert page.status_code == 200
    assert "Certificate Requests" in page.text
    assert "Submit Request" in page.text
    assert "CA Settings" not in page.text
    assert "atlaso-ca.json" not in page.text
    assert "/certificate-authority" not in page.text
    with SessionLocal() as db:
        issued = db.execute(select(CaCertificate).where(CaCertificate.common_name == "issued.atlaso.internal")).scalar_one()
        certificate_id = issued.id
    portal_page = client.get("/requests", headers={"host": "ca.atlaso.internal"})
    assert portal_page.status_code == 200
    assert "Certificate Request Portal" in portal_page.text
    assert 'class="brand" href="/"' in portal_page.text
    assert 'action="/requests"' in portal_page.text
    assert 'action="/requests/logout"' in portal_page.text
    assert 'data-history-back' in portal_page.text
    assert 'name="next" value="/requests"' in portal_page.text
    assert f'action="/requests/certificates/{certificate_id}/revoke"' in portal_page.text
    assert 'class="app-shell"' not in portal_page.text
    assert 'class="sidebar"' not in portal_page.text
    assert "Unprivileged control plane" not in portal_page.text
    assert "/certificate-authority" not in portal_page.text
    csrf = portal_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    submitted = client.post(
        "/requests",
        data={
            "csrf": csrf,
            "common_name": "operator-request.atlaso.internal",
            "subject_alt_names": "operator-request.atlaso.internal",
            "description": "operator request",
        },
        follow_redirects=False,
    )
    assert submitted.status_code == 303
    assert submitted.headers["location"] == "/requests"

    with SessionLocal() as db:
        request_row = db.execute(select(CaCertificate).where(CaCertificate.common_name == "operator-request.atlaso.internal")).scalar_one()
        assert request_row.status == "planned"

    revoked = client.post(
        f"/requests/certificates/{certificate_id}/revoke",
        data={"csrf": csrf, "reason": "rotation"},
        follow_redirects=False,
    )
    assert revoked.status_code == 303
    assert revoked.headers["location"] == "/requests"
    with SessionLocal() as db:
        issued = db.get(CaCertificate, certificate_id)
        assert issued.status == "revoked"
        assert issued.revoked_by == "admin"
        assert issued.revocation_reason == "rotation"


def test_certificate_operator_cannot_render_vcf_helper_dns_inventory(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.CERTIFICATE_OPERATOR.value
        admin.roles_json = roles_to_json([Role.CERTIFICATE_OPERATOR.value])
        db.commit()

    login(client)
    response = client.get("/vcf-helper")
    assert response.status_code == 403
    assert "Missing required scope: read:dns" in response.text


def test_ca_apply_payload_leaves_csr_private_key_empty():
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


def test_kms_page_renders(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ServiceState

    login(client)
    with SessionLocal() as db:
        service = db.execute(select(ServiceState).where(ServiceState.service == "kms")).scalar_one()
        service.enabled = True
        service.running = True
        service.health = "healthy"
        db.commit()

    kms = client.get("/kms")
    assert kms.status_code == 200
    assert "KMS / KMIP" in kms.text
    assert "PyKMIP" in kms.text
    assert "lab KMIP server" in kms.text
    assert "kms-keys-table" in kms.text
    assert "kms-clients-table" in kms.text
    assert "vcf-management" in kms.text
    assert "vcf-sddc-manager-aes" in kms.text
    assert "kms.atlaso.internal" in kms.text
    assert "Listen interfaces" in kms.text
    assert "Listen addresses" in kms.text
    assert "service-bind-editor" in kms.text
    assert "service-bind-editor stacked-service-bind-editor" in kms.text
    assert '<select name="backend"' not in kms.text
    assert 'type="hidden" name="backend" value="pykmip"' in kms.text
    assert kms.text.index('name="hostname"') < kms.text.index('data-tag-name="listen_interfaces"')
    assert kms.text.index('data-tag-name="listen_interfaces"') < kms.text.index('data-derived-listen-addresses')
    assert kms.text.index('data-derived-listen-addresses') < kms.text.index('name="port"')
    assert 'name="listen_interfaces_present"' in kms.text
    assert 'data-tag-name="listen_interfaces"' in kms.text
    assert 'data-tag-name="listen_addresses"' not in kms.text
    assert "data-tag-single" not in kms.text
    assert "192.168.50.1" in kms.text
    assert "eth2 - access / access / 192.168.50.1" in kms.text
    assert 'data-autosave-status-id="kms-settings-autosave-status"' in kms.text
    assert "Changes save automatically." in kms.text
    assert 'href="/dashboard#appliance-apply-review"' in kms.text
    assert "Review appliance changes" in kms.text
    assert "pykmip.conf" in kms.text
    assert "/var/lib/atlaso/kms/pykmip.db" in kms.text
    assert "<span>Database path</span>" not in kms.text
    assert "<span>Config path</span>" not in kms.text
    assert "<span>Client CA path</span>" in kms.text
    assert "fixed-value-field" in kms.text
    assert 'name="server_certificate"' not in kms.text
    assert 'name="ca_certificate_path"' not in kms.text
    assert 'name="database_path"' not in kms.text
    assert 'name="config_path"' not in kms.text
    assert "data-confirm-modal" in kms.text

    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "initializeKmsKeysTable" in app_js.text
    assert "initializeKmsClientsTable" in app_js.text
    assert "initializeKmsSettings" in app_js.text
    assert "+ Add key here" in app_js.text
    assert "+ Add client here" in app_js.text
    assert "deleteKmsKeyFromMenu" in app_js.text
    assert "deleteKmsClientFromMenu" in app_js.text
    assert '<span class="status-pill good">live</span>' in kms.text
    assert "preview-modal" in kms.text
    assert "data-preview-modal-code" in kms.text
    assert "initializeTerminalNoteActions" in app_js.text


def test_kms_settings_autosave_returns_json(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord

    login(client)
    page = client.get("/kms")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/kms/settings",
        data={
            "enabled": "on",
            "backend": "pykmip",
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
    refreshed = client.get("/kms")
    assert "enabled" in refreshed.text
    assert "/tmp/rogue-kms.db" not in refreshed.text
    assert "/tmp/rogue-kms.conf" not in refreshed.text
    assert "/tmp/rogue-client-ca.crt" not in refreshed.text
    assert "/etc/atlaso/ca/root.crt" in refreshed.text
    assert "/var/lib/atlaso/kms/pykmip.db" in refreshed.text
    assert "/etc/atlaso/kms/pykmip.conf" in refreshed.text
    assert "10.0.0.99" not in refreshed.text

    with SessionLocal() as db:
        record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms.atlaso.internal", DnsRecord.record_type == "CNAME")).scalar_one()
        assert record.address == "kms-192-168-50-1.atlaso.internal"
        interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms-192-168-50-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert interface_record.address == "192.168.50.1"
        assert "KMS/KMIP endpoint" in (interface_record.description or "")


def test_kms_settings_accept_multiple_listen_targets(client):
    login(client)
    page = client.get("/kms")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/kms/settings",
        data={
            "enabled": "on",
            "backend": "pykmip",
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
    assert "# Atlaso KMS listen interfaces: eth2" in payload["config_preview"]
    assert "# Atlaso KMS listen addresses: 192.168.50.1" in payload["config_preview"]


def test_kms_enable_autocreates_ca_managed_certificate_rows(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaSettings

    login(client)
    with SessionLocal() as db:
        ca_settings = db.execute(select(CaSettings)).scalar_one()
        ca_settings.enabled = True
        db.commit()

    page = client.get("/kms")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/kms/settings",
        data={
            "enabled": "on",
            "backend": "pykmip",
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
    assert response.json()["validation_errors"] == []

    with SessionLocal() as db:
        server_cert = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "kms:server")).scalar_one()
        client_cert = db.execute(select(CaCertificate).where(CaCertificate.managed_owner == "kms:client:vcf-management")).scalar_one()
        assert server_cert.status == "issued"
        assert server_cert.ip_addresses == "192.168.50.1"
        assert server_cert.cert_path == "/etc/atlaso/kms/certs/kms.atlaso.internal.crt"
        assert client_cert.status == "issued"


def test_kms_apply_task_captures_current_desired_state(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job

    login(client)
    page = client.get("/kms")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "kms"})

    assert_apply_redirect(response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "/var/lib/atlaso/apply/kms/pykmip.conf" in (job.result or "")
        assert "pykmip" in (job.result or "")
        assert "vcf-sddc-manager-aes" in (job.result or "")


def test_vcf_backups_page_uses_local_user_for_sftp(client):
    login(client)
    page = client.get("/vcf-backups")
    assert page.status_code == 200
    assert "VCF Backup SFTP" in page.text
    assert "Authentication uses one local Atlaso user from Users" in page.text
    assert "SFTP user" in page.text
    assert "vcf-backup" in page.text
    assert "/mnt/atlaso-vcf-backups" in page.text
    assert "/backups" in page.text
    assert 'action="/vcf-backups/settings"' in page.text
    assert 'data-autosave-status-id="vcf-backup-settings-status"' in page.text
    assert 'href="/dashboard#appliance-apply-review"' in page.text
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


def test_vcf_backups_settings_badge_reflects_desired_state(client, monkeypatch):
    from atlaso.app.config import get_settings

    login(client)
    monkeypatch.setenv("ATLASO_DRY_RUN_SYSTEM_ADAPTERS", "false")
    get_settings.cache_clear()

    page = client.get("/vcf-backups")

    assert page.status_code == 200
    settings_panel = page.text.split("<h2>SFTP Settings</h2>", 1)[1].split("</form>", 1)[0]
    assert '<span class="status-pill muted">disabled</span>' in settings_panel
    assert '<span class="status-pill warn">dry-run</span>' not in page.text


def test_vcf_private_registry_page_models_harbor_and_bundle_relocation(client):
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
    assert 'action="/vcf-private-registry/settings"' in page.text
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
    assert legacy.headers["location"] == "/vcf-offline-depot"

    page = client.get("/vcf-offline-depot")
    assert page.status_code == 200
    assert "VCF Offline Depot" in page.text
    assert "HTTPS Repository" not in page.text
    assert "Download profiles" in page.text
    assert "VCFDT tasks" in page.text
    assert 'id="vcf-depot-tasks-table" class="tabulator-shell"' in page.text
    assert 'id="vcf-depot-task-log-modal"' in page.text
    assert 'class="terminal-note vcfdt-task-log-preview"' in page.text
    assert 'data-terminal-note-open="false"' in page.text
    assert "No VCFDT tasks have been executed." in page.text
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
    assert '<label class="file-upload-control compact-file-upload">' in page.text
    assert "Add or update the VCF Download Tool package" in page.text
    assert "no package staged" in page.text
    assert ">Add</strong>" in page.text
    assert "Reset VCFDT package" in page.text
    assert "Also reset saved application-prodv2.properties configuration" in page.text
    assert 'data-vcf-depot-tool-reset-action>Reset</button>' in page.text
    assert 'button danger compact-button hidden' in page.text
    assert "Stage Broadcom credential" in page.text
    assert ">Stage</button>" in page.text
    assert 'data-vcf-depot-credentials-modal-open data-vcf-depot-requires-tool disabled' in page.text
    assert "Choose a credential file or paste credential text." in page.text
    assert "No Broadcom credentials staged." in page.text
    assert 'action="/vcf-offline-depot/credentials"' in page.text
    assert "vcf-depot-credentials-modal" in page.text
    assert 'data-vcf-depot-credentials-modal-open' in page.text
    assert 'name="credential_type"' in page.text
    assert 'name="credential_file"' in page.text
    assert 'name="credential_text"' in page.text
    assert "Edit application-prodv2.properties" in page.text
    assert ">Edit</button>" in page.text
    assert 'data-vcf-depot-properties-modal-open data-vcf-depot-requires-tool disabled' in page.text
    assert 'action="/vcf-offline-depot/application-properties"' in page.text
    assert 'name="application_properties"' in page.text
    assert "Save configuration" in page.text
    assert "lcm.depot.adapter.host=dl.broadcom.com" in page.text
    assert "/vcf-offline-depot/profiles/" in page.text
    assert "Start" in page.text
    assert page.text.index("<th>Name</th>") < page.text.index("<th>Start</th>") < page.text.index("<th>Type</th>")
    assert 'href="/logs"' in page.text
    assert "Refresh software depot ID" in page.text
    assert 'data-vcf-depot-generate-id-modal-open data-vcf-depot-requires-tool disabled' in page.text
    assert 'name="selected_units" value="vcf_offline_depot"' in page.text
    assert "Software depot ID" in page.text
    assert "VCFDT staging" in page.text
    assert "Staged VCFDT inputs" not in page.text
    depot_settings_index = page.text.index("<h2>Depot Settings</h2>")
    vcfdt_staging_index = page.text.index("VCFDT staging")
    assert depot_settings_index < vcfdt_staging_index < page.text.index("VCF Download Tool", vcfdt_staging_index) < page.text.index("Software depot ID")
    assert '<span class="status-pill warn">dry-run</span>' not in page.text
    assert "Activation code" in page.text
    assert "Choose credential file" in page.text
    assert "no file selected" in page.text
    assert "Choose VCFDT archive" not in page.text
    assert "DNS alias follows the first selected service listener." in page.text
    assert "Server certificate" not in page.text
    assert 'name="server_certificate"' not in page.text
    assert "Telemetry choice" not in page.text
    assert "<span>Telemetry</span>" not in page.text
    assert "<span>VMware CEIP</span>" in page.text
    assert 'href="/settings#vmware-product-preferences"' in page.text
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
    assert 'data-vcf-depot-software-depot-copy' in page.text
    assert 'Copy software depot ID' in page.text
    assert 'data-autosave-upload-progress' in page.text
    assert "not generated" not in page.text
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
    assert '<input class="readonly-inline-value software-depot-id-value hidden" type="text" value="" readonly data-vcf-depot-software-depot-id aria-label="Software depot ID">' in page.text
    assert 'action="/vcf-offline-depot/settings"' in page.text
    assert 'data-autosave-status-id="vcf-depot-settings-status"' in page.text
    assert 'data-components=' in page.text
    assert 'data-esx-platforms=' in page.text
    assert "VCF_OBSERVABILITY_DATA_PLATFORM" in page.text
    assert "VSAN_FILE_SERVICES" in page.text
    assert "embeddedEsx-6.7-INT" in page.text
    assert "esxio-9.1-INTL" in page.text
    assert 'href="/dashboard#appliance-apply-review"' in page.text
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "initializeVcfDepotSettings" in app_js.text
    assert "formatNginxListen(listenAddress, port)" in app_js.text
    software_depot_modal_js = app_js.text.split("function initializeVcfDepotSoftwareDepotIdGenerator", 1)[1].split("function ", 1)[0]
    assert 'modal.close("submit")' in software_depot_modal_js
    assert 'submitButton.textContent = "Creating task…"' in software_depot_modal_js
    assert "initializeVcfDepotProfilesTable" in app_js.text
    assert "initializeVcfDepotTasksTable" in app_js.text
    assert "refreshVcfDepotTasksTable" in app_js.text
    assert 'ajaxURL: "/vcf-offline-depot/tasks/status"' in app_js.text
    assert 'paginationMode: "remote"' in app_js.text
    assert "paginationSize: 10" in app_js.text
    tasks_table_js = app_js.text.split("function initializeVcfDepotTasksTable", 1)[1].split("function ", 1)[0]
    assert 'height: "380px"' in tasks_table_js
    assert "paginationSizeSelector" not in tasks_table_js
    assert "await vcfDepotTasksTable.replaceData()" in app_js.text
    assert "reloadData" not in app_js.text
    assert "window.setInterval(refreshVcfDepotTasksTable, 2000)" in app_js.text
    assert "vcfDepotTasksRefreshPending" in app_js.text
    assert "openVcfDepotTaskLog" in app_js.text
    assert 'window.Prism.languages["atlaso-log"]' in app_js.text
    assert "window.Prism.highlightElement(content)" in app_js.text
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
    assert "location = /manifest.webmanifest" in app_js.text
    assert "location = /service-worker.js" in app_js.text
    assert "location = /ca" in app_js.text
    assert "location ^~ /ca/" in app_js.text
    assert "location = /requests" in app_js.text
    assert "location ^~ /requests/" in app_js.text
    assert "updateVcfDepotValidation" in app_js.text
    assert "initializeVcfDepotSoftwareDepotIdGenerator" in app_js.text
    assert "initializeVcfDepotCredentialsPaste" in app_js.text
    assert "updateVcfDepotCredentialStatus" in app_js.text
    assert "previewVcfDepotProfileScript" in app_js.text
    assert 'label: "Preview script"' in app_js.text
    assert "Runtime files refresh during Appliance Apply or profile download." in app_js.text
    assert "initializeVcfDepotPropertiesEditor" in app_js.text
    assert "initializeCopyValueButtons" in app_js.text
    assert "clearSelectedFileInputs" in app_js.text
    assert "Uploaded ${payload.tool_archive_name" in app_js.text
    assert "autosaveErrorFromText" in app_js.text
    assert "copyTextWithTextareaFallback" in app_js.text
    assert "window.isSecureContext" in app_js.text
    assert "softwareDepotId instanceof HTMLInputElement" in app_js.text
    assert "softwareDepotCopy.dataset.copyValue = depotId" in app_js.text
    assert "setVcfDepotToolDependentActions" in app_js.text
    assert "startVcfDepotProfileDownload" in app_js.text
    start_download_js = app_js.text.split("async function startVcfDepotProfileDownload", 1)[1].split("async function ", 1)[0]
    assert "window.location.reload()" not in start_download_js
    assert "setVcfDepotDownloadActive(true, payload.job_id)" in start_download_js
    assert "await vcfDepotTasksTable.setPage(1)" in start_download_js
    assert "await refreshVcfDepotTasksTable()" in start_download_js
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
    assert "setVcfDepotDownloadActive" in app_js.text
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
    assert ".vcf-platform-tooltip" in app_css.text
    assert ".vcf-platform-tip table" in app_css.text
    assert ".vcf-platforms-cell" in app_css.text
    assert ".tabulator-cell.vcf-platforms-cell:hover .vcf-platform-tip" in app_css.text
    assert ".readonly-inline-value" in app_css.text
    assert ".software-depot-id-value" in app_css.text
    assert ".icon-button" in app_css.text
    assert ".code-editor-textarea" in app_css.text
    assert ".code-editor-textarea + .cm-editor" in app_css.text
    assert "#vcf-depot-properties-modal .confirm-modal-panel" in app_css.text
    assert "#vcf-depot-task-log-modal .confirm-modal-panel" in app_css.text
    assert ".vcfdt-task-log-preview code" in app_css.text
    assert ".vcf-offline-depot-workspace > .side-stack .detail-panel" in app_css.text
    assert ".vcfdt-tool-manager" in app_css.text
    assert ".compact-file-upload" in app_css.text
    assert 'software-depot-id-value' in page.text
    assert 'data-codemirror-editor data-codemirror-language="atlaso-hosts" data-vcf-depot-properties-textarea' in page.text

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
    assert payload["tool_version"] == ""
    assert payload["software_depot_id"] == ""
    assert payload["software_depot_id_error"] == ""
    assert payload["download_token_present"] is True
    assert payload["application_properties_present"] is True
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


def test_vcf_offline_depot_upload_rejects_malformed_archive_before_saving(client, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfOfflineDepotSettings

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    login(client)
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
            "tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", b"\x1f\x8b\x08\x00truncated", "application/gzip"),
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 400
    assert "incomplete or invalid" in response.text
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert settings.tool_archive_path == ""
        assert settings.tool_version == ""


def test_vcf_offline_depot_tool_upload_marks_apply_pending_without_profiles(client, tmp_path, monkeypatch):
    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import appliance_apply_status, appliance_apply_units, update_appliance_apply_baselines

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()
        assert appliance_apply_status(db, "vcf_offline_depot")["changed"] is False

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
        status = appliance_apply_status(db, "vcf_offline_depot")
        assert status["changed"] is True
        unit = next(unit for unit in appliance_apply_units(db) if unit["id"] == "vcf_offline_depot")
        assert "# VCFDT tool package status" in unit["config_preview"]
        assert "# Archive: vcf-download-tool-9.1.0.test.tar.gz" in unit["config_preview"]


def test_vcf_offline_depot_generation_timestamp_does_not_reopen_apply_unit(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
    )
    from atlaso.app.ui import appliance_apply_units, set_setting_value, update_appliance_apply_baselines

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


def test_vcf_offline_depot_apply_stages_tool_without_download_profiles(client, tmp_path, monkeypatch):
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


def test_vcf_offline_depot_apply_can_disable_https_without_vcfdt_tool_steps(client, tmp_path):
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
        assert "stage-tool" not in (job.result or "")
        assert "generate-software-depot-id" not in (job.result or "")
        assert "apply-properties" not in (job.result or "")


def test_vcf_offline_depot_tool_reset_can_preserve_or_clear_configuration(client, tmp_path, monkeypatch):
    from pathlib import Path

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
        VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
        VCF_DEPOT_ACTIVATION_NAME_KEY,
        VCF_DEPOT_ACTIVATION_VALUE_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_ERROR_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
        VCF_DEPOT_TOKEN_NAME_KEY,
        VCF_DEPOT_TOKEN_VALUE_KEY,
    )

    monkeypatch.setattr("atlaso.app.ui.find_local_vcf_download_tool_archive", lambda: None)

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    make_vcfdt_archive(archive_path)
    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    upload = client.post(
        "/vcf-offline-depot/settings",
        data={"hostname": "depot.atlaso.internal", "listen_interface": "eth2", "port": "443", "csrf": csrf},
        files={"tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", archive_path.read_bytes(), "application/gzip")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert upload.status_code == 200
    assert upload.json()["tool_archive_name"] == "vcf-download-tool-9.1.0.test.tar.gz"
    credential = client.post(
        "/vcf-offline-depot/credentials",
        data={"credential_type": "download_token", "credential_text": "reset-me", "csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert credential.status_code == 200

    refreshed = client.get("/vcf-offline-depot")
    assert ">Update</strong>" in refreshed.text
    assert 'data-vcf-depot-tool-reset-action>Reset</button>' in refreshed.text
    assert 'button danger compact-button hidden' not in refreshed.text

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
        properties_setting = db.execute(select(Setting).where(Setting.key == VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY)).scalar_one()
        assert "custom.setting=true" in properties_setting.value

    reset_page = client.get("/vcf-offline-depot")
    assert "no package staged" in reset_page.text
    assert "operator saved · saved" in reset_page.text
    assert 'data-vcf-depot-properties-modal-open data-vcf-depot-requires-tool disabled' in reset_page.text

    apply_reset = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "vcf_offline_depot"})
    assert apply_reset.status_code == 200
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "reset-tool" in (job.result or "")

    upload_again = client.post(
        "/vcf-offline-depot/settings",
        data={"hostname": "depot.atlaso.internal", "listen_interface": "eth2", "port": "443", "csrf": csrf},
        files={"tool_archive_file": ("vcf-download-tool-9.1.0.test.tar.gz", archive_path.read_bytes(), "application/gzip")},
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert upload_again.status_code == 200

    reset_with_configuration = client.post(
        "/vcf-offline-depot/tool/reset",
        data={"csrf": csrf, "reset_application_properties": "on"},
        follow_redirects=False,
    )
    assert reset_with_configuration.status_code == 303
    with SessionLocal() as db:
        for key in [
            VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY,
            VCF_DEPOT_APPLICATION_PROPERTIES_SOURCE_KEY,
            VCF_DEPOT_APPLICATION_PROPERTIES_UPDATED_AT_KEY,
        ]:
            assert db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none() is None


def test_vcf_offline_depot_without_tool_clears_stale_credential_state(client, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.services.vcf_offline_depot import VCF_DEPOT_TOKEN_NAME_KEY, VCF_DEPOT_TOKEN_VALUE_KEY

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
    from atlaso.app import ui

    active_log = tmp_path / "active-tool" / "log" / "vdt.log"
    task_logs = tmp_path / "task-logs"
    monkeypatch.setattr(ui, "VCF_DEPOT_VDT_LOG_PATH", active_log)
    monkeypatch.setattr(ui, "VCF_DEPOT_TASK_LOG_DIR", task_logs)
    active_log.parent.mkdir(parents=True)
    active_log.write_text("live output\n", encoding="utf-8")

    archived = ui.archive_vcf_depot_task_log("job_123", "Binaries Download")

    assert archived == task_logs / "job_123-binaries-download.log"
    assert archived.read_text(encoding="utf-8") == "live output\n"
    assert not active_log.exists()


def test_vcf_offline_depot_appliance_requires_staged_and_active_tool(tmp_path, monkeypatch):
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
    from pathlib import PurePosixPath

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
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
    assert "download-token.txt" in staged_page.text
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


def test_vcf_offline_depot_manual_profile_download_starts_job(client, tmp_path):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, Setting, VcfDepotDownloadProfile, VcfOfflineDepotSettings
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
    assert payload["log_path"] == f"/var/lib/atlaso/vcfDownloadTool/task-logs/{payload['job_id']}-vcf-install.log"
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
    assert "Wait for it to finish" in concurrent_response.json()["detail"]

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
        assert f'"log_path": "/var/lib/atlaso/vcfDownloadTool/task-logs/{job.id}-vcf-install.log"' in (job.result or "")
        assert "/var/lib/atlaso/vcfDownloadTool/active-tool/bin/vcf-download-tool" in (job.result or "")
        assert "--depot-download-token-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/download-token.txt" in (job.result or "")
        assert "manual-secret-token" not in (job.result or "")
        assert profile and profile.status == "ready"

    task_log_page = client.get(f"/vcf-offline-depot/tasks/{payload['job_id']}/log")
    assert task_log_page.status_code == 200
    assert "VCFDT task log" in task_log_page.text
    assert "No task log is available." in task_log_page.text
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
    task_row = next(task for task in task_status_payload.json()["tasks"] if task["id"] == payload["job_id"])
    assert task_row["status"] == "pending"
    assert task_row["progress_percent"] == "0"


def test_vcf_offline_depot_startup_recovers_interrupted_download(client):
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile
    from atlaso.app.ui import recover_interrupted_vcf_depot_download_jobs

    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="interrupted", profile_type="binaries", enabled=True, status="ready")
        db.add(profile)
        db.flush()
        db.add(
            Job(
                id="job_interrupted_vcfdt",
                type="vcf-depot-download",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=35,
                result=json.dumps({"profile_id": profile.id, "profile_name": profile.name}),
            )
        )
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
        assert recover_interrupted_vcf_depot_download_jobs(db) == 0


def test_vcf_offline_depot_root_runtime_wrapper_counts_as_installed(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from pathlib import Path

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
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, Setting, VcfDepotDownloadProfile, VcfOfflineDepotSettings
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
    assert "activation-code.txt" in page.text
    assert "token not uploaded" not in page.text
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
        assert "--depot-download-activation-code-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/activation-code.txt" in (job.result or "")
        assert "--depot-download-token-file=/var/lib/atlaso/vcfDownloadTool/active-tool/secrets/download-token.txt" not in (job.result or "")
        assert "manual-secret-activation-code" not in (job.result or "")


def test_vcf_offline_depot_prepare_runtime_stages_saved_application_properties(client, tmp_path, monkeypatch):
    import io
    import tarfile
    from pathlib import PurePosixPath

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import VCF_DEPOT_APPLICATION_PROPERTIES_CONTENT_KEY, VCF_DEPOT_APPLICATION_PROPERTIES_NAME
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


def test_vcf_offline_depot_generates_software_depot_id(client, tmp_path, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting, VcfOfflineDepotSettings
    from atlaso.app.services.vcf_offline_depot import (
        VCF_DEPOT_SOFTWARE_DEPOT_ID_GENERATED_AT_KEY,
        VCF_DEPOT_SOFTWARE_DEPOT_ID_KEY,
        VCF_DEPOT_TOOL_VERSION_SOURCE_KEY,
    )
    from atlaso.app.ui import persist_vcf_depot_metadata_from_apply

    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive_path.write_bytes(b"placeholder")
    with SessionLocal() as db:
        settings = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        settings.tool_archive_path = str(archive_path)
        settings.tool_version = "9.1.0"
        db.commit()

    login(client)
    page = client.get("/vcf-offline-depot")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-offline-depot/software-depot-id/generate",
        data={"csrf": csrf},
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 409
    payload = response.json()
    assert payload["status"] == "apply-required"
    assert payload["software_depot_id"] == ""
    assert "Appliance Apply" in payload["software_depot_id_error"]

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


def test_vcf_offline_depot_migrates_legacy_store_path(client):
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
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VlanInterface

    with SessionLocal() as db:
        db.add(
            VlanInterface(
                name="eth1.60",
                parent_interface="eth1",
                vlan_id=60,
                ip_cidr="192.168.60.1/24",
                role="services",
                enabled=True,
            )
        )
        db.commit()

    login(client)
    page = client.get("/vcf-backups")
    assert page.status_code == 200
    assert "eth1 - access / trunk" not in page.text
    assert "eth1.60 - VLAN 60 on eth1 / services / 192.168.60.1" in page.text


def test_vcf_backups_settings_autosave_and_status_api(client):
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


def test_disabled_ldap_apply_keeps_staged_user_password_pending(monkeypatch):
    from types import SimpleNamespace

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.models import LdapSettings, LdapUser
    from atlaso.app.services.ldap import clear_pending_ldap_password, has_pending_ldap_password, stage_ldap_user_password
    from atlaso.app.ui import execute_appliance_apply_unit

    settings = LdapSettings(enabled=False)
    user = LdapUser(id=98765, uid="pending-user", surname="User", display_name="Pending User", enabled=True)
    stage_ldap_user_password(user, "VeryStrong1!Directory", settings)

    class SuccessfulLdapAdapter:
        dry_run = False

        @staticmethod
        def validate_ldap_config(path):
            return AdapterResult(["ldap", "validate", path], False)

        @staticmethod
        def apply_ldap_config(path):
            return AdapterResult(["ldap", "apply", path], False)

    monkeypatch.setattr("atlaso.app.ui.stage_appliance_apply_config", lambda _path, _preview: "disabled-ldap.json")
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
    finally:
        clear_pending_ldap_password(user)


def test_physical_and_vlan_pages_render(client):
    login(client)
    physical = client.get("/physical-interfaces")
    assert physical.status_code == 200
    assert "Physical Interfaces" in physical.text
    assert "Review observed Photon NICs, then edit desired access, trunk, IPv4/IPv6 addressing and management gateways, and admin state" in physical.text
    assert "physical-interfaces-table" in physical.text
    assert "Refresh host inventory" in physical.text
    assert "Observed IPv4" in physical.text
    assert "Observed IPv6" in physical.text
    assert "IPv4 CIDR" in physical.text
    assert "IPv4 Gateway" in physical.text
    assert "Management gateway" in physical.text
    assert "IPv6 CIDR" in physical.text
    assert "IPv6 Gateway" in physical.text
    assert "network-state-icon up" in physical.text
    assert "eth0" in physical.text
    assert "192.168.49.1/24" in physical.text
    assert "192.168.50.1/24" in physical.text
    assert "Link Type" in physical.text
    assert "Review appliance changes" in physical.text
    assert "/var/lib/atlaso/apply/network/atlaso-network.conf" in physical.text

    vlans = client.get("/vlan-interfaces")
    assert vlans.status_code == 200
    assert "VLAN Interfaces" in vlans.text
    assert "For standard access-mode NICs, assign IPv4/IPv6 CIDR on Physical Interfaces instead." in vlans.text
    assert "vlan-interfaces-table" in vlans.text
    app_js = client.get("/static/app.js").text
    assert "+ Add VLAN" in app_js
    vlan_table_js = app_js.split("function initializeVlanInterfacesTable()", 1)[1].split("function initializeDnsRecordsTable()", 1)[0]
    assert vlan_table_js.index('field: "add_vlan"') < vlan_table_js.index('field: "vlan_id"') < vlan_table_js.index('field: "parent_interface"') < vlan_table_js.index('field: "name"')
    assert 'cellClick: (event, cell) => activateNewVlanRow(cell)' in vlan_table_js
    assert 'markNewRecordRow(row, "vlan_id", "add_vlan")' in vlan_table_js
    assert "async function activateNewVlanRow(cell)" in client.get("/static/app.js").text
    assert "data.is_activated" in client.get("/static/app.js").text
    assert "const parentMtus = Object.fromEntries" in vlan_table_js
    assert "newVlanInterfaceRow(defaultParent, defaultMtu)" in vlan_table_js
    assert "autoSaveVlanParent(cell, csrf, parentMtus)" in vlan_table_js
    assert "autoSaveVlanId(cell, csrf)" in vlan_table_js
    assert "function vlanDerivedName(data)" in app_js
    assert 'data-parent-options=\'[{"label": "eth1 - trunk' in vlans.text
    assert "data-parent-options" in vlans.text
    assert "deleteVlanInterfaceFromMenu" in app_js
    assert "refreshNetworkSideStack" in app_js
    assert "highlightConfigPreviews(nextSideStack)" in app_js
    assert "networkStateIcon" in app_js
    assert "operStateFormatter" in app_js
    assert "physicalRoleFormatter" in app_js
    assert 'editable: (cell) => cell.getRow().getData().mode !== "trunk"' in app_js
    assert app_js.count('editable: (cell) => cell.getRow().getData().mode !== "trunk"') >= 3
    assert 'role: "unused", ipv4_method: "static", ip_cidr: "", gateway: "", ipv6_enabled: false, ipv6_cidr: "", ipv6_gateway: ""' in app_js
    assert "data.requires_activation && !data.is_activated" in app_js
    assert "cidrInputEditor" in app_js
    assert "isValidCidr" in app_js
    assert "ipv4GatewayIsOnLink" in app_js
    assert 'title: "IPv4 Gateway"' in app_js
    assert 'editorParams: { family: "ipv4", placeholder: "192.168.50.1/24" }' in app_js
    assert 'editorParams: { family: "ipv6", placeholder: "fd00:50::1/64" }' in app_js
    app_css = client.get("/static/app.css").text
    assert ".network-state-icon.up" in app_css
    assert ".network-state-icon.down" in app_css
    assert ".network-state-icon.missing" in app_css
    assert ".invalid-cidr-input" in app_css
    assert ".vlan-interfaces-table .tabulator-row.new-record-row .new-record-primary-cell" in app_css
    assert "Review appliance changes" in vlans.text
    assert "/var/lib/atlaso/apply/network/atlaso-network.conf" in vlans.text


def test_management_interface_dual_stack_gateways_are_saved_and_drive_main_and_table_100(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    page = client.get("/physical-interfaces")
    rows = json.loads(html.unescape(page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]))
    management = next(row for row in rows if row["role"] == "management")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    saved = client.post(
        f"/physical-interfaces/{management['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "static",
            "ip_cidr": "192.168.49.1/24",
            "gateway": "192.168.49.254",
            "ipv6_enabled": "on",
            "ipv6_cidr": "2001:db8:49::10/64",
            "ipv6_gateway": "fe80::1",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert saved.status_code == 303
    refreshed = client.get("/physical-interfaces")
    assert '"gateway": "192.168.49.254"' in refreshed.text
    assert '"ipv6_gateway": "fe80::1"' in refreshed.text
    assert "gateway=192.168.49.254" in refreshed.text
    assert "ipv6_gateway=fe80::1" in refreshed.text
    assert "Static management gateways install in the main table and management policy table 100." in refreshed.text
    routes_wan = client.get("/routes-wan")
    assert "gateway=192.168.49.254" in routes_wan.text
    assert "ip route replace default via 192.168.49.254 dev eth0\n" in routes_wan.text
    assert "ip route replace default via 192.168.49.254 dev eth0 table 100" in routes_wan.text
    assert "ip -6 route replace default via fe80::1 dev eth0\n" in routes_wan.text
    assert "ip -6 route replace default via fe80::1 dev eth0 table 100" in routes_wan.text
    with SessionLocal() as db:
        row = db.scalar(select(PhysicalInterface).where(PhysicalInterface.id == management["id"]))
        assert row is not None
        assert row.gateway == "192.168.49.254"
        assert row.ipv6_gateway == "fe80::1"

    invalid = client.post(
        f"/physical-interfaces/{management['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "static",
            "ip_cidr": "192.168.49.1/24",
            "gateway": "192.168.50.254",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
    )
    assert invalid.status_code == 422
    assert "must be on-link" in invalid.text


def test_physical_interface_refresh_imports_host_inventory_without_apply_job(client, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route, VlanInterface
    from atlaso.app.services.networking import HostPhysicalInterface

    login(client)

    def fake_discover():
        return [
            HostPhysicalInterface(
                name="ens192",
                mac_address="00:15:5d:aa:bb:cc",
                driver="hv_netvsc",
                speed="10000 Mbps",
                host_ip_cidr="192.168.49.22/24",
                host_mtu=1500,
                host_admin_state="up",
                oper_state="up",
            )
        ]

    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", fake_discover)
    page = client.get("/physical-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/physical-interfaces/refresh", data={"csrf": csrf}, follow_redirects=False)

    assert response.status_code == 303
    refreshed = client.get("/physical-interfaces")
    assert "ens192" in refreshed.text
    assert "192.168.49.22/24" in refreshed.text
    assert "host" in refreshed.text
    assert "02:15:5d:00:10:02" not in refreshed.text
    assert "02:15:5d:00:10:03" not in refreshed.text

    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "ens192")).scalar_one()
        assert interface.inventory_source == "host"
        assert interface.desired_state_source == "seed"
        assert interface.ip_cidr is None
        assert interface.admin_state == "down"
        assert db.execute(select(PhysicalInterface).where(PhysicalInterface.name.in_(["eth0", "eth1", "eth2"]))).scalars().all() == []
        assert db.execute(select(VlanInterface).where(VlanInterface.parent_interface == "eth1")).scalars().all() == []
        assert db.execute(select(Route).where(Route.interface_name == "eth1.20")).scalars().all() == []
        assert db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one_or_none() is None


def test_physical_interface_edit_updates_desired_state(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        NtpSettings,
        DhcpScope,
        DnsRecord,
        DnsSettings,
        KmsSettings,
        VcfBackupSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_DEFAULT_HOSTNAME,
        ESXI_PXE_DNS_RECORD_DESCRIPTION,
        ESXI_PXE_HTTP_PORT,
        ESXI_TFTP_ROOT,
        esxi_pxe_boot_settings,
        save_esxi_pxe_boot_settings,
    )

    login(client)
    with SessionLocal() as db:
        for model in (
            DnsSettings,
            NtpSettings,
            CaSettings,
            KmsSettings,
            VcfBackupSettings,
            VcfOfflineDepotSettings,
            VcfPrivateRegistrySettings,
        ):
            settings = db.execute(select(model)).scalar_one()
            settings.enabled = True
            settings.listen_interface = "eth2"
            settings.listen_address = "192.168.50.1"
            db.add(settings)
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.interface_name = "eth2"
        scope.site_address = "192.168.50.1"
        scope.prefix_length = 24
        scope.range_expression = "192.168.50.100-200"
        scope.dns_server = "192.168.50.1"
        scope.ntp_server = "192.168.50.1"
        db.add(scope)
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname=ESXI_PXE_DEFAULT_HOSTNAME,
            listen_interface="eth2",
            listen_address="192.168.50.1",
            dhcp_scope_ids=[scope.id],
            tftp_root=ESXI_TFTP_ROOT.as_posix(),
            http_port=ESXI_PXE_HTTP_PORT,
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="http://192.168.50.1:8080/pxe/esxi/mboot.efi",
        )
        db.add(
            DnsRecord(
                hostname=ESXI_PXE_DEFAULT_HOSTNAME,
                record_type="A",
                address="192.168.50.1",
                description=ESXI_PXE_DNS_RECORD_DESCRIPTION,
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": "route",
            "mode": "access",
            "ip_cidr": "192.168.70.1/24",
            "mtu": "1400",
            "admin_state": "down",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/physical-interfaces")
    assert '"role": "route"' in refreshed.text
    assert '"mode": "access"' in refreshed.text
    assert '"ip_cidr": "192.168.70.1/24"' in refreshed.text
    assert '"mtu": 1400' in refreshed.text
    assert '"admin_state": "down"' in refreshed.text
    assert '"desired_state_source": "user"' in refreshed.text

    with SessionLocal() as db:
        for model in (
            DnsSettings,
            NtpSettings,
            CaSettings,
            KmsSettings,
            VcfBackupSettings,
            VcfOfflineDepotSettings,
            VcfPrivateRegistrySettings,
        ):
            settings = db.execute(select(model)).scalar_one()
            assert settings.listen_interface == "eth2"
            assert settings.listen_address == "192.168.70.1"
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        assert scope.interface_name == "eth2"
        assert scope.site_address == "192.168.70.1"
        assert scope.prefix_length == 24
        assert scope.range_expression == "192.168.70.100-192.168.70.200"
        assert scope.dns_server == "192.168.70.1"
        assert scope.ntp_server == "192.168.70.1"
        kms_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms.atlaso.internal", DnsRecord.record_type == "CNAME")).scalar_one()
        assert kms_record.address == "kms-192-168-70-1.atlaso.internal"
        kms_interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "kms-192-168-70-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert kms_interface_record.address == "192.168.70.1"
        boot = esxi_pxe_boot_settings(db)
        assert boot["listen_interface"] == "eth2"
        assert boot["listen_address"] == "192.168.70.1"
        assert boot["effective_native_uefi_http_url"] == "http://192.168.70.1:8080/pxe/esxi/mboot.efi"
        pxe_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == ESXI_PXE_DEFAULT_HOSTNAME, DnsRecord.record_type == "CNAME")).scalar_one()
        assert pxe_record.address == "esxi-pxe-192-168-70-1.atlaso.internal"
        pxe_interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "esxi-pxe-192-168-70-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert pxe_interface_record.address == "192.168.70.1"


def test_physical_interface_edit_repairs_stale_scope_after_host_inventory_refresh(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NtpSettings, DhcpScope, DnsRecord, DnsSettings, Setting
    from atlaso.app.services.esxi_pxe import ESXI_PXE_DEFAULT_HOSTNAME, ESXI_PXE_DNS_RECORD_DESCRIPTION, ESXI_PXE_HTTP_PORT, ESXI_PXE_LISTEN_ADDRESS_KEY, ESXI_TFTP_ROOT, save_esxi_pxe_boot_settings

    login(client)
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dns_settings.listen_interface = "eth2"
        dns_settings.listen_address = "192.168.1.1"
        ntp_settings = db.execute(select(NtpSettings)).scalar_one()
        ntp_settings.enabled = True
        ntp_settings.listen_interface = "eth2"
        ntp_settings.listen_address = "192.168.1.1"
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.interface_name = "eth2"
        scope.site_address = "192.168.1.1"
        scope.prefix_length = 24
        scope.range_expression = "192.168.1.100-120"
        scope.dns_server = "192.168.1.1"
        scope.ntp_server = "192.168.1.1"
        save_esxi_pxe_boot_settings(
            db,
            enabled=True,
            hostname=ESXI_PXE_DEFAULT_HOSTNAME,
            listen_interface="eth2",
            listen_address="192.168.1.1",
            dhcp_scope_ids=[scope.id],
            tftp_root=ESXI_TFTP_ROOT.as_posix(),
            http_port=ESXI_PXE_HTTP_PORT,
            bios_bootfile="undionly.kpxe",
            uefi_bootfile="snponly.efi",
            native_uefi_http_enabled=True,
            native_uefi_http_url="",
        )
        db.add(
            DnsRecord(
                hostname=ESXI_PXE_DEFAULT_HOSTNAME,
                record_type="A",
                address="192.168.1.1",
                description=ESXI_PXE_DNS_RECORD_DESCRIPTION,
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": "access",
            "mode": "access",
            "ip_cidr": "192.168.50.1/24",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        assert scope.site_address == "192.168.50.1"
        assert scope.range_expression == "192.168.50.100-192.168.50.120"
        assert scope.dns_server == "192.168.50.1"
        assert scope.ntp_server == "192.168.50.1"
        pxe_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == ESXI_PXE_DEFAULT_HOSTNAME, DnsRecord.record_type == "CNAME")).scalar_one()
        assert pxe_record.address == "esxi-pxe-192-168-50-1.atlaso.internal"
        pxe_interface_record = db.execute(select(DnsRecord).where(DnsRecord.hostname == "esxi-pxe-192-168-50-1.atlaso.internal", DnsRecord.record_type == "A")).scalar_one()
        assert pxe_interface_record.address == "192.168.50.1"
        pxe_listen = db.execute(select(Setting).where(Setting.key == ESXI_PXE_LISTEN_ADDRESS_KEY)).scalar_one()
        assert pxe_listen.value == "192.168.50.1"
        pxe_listen.value = "192.168.1.1"
        db.add(pxe_listen)
        db.commit()

    second_response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={
            "role": "access",
            "mode": "access",
            "ip_cidr": "192.168.50.1/24",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert second_response.status_code == 303
    with SessionLocal() as db:
        pxe_listen = db.execute(select(Setting).where(Setting.key == ESXI_PXE_LISTEN_ADDRESS_KEY)).scalar_one()
        assert pxe_listen.value == "192.168.50.1"


def test_physical_interface_trunk_mode_clears_non_applicable_role(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    page = client.get("/physical-interfaces")
    rows = json.loads(html.unescape(page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]))
    interface_id = next(row["id"] for row in rows if row["name"] == "eth2")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{interface_id}/edit",
        data={"role": "access", "mode": "trunk", "ipv4_method": "dhcp", "ip_cidr": "192.168.50.1/24", "ipv6_cidr": "fd00:50::1/64", "mtu": "1500", "admin_state": "up", "csrf": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.id == interface_id)).scalar_one()
        assert interface.mode == "trunk"
        assert interface.role == "unused"
        assert interface.ipv4_method == "static"
        assert interface.ip_cidr is None
        assert interface.ipv6_cidr is None


def test_physical_interface_link_type_locked_when_vlans_exist(client):
    import html
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        eth1 = db.query(PhysicalInterface).filter_by(name="eth1").one()
        eth1.mode = "trunk"
        db.add(
            VlanInterface(
                name="eth1.50",
                parent_interface="eth1",
                vlan_id=50,
                ip_cidr="192.168.50.1/24",
                mtu=1500,
                role="access",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    eth1_row = next(row for row in rows if row["name"] == "eth1")
    assert eth1_row["vlan_count"] >= 1
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{eth1_row['id']}/edit",
        data={
            "role": "access",
            "mode": "access",
            "ip_cidr": "",
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
    )
    assert response.status_code == 409
    assert "Move or delete those VLANs before changing the link type" in response.text


def test_physical_interface_grid_menu_actions_are_available(client):
    login(client)
    page = client.get("/physical-interfaces")
    assert page.status_code == 200

    js = client.get("/static/app.js?v=public-address-mode-20260708-1")
    assert js.status_code == 200
    assert "Disable interface" in js.text
    assert "Enable interface" in js.text
    assert "Convert DHCP lease to static" in js.text
    assert "requestConfirmation" in js.text
    assert "The management interface must stay enabled." in js.text
    assert 'data.role === "management" && data.admin_up' in js.text
    assert "atlaso_public_address_mode" in js.text
    assert "initializePublicAddressModeToggle" in js.text


def test_management_dhcp_interface_can_be_saved_as_static_from_observed_addresses(client, monkeypatch):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, DnsSettings, PhysicalInterface

    login(client)
    monkeypatch.setattr("atlaso.app.services.appliance_settings.observed_management_dhcp_dns_servers", lambda interface_name: ["127.0.0.1", "::1", "192.168.167.2", "192.168.167.3"])
    with SessionLocal() as db:
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        appliance_settings.external_dns_servers = ""
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = False
        dns_settings.upstream_servers = ""
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.mode = "access"
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.host_ip_cidr = "192.168.167.219/24"
        eth0.host_ipv6_cidr = "fd00:167::219/64"
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    eth0_row = next(row for row in rows if row["name"] == "eth0")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{eth0_row['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "static",
            "ip_cidr": eth0_row["host_ip_cidr"],
            "ipv6_enabled": "on",
            "ipv6_cidr": eth0_row["host_ipv6_cidr"],
            "mtu": "1500",
            "admin_state": "up",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    with SessionLocal() as db:
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        assert eth0.ipv4_method == "static"
        assert eth0.ip_cidr == "192.168.167.219/24"
        assert eth0.ipv6_cidr == "fd00:167::219/64"
        appliance_settings = db.execute(select(ApplianceSettings)).scalar_one()
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        assert appliance_settings.external_dns_servers == "192.168.167.2\n192.168.167.3"
        assert dns_settings.upstream_servers == "192.168.167.2\n192.168.167.3"


def test_management_physical_interface_cannot_be_disabled(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        eth0.role = "management"
        eth0.mode = "access"
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.admin_state = "up"
        db.commit()

    page = client.get("/physical-interfaces")
    payload = page.text.split("data-interfaces='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    eth0_row = next(row for row in rows if row["name"] == "eth0")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        f"/physical-interfaces/{eth0_row['id']}/edit",
        data={
            "role": "management",
            "mode": "access",
            "ipv4_method": "dhcp",
            "ip_cidr": "",
            "ipv6_cidr": "",
            "mtu": "1500",
            "admin_state": "down",
            "csrf": csrf,
        },
    )

    assert response.status_code == 422
    assert "management interface must stay enabled" in response.text
    with SessionLocal() as db:
        eth0 = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        assert eth0.role == "management"
        assert eth0.admin_state == "up"


def test_vlan_interface_create_edit_delete_and_apply(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "50",
            "ip_cidr": "192.168.50.1/24",
            "mtu": "1500",
            "role": "services",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    page = client.get("/vlan-interfaces")
    assert "eth1.50" in page.text
    assert "192.168.50.1/24" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network"})
    assert_apply_redirect(apply_response)

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "atlaso-helper" in (job.result or "")
        assert "eth1.50" in (job.result or "")

    page = client.get("/vlan-interfaces")
    import html
    import json

    payload = page.text.split("data-vlans='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    vlan_id = next(row["id"] for row in rows if row["name"] == "eth1.50")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    deleted = client.post(f"/vlan-interfaces/{vlan_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert deleted.status_code == 303
    assert "eth1.50" not in client.get("/vlan-interfaces").text


def test_vlan_page_prefers_real_trunk_parent_when_inventory_has_eth2(client):
    import html
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        db.query(PhysicalInterface).delete()
        db.add_all(
            [
                PhysicalInterface(
                    name="eth0",
                    mac_address="00:15:5d:01:1d:1a",
                    ip_cidr="192.168.49.1/24",
                    role="management",
                    mode="access",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth1",
                    mac_address="00:15:5d:01:1d:1b",
                    ip_cidr="192.168.50.1/24",
                    role="access",
                    mode="access",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth2",
                    mac_address="00:15:5d:01:1d:1c",
                    mtu=9000,
                    role="access",
                    mode="trunk",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth3",
                    mac_address="00:15:5d:01:1d:1d",
                    role="route",
                    mode="access",
                    inventory_source="host",
                    desired_state_source="user",
                ),
            ]
        )
        db.commit()

    page = client.get("/vlan-interfaces")
    payload = page.text.split("data-parent-options='", 1)[1].split("'", 1)[0]
    options = json.loads(html.unescape(payload))

    assert options == [{"name": "eth2", "label": "eth2 - trunk - host NIC - 00:15:5d:01:1d:1c", "mtu": 9000}]
    assert "eth2 - trunk - host NIC" in page.text
    assert "eth2 - access - trunk" not in page.text


def test_vlan_page_disables_missing_parent_vlan(client):
    import html
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, VlanInterface

    login(client)
    with SessionLocal() as db:
        db.query(VlanInterface).delete()
        db.query(PhysicalInterface).delete()
        db.add_all(
            [
                PhysicalInterface(
                    name="missing_155d011d1d",
                    mac_address="00:15:5d:01:1d:1d",
                    role="unused",
                    mode="unused",
                    admin_state="down",
                    oper_state="missing",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                PhysicalInterface(
                    name="eth2",
                    mac_address="00:15:5d:01:1d:1c",
                    role="access",
                    mode="trunk",
                    inventory_source="host",
                    desired_state_source="user",
                ),
                VlanInterface(
                    parent_interface="missing_155d011d1d",
                    name="missing_155d011d1d.11",
                    vlan_id=11,
                    ip_cidr="192.168.11.1/24",
                    enabled=True,
                ),
            ]
        )
        db.commit()

    page = client.get("/vlan-interfaces")
    assert page.status_code == 200
    vlan_payload = page.text.split("data-vlans='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(vlan_payload))
    row = next(item for item in rows if item["name"] == "missing_155d011d1d.11")
    assert row["parent_missing"] is True
    assert row["enabled"] is False

    parent_payload = page.text.split("data-parent-options='", 1)[1].split("'", 1)[0]
    options = json.loads(html.unescape(parent_payload))
    assert options == [{"name": "eth2", "label": "eth2 - trunk - host NIC - 00:15:5d:01:1d:1c", "mtu": 1500}]

    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        f"/vlan-interfaces/{row['id']}/edit",
        data={
            "parent_interface": "missing_155d011d1d",
            "vlan_id": "11",
            "ip_cidr": "192.168.11.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert response.status_code == 409
    assert "missing from host inventory" in response.text


def test_vlan_interface_rejects_non_trunk_parent(client):
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth2",
            "vlan_id": "60",
            "ip_cidr": "192.168.60.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert response.status_code == 409
    assert "is not a trunk interface" in response.text


def test_vlan_interface_requires_vlan_id_and_ip_cidr(client):
    login(client)
    page = client.get("/vlan-interfaces")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    missing_ip = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "70",
            "ip_cidr": "",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert missing_ip.status_code == 409
    assert "VLAN IPv4 CIDR, IPv6 CIDR, or both are required." in missing_ip.text

    missing_vlan = client.post(
        "/vlan-interfaces",
        data={
            "parent_interface": "eth1",
            "vlan_id": "",
            "ip_cidr": "192.168.70.1/24",
            "mtu": "1500",
            "role": "access",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert missing_vlan.status_code == 409
    assert "VLAN ID is required" in missing_vlan.text


def test_firewall_page_create_rule_and_apply_task(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/firewall")
    assert page.status_code == 200
    assert "Firewall Rules" in page.text
    assert "firewall-rules-table" in page.text
    assert "Review appliance changes" in page.text
    assert "nftables" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    rejected = client.post(
        "/firewall/rules",
        data={
            "name": "raw-source-rejected",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "192.168.50.0/24",
            "destination": "any",
            "destination_port": "443",
            "interface_name": "eth2",
            "priority": "29",
            "enabled": "on",
            "description": "raw source should not save",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert rejected.status_code == 422
    assert "Source must use Any or a firewall group." in rejected.text

    group_response = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "create",
            "group_name": "VCenter clients",
            "group_entries": "192.168.50.0/24",
        },
    )
    assert group_response.status_code == 200

    created = client.post(
        "/firewall/rules",
        data={
            "name": "allow-vcenter",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "group:custom:vcenter-clients",
            "destination": "any",
            "destination_port": "443",
            "interface_name": "eth2",
            "priority": "30",
            "enabled": "on",
            "description": "VCF management access",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert "allow-vcenter" in client.get("/firewall").text

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "firewall"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "atlaso-helper firewall apply" in (job.result or "")
        assert "allow-vcenter" in (job.result or "")


def test_firewall_settings_autosave_updates_desired_state_preview(client):
    login(client)
    page = client.get("/firewall")
    assert page.status_code == 200
    assert "data-firewall-enabled-status" in page.text
    assert "atlaso-brand-20260725-1" in page.text
    codemirror = client.get("/static/vendor/codemirror/atlaso-codemirror.min.js")
    assert codemirror.status_code == 200
    assert "AtlasoCodeMirror" in codemirror.text
    assert "initializeSwitchFields" in client.get("/static/app.js").text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    disabled = client.post(
        "/firewall/settings",
        data={
            "csrf": csrf,
            "default_input_policy": "drop",
            "default_forward_policy": "drop",
            "default_output_policy": "accept",
            "allow_established": "on",
            "allow_loopback": "on",
            "allow_icmp": "on",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert disabled.status_code == 200
    disabled_payload = disabled.json()
    assert disabled_payload["enabled"] is False
    assert disabled_payload["valid"] is True
    assert "Atlaso firewall desired state is disabled" in disabled_payload["config_preview"]
    assert "table inet atlaso" not in disabled_payload["config_preview"]

    enabled = client.post(
        "/firewall/settings",
        data={
            "csrf": csrf,
            "enabled": "on",
            "default_input_policy": "drop",
            "default_forward_policy": "drop",
            "default_output_policy": "accept",
            "allow_established": "on",
            "allow_loopback": "on",
            "allow_icmp": "on",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert enabled.status_code == 200
    enabled_payload = enabled.json()
    assert enabled_payload["enabled"] is True
    assert enabled_payload["settings"]["enabled"] is True
    assert "table inet atlaso" in enabled_payload["config_preview"]
    assert 'comment "mgmt-console"' in enabled_payload["config_preview"]
    assert 'tcp ip saddr' not in enabled_payload["config_preview"]
    assert 'tcp dport { 22, 80, 443 } accept comment "mgmt-console"' in enabled_payload["config_preview"]


def test_global_appliance_apply_tracks_baselines_diffs_and_skips(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep, Setting

    login(client)
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "appliance-apply-modal" in page.text
    assert 'class="button primary hidden" type="submit" data-appliance-apply-submit' in page.text
    assert "data-apply-submit-tracker" not in page.text
    direct = client.get("/appliance-apply", follow_redirects=False)
    assert direct.status_code == 303
    assert direct.headers["location"] == "/dashboard#appliance-apply-review"
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
    assert baseline_response.headers["location"].startswith("/tasks?job_id=job_")
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


def test_appliance_apply_connection_warnings_detect_management_address_and_certificate_changes():
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


def test_appliance_apply_review_returns_management_address_connection_warning(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.20/24"
        db.commit()

    review = client.get("/appliance-apply/review")

    assert review.status_code == 200
    network = next(unit for unit in review.json()["units"] if unit["id"] == "network")
    assert len(network["connection_warnings"]) == 1
    assert "from 192.168.49.1/24 to 192.168.49.20/24" in network["connection_warnings"][0]


def test_appliance_apply_json_submission_returns_master_with_live_child_status(client):
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["job_id"].startswith("job_")
    assert payload["status_url"] == f"/tasks/{payload['job_id']}/status"
    assert payload["task"]["type"] == "appliance-apply"
    assert [(step["component_key"], step["status"]) for step in payload["task"]["_children"]] == [("firewall", "pending")]

    status_response = client.get(payload["status_url"])
    assert status_response.status_code == 200
    task = status_response.json()["task"]
    assert task["status"] == "succeeded"
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [("firewall", "succeeded")]


def test_appliance_apply_rejects_submission_while_another_task_is_active(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_active_apply",
                type="appliance-apply",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=25,
                result="{}",
            )
        )
        db.commit()

    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "firewall"})

    assert response.status_code == 423
    assert response.json()["job_id"] == "job_active_apply"
    assert "Changes are locked" in response.json()["detail"]
    with SessionLocal() as db:
        jobs = db.scalars(select(Job).where(Job.type == "appliance-apply")).all()
        assert [job.id for job in jobs] == ["job_active_apply"]


def test_recover_interrupted_appliance_apply_jobs_marks_active_tasks_failed(client):
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

    def execute(unit, *, adapter=None):
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
        return [after if apply_completed else before]

    def execute(unit, *, adapter=None):
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


def test_appliance_apply_parent_cancel_finishes_current_step_and_skips_remaining(client, monkeypatch):
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

    def execute(unit, *, adapter=None):
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


def test_appliance_startup_initializes_factory_apply_baseline(monkeypatch, tmp_path):
    from sqlalchemy import select
    from starlette.testclient import TestClient

    import atlaso.app.database as database
    from atlaso.app.config import get_settings
    from atlaso.app.models import AuditEvent, Setting, User

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

    with TestClient(create_app()) as test_client:
        login(test_client)
        page = test_client.get("/appliance-apply", follow_redirects=False)
        assert page.status_code == 303
        assert page.headers["location"] == "/dashboard#appliance-apply-review"
        review = test_client.get("/appliance-apply/review")
        assert review.status_code == 200
        assert review.json()["units"] == []

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
    from atlaso.app.database import SessionLocal
    from atlaso.app.ui import appliance_apply_units

    login(client)
    with SessionLocal() as db:
        unit_ids = [unit["id"] for unit in appliance_apply_units(db)]

    assert unit_ids.index("firewall") < unit_ids.index("wan")


def test_network_apply_config_includes_removed_vlan_targets_from_baseline():
    from atlaso.app.ui import network_config_with_removed_vlans, network_vlan_entries_from_config, removed_network_vlan_entries

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
                "  role=services",
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
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow
    from atlaso.app.ui import removed_network_vlan_entries, successful_network_apply_vlan_entries

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
            "  role=services",
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
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow
    from atlaso.app.ui import removed_network_vlan_entries, successful_network_apply_vlan_entries

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
            "  role=services",
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
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, DhcpScope, KmsSettings, VcfBackupSettings, VcfOfflineDepotSettings

    def fake_service_status(self, unit: str):
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

    assert '<span class="status-pill good">live</span>' in client.get("/kms").text
    assert '<span class="status-pill good">live</span>' in client.get("/vcf-offline-depot").text
    ca_page = client.get("/certificate-authority").text
    assert '<span class="status-pill muted">disabled</span>' not in ca_page
    assert '<span class="status-pill good">live</span>' in ca_page or '<span class="status-pill warn">needs attention</span>' in ca_page

    token = create_api_token(client, ["read:services"])
    assert client.get("/api/v1/services/ca", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True
    assert client.get("/api/v1/services/repository", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True
    assert client.get("/api/v1/services/vcf-backups", headers={"Authorization": f"Bearer {token}"}).json()["running"] is True


def test_esx_storage_live_status_requires_rpcbind_only_for_nfs3(client, monkeypatch):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxNfsShare, EsxStorageSettings, EsxStorageVolume

    def fake_service_status(self, unit: str):
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
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, DnsSettings, ServiceState

    def fake_service_status(self, unit: str):
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
    import html
    import json

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings

    def fake_service_status(self, unit: str):
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


def test_ca_apply_task_captures_current_desired_state(client):
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
    from pathlib import Path

    from sqlalchemy import select

    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.config import get_settings
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, Job

    staged_path = tmp_path / "atlaso-ca.json"
    captured: dict[str, str] = {}

    def fake_validate_ca_config(self, config_path: str):
        captured["validate_payload"] = Path(config_path).read_text(encoding="utf-8")
        return AdapterResult(command=["atlaso-helper", "ca", "validate", config_path], dry_run=False, stdout="validated")

    def fake_apply_ca_config(self, config_path: str):
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

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "BEGIN PRIVATE KEY" not in (job.result or "")


def test_appliance_apply_status_redacts_undecryptable_ca_private_key(client):
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


def test_dns_settings_accept_multiple_listen_interfaces(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/settings",
        data={
            "enabled": "on",
            "listen_interfaces": ["eth0", "eth2"],
            "upstream_servers": "1.1.1.1\n9.9.9.9",
            "cache_size": "1000",
            "expand_hosts": "on",
            "authoritative": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/dns")
    assert "interface=eth0" not in refreshed.text
    assert "interface=eth2" in refreshed.text
    assert "listen-address=192.168.49.1" not in refreshed.text
    assert "listen-address=192.168.50.1" in refreshed.text
    assert "listen-address=192.168.60.1" not in refreshed.text
    assert "domain=atlaso.internal" in refreshed.text


def test_dns_settings_autosave_returns_json(client):
    login(client)
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
            "conditional_forwarders": "sddc.internal=192.168.10.10,192.168.10.11",
            "cache_size": "500",
            "expand_hosts": "on",
            "authoritative": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "saved"
    assert response.json()["listen_interfaces"] == ["eth2"]
    assert response.json()["valid"] is True
    assert "ESXi PXE boot services require DHCP to be enabled so clients receive boot files." not in response.json()["validation_errors"]
    assert "server=/sddc.internal/192.168.10.10" in response.json()["config_preview"]
    assert "server=/sddc.internal/192.168.10.11" in response.json()["config_preview"]
    refreshed = client.get("/dns")
    assert "server=/sddc.internal/192.168.10.10" in refreshed.text
    assert "server=/sddc.internal/192.168.10.11" in refreshed.text
    assert "sddc.internal=192.168.10.10,192.168.10.11" in refreshed.text


def test_dns_settings_autosave_filters_invalid_listen_interfaces(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/settings",
        data={
            "enabled": "on",
            "listen_interfaces_present": "1",
            "listen_addresses_present": "1",
            "listen_interfaces": ["eth1", "eth2"],
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
    assert response.json()["listen_interfaces"] == ["eth2"]
    assert response.json()["valid"] is True
    assert "ESXi PXE boot services require DHCP to be enabled so clients receive boot files." not in response.json()["validation_errors"]
    assert "interface=eth2" in response.json()["config_preview"]


def test_dns_validation_requires_dhcp_only_when_esxi_pxe_boot_enabled(client):
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


def test_dhcp_settings_autosave_returns_json(client):
    login(client)
    page = client.get("/dhcp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dhcp/settings",
        data={
            "enabled": "on",
            "interface_name": "eth2",
            "site_address": "192.168.50.1",
            "prefix_length": "24",
            "lease_time": "8h",
            "domain_name": "atlaso.internal",
            "dns_server": "192.168.50.1",
            "authoritative": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "saved"


def test_dhcp_settings_autosave_allows_service_toggle_only(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings

    login(client)
    page = client.get("/dhcp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dhcp/settings",
        data={
            "enabled": "on",
            "authoritative": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "saved"

    with SessionLocal() as db:
        settings = db.execute(select(DhcpSettings)).scalar_one()
        assert settings.enabled is True
        assert settings.authoritative is True


def test_dhcp_settings_badge_reflects_desired_state_not_seeded_service_state(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, ServiceState

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(DhcpSettings)).scalar_one()
        settings.enabled = True
        state = db.execute(select(ServiceState).where(ServiceState.service == "dhcp")).scalar_one()
        state.enabled = False
        state.running = False
        state.health = "disabled"
        db.commit()

    page = client.get("/dhcp")
    settings_panel = page.text.split("<h2>DHCP Settings</h2>", 1)[1].split("</form>", 1)[0]

    assert page.status_code == 200
    assert '<span class="status-pill good">enabled</span>' in settings_panel
    assert '<span class="status-pill muted">disabled</span>' not in settings_panel


def test_dhcp_scope_edit_form_updates_ip_zone(client):
    login(client)
    page = client.get("/dhcp")
    import html
    import json

    payload = page.text.split("data-scopes='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    scope_id = next(row["id"] for row in rows if row["name"] == "SiteA")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    updated = client.post(
        f"/dhcp/scopes/{scope_id}/edit",
        data={
            "name": "SiteA-Lab",
            "interface_name": "eth2",
            "site_address": "192.168.50.1",
            "prefix_length": "24",
            "range_expression": "192.168.50.110-210",
            "lease_time": "8h",
            "domain_name": "atlaso.internal",
            "dns_server": "192.168.50.1",
            "ntp_server": "192.168.50.1",
            "description": "edited IP zone",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert updated.status_code == 303

    refreshed = client.get("/dhcp")
    assert "SiteA-Lab" in refreshed.text
    assert "192.168.50.110" in refreshed.text
    assert "edited IP zone" in refreshed.text
    assert '"ntp_server": "192.168.50.1"' in refreshed.text


def test_dhcp_vlan_scope_can_be_created_without_dns_server(client):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope

    login(client)
    page = client.get("/dhcp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/dhcp/scopes",
        data={
            "name": "VLAN20",
            "address_family": "ipv4",
            "interface_name": "eth1.20",
            "site_address": "192.168.20.1",
            "prefix_length": "24",
            "range_expression": "192.168.20.100-192.168.20.200",
            "lease_time": "12h",
            "domain_name": "atlaso.internal",
            "dns_server": "",
            "ntp_server": "",
            "description": "VLAN DHCP zone without a bound DNS listener",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert created.status_code == 303
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "VLAN20")).scalar_one()
        assert scope.interface_name == "eth1.20"
        assert scope.dns_server == ""

    app_js = client.get("/static/app.js").text
    required_block = app_js.split("function hasRequiredDhcpScopeFields", 1)[1].split("async function autoSaveDhcpScope", 1)[0]
    assert "data.address_family" in required_block
    assert "data.prefix_length" in required_block
    assert "data.lease_time" in required_block
    assert "data.domain_name" in required_block
    assert "data.dns_server" not in required_block


def test_dhcp_scope_family_cannot_change_after_create(client):
    import html
    import json

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope

    login(client)
    page = client.get("/dhcp")

    payload = page.text.split("data-scopes='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    scope_id = next(row["id"] for row in rows if row["name"] == "SiteA")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    rejected = client.post(
        f"/dhcp/scopes/{scope_id}/edit",
        data={
            "name": "SiteA",
            "address_family": "ipv6",
            "interface_name": "eth2",
            "site_address": "fd00:50::1",
            "prefix_length": "64",
            "range_expression": "fd00:50::100-fd00:50::200",
            "lease_time": "8h",
            "domain_name": "atlaso.internal",
            "dns_server": "fd00:50::1",
            "ntp_server": "fd00:50::1",
            "description": "try family flip",
            "enabled": "on",
            "csrf": csrf,
        },
    )

    assert rejected.status_code == 409
    assert "DHCP IP zone family cannot be changed after it is created." in rejected.text
    with SessionLocal() as db:
        scope = db.execute(select(DhcpScope).where(DhcpScope.id == scope_id)).scalar_one()
        assert scope.address_family == "ipv4"
        assert scope.range_expression == "192.168.50.100-192.168.50.200"


def test_dhcp_page_tolerates_stale_ipv6_esxi_pxe_scope_selection(client):
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


def test_dhcp_reservation_edit_form_updates_row(client):
    login(client)
    page = client.get("/dhcp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/dhcp/reservations",
        data={
            "hostname": "reserved-client",
            "mac_address": "02:15:5d:00:22:22",
            "ip_address": "192.168.50.122",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    page = client.get("/dhcp")
    import html
    import json

    payload = page.text.split("data-reservations='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    reservation_id = next(row["id"] for row in rows if row["hostname"] == "reserved-client.atlaso.internal")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    updated = client.post(
        f"/dhcp/reservations/{reservation_id}/edit",
        data={
            "hostname": "reserved-client-2.atlaso.internal",
            "mac_address": "02:15:5d:00:22:23",
            "ip_address": "192.168.50.123",
            "description": "edited from grid",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert updated.status_code == 303

    refreshed = client.get("/dhcp")
    assert "reserved-client-2.atlaso.internal" in refreshed.text
    assert "192.168.50.123" in refreshed.text
    assert "edited from grid" in refreshed.text
    dns_page = client.get("/dns")
    assert "reserved-client-2.atlaso.internal" in dns_page.text


def test_dns_zone_create_adds_domain_tab(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/zones",
        data={"domain": "sitea.internal", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/dns")
    assert "sitea.internal" in refreshed.text
    assert 'data-domain="sitea.internal"' in refreshed.text


def test_dns_reverse_zones_are_closed_native_disclosures_with_authority_summary(client):
    login(client)
    page = client.get("/dns")

    assert page.status_code == 200
    assert '<details class="reverse-zone-card">' in page.text
    assert '<details class="reverse-zone-card" open' not in page.text
    assert '<summary class="reverse-zone-summary">' in page.text
    assert 'class="reverse-zone-chevron" aria-hidden="true"' in page.text
    assert "Generated authoritative records" in page.text
    assert "SOA + NS +" in page.text
    assert 'name="authoritative_server"' in page.text
    assert 'name="authoritative_contact"' in page.text
    assert 'name="authoritative_ttl"' in page.text
    assert "Server-managed SOA serial" in page.text


def test_dns_zone_delete_removes_domain_and_scoped_records(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/dns/zones",
        data={"domain": "delete-me.internal", "csrf": csrf},
        follow_redirects=False,
    )
    assert created.status_code == 303

    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    record = client.post(
        "/dns/records",
        data={
            "hostname": "app",
            "domain": "delete-me.internal",
            "record_type": "A",
            "address": "192.168.50.222",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert record.status_code == 303

    page = client.get("/dns")
    assert "delete-me.internal" in page.text
    assert "app.delete-me.internal" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    deleted = client.post(
        "/dns/zones/delete",
        data={"domain": "delete-me.internal", "csrf": csrf},
        follow_redirects=False,
    )
    assert deleted.status_code == 303

    refreshed = client.get("/dns")
    assert "delete-me.internal" not in refreshed.text
    assert "app.delete-me.internal" not in refreshed.text
    assert "domain=atlaso.internal" in refreshed.text


def test_dns_zone_delete_keeps_at_least_one_domain(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/zones/delete",
        data={"domain": "atlaso.internal", "csrf": csrf},
    )

    assert response.status_code == 422
    assert "At least one DNS domain must remain managed." in response.text
    assert "atlaso.internal" in response.text


def test_dns_zone_warns_for_local_domain(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/zones",
        data={"domain": "vcf.local", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/dns")
    assert "Avoid .local for VCF" in refreshed.text
    assert "vcf.internal" in refreshed.text
    assert "VMware Cloud Foundation does not work reliably" in refreshed.text
    assert "RFC 6762" in refreshed.text
    assert "RFC 6761" in refreshed.text
    assert "IANA Special-Use Domain Names registry" in refreshed.text
    assert "ICANN/IANA private-use TLD selection" in refreshed.text


def test_vcf_helper_page_renders_domain_dropdown(client):
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
    assert 'href="/vcf-helper"' in response.text
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
    assert "window.location.assign(`/tasks?job_id=${encodeURIComponent(data.job_id || \"\")}`)" in app_js
    assert "const hasTargetDetails = Boolean(data.target?.appliance)" in app_js
    assert "tlsConfirm.checked = isConfirmedTls" in app_js


def test_vcf_sddc_dhcp_assignment_uses_static_address_outside_scope(client):
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
    assert 'action="/vcf-trust/root-ca"' in response.text
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
    assert "window.location.assign(payload.redirect || `/tasks?job_id=" in app_js
    assert "After TLS confirmation" in app_js
    assert "previouslyConfirmedTls" in app_js
    assert "tlsCheckbox.checked = isConfirmedTls" in app_js
    assert "data-vcf-trust-auth-method" not in app_js

    legacy = client.get("/vcf-trust", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/vcf-helper?vcf_trust=1"


def test_vcf_trust_inspects_target_tls_without_persisting_target(client, monkeypatch):
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfTrustTarget
    import atlaso.app.ui as ui

    login(client)
    csrf = client.get("/vcf-helper").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "tls_sha256_fingerprint", lambda _address, _port: "AA:BB")
    monkeypatch.setattr(ui, "inspect_vcf_trust_target", lambda *_args, **_kwargs: {"role": "VcfInstaller", "version": "9.1.0.0"})
    resolved_credentials = []
    original_resolver = ui._resolve_vcf_helper_credentials

    def track_resolver(*args, **kwargs):
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
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, VcfTrustTarget
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.ui import get_ca_settings_row
    import atlaso.app.ui as ui

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        db.commit()
    monkeypatch.setattr(ui, "tls_sha256_fingerprint", lambda _address, _port: "AA:BB")
    queued = []
    monkeypatch.setattr(ui, "queue_vcf_trust_job", lambda job_id, target_id, credentials, ca: queued.append((job_id, target_id, credentials, ca)))
    resolved_credentials = []
    original_resolver = ui._resolve_vcf_helper_credentials

    def track_resolver(*args, **kwargs):
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


def test_vcf_trust_rejects_mismatched_confirmed_tls_fingerprint(client, monkeypatch):
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.ui import get_ca_settings_row
    import atlaso.app.ui as ui

    login(client)
    with SessionLocal() as db:
        settings = get_ca_settings_row(db)
        settings.enabled = True
        ensure_root_ca_material(settings)
        db.commit()
    monkeypatch.setattr(ui, "tls_sha256_fingerprint", lambda _address, _port: "AA:BB")
    csrf = client.get("/vcf-helper").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/vcf-trust/root-ca",
        data={
            "address": "vcf-installer.example.test",
            "api_username": "administrator@vsphere.local",
            "api_password": "api-secret",
            "confirmed_tls_fingerprint": "CC:DD",
            "csrf": csrf,
        },
        headers={"X-Atlaso-VCF-Trust": "1"},
    )

    assert response.status_code == 409
    assert response.json()["fingerprint"] == "AA:BB"


def test_vcf_trust_job_preserves_cancelled_state_at_progress_checkpoint(client, monkeypatch):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfTrustTarget
    from atlaso.app.services.ca import ensure_root_ca_material
    from atlaso.app.services.vcf_trust import VcfTrustCredentials, root_ca_info
    from atlaso.app.ui import get_ca_settings_row
    import atlaso.app.ui as ui

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
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.services.vcf_depot_target import LocalDepotEndpoint
    import atlaso.app.ui as ui

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


def test_duplicate_dns_record_form_shows_conflict(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    first = client.post(
        "/dns/records",
        data={
            "hostname": "duplicate.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.40",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert first.status_code == 303

    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    same_owner_different_value = client.post(
        "/dns/records",
        data={
            "hostname": "duplicate.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.41",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert same_owner_different_value.status_code == 200

    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    duplicate = client.post(
        "/dns/records",
        data={
            "hostname": "duplicate.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.40",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert duplicate.status_code == 409
    assert "already exists" in duplicate.text


def test_dns_record_form_scopes_relative_host_to_domain(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/records",
        data={
            "hostname": "scoped",
            "domain": "atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.90",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/dns")
    assert "scoped.atlaso.internal" in refreshed.text
    assert "scoped" in refreshed.text


def test_dns_record_form_rejects_wrong_ip_family(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/records",
        data={
            "hostname": "wrong-family",
            "domain": "atlaso.internal",
            "record_type": "AAAA",
            "address": "192.168.50.91",
            "enabled": "on",
            "csrf": csrf,
        },
    )

    assert response.status_code == 422
    assert "must use an IPv6 address" in response.text


def test_dns_record_edit_form_updates_row(client):
    import html
    import json

    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/dns/records",
        data={
            "hostname": "editable.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.60",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303

    page = client.get("/dns")
    payload = page.text.split("data-records='", 1)[1].split("'", 1)[0]
    records = json.loads(html.unescape(payload))
    record_id = next(record["id"] for record in records if record["hostname"] == "editable.atlaso.internal")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    updated = client.post(
        f"/dns/records/{record_id}/edit",
        data={
            "hostname": "editable-renamed.atlaso.internal",
            "record_type": "A",
            "address": "192.168.50.61",
            "description": "edited from UI",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert updated.status_code == 303

    refreshed = client.get("/dns")
    assert "editable-renamed.atlaso.internal" in refreshed.text
    assert "192.168.50.61" in refreshed.text
    assert "edited from UI" in refreshed.text


def test_hosts_file_editor_replaces_dns_records(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    imported = client.post(
        "/dns/records/import",
        data={
            "domain": "atlaso.internal",
            "hosts_text": "192.168.50.80 bulk bulk-alias\n",
            "replace_existing": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert imported.status_code == 303

    refreshed = client.get("/dns")
    assert "Import Hosts" in refreshed.text
    assert "bulk.atlaso.internal" in refreshed.text
    assert "bulk-alias.atlaso.internal" in refreshed.text
    assert "core.atlaso.internal" in refreshed.text


def test_zone_file_editor_import_replaces_domain_records(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    imported = client.post(
        "/dns/zones/import",
        data={
            "domain": "atlaso.internal",
            "zone_text": "$ORIGIN atlaso.internal.\nwww IN CNAME core.atlaso.internal.\nipv6 IN AAAA 2001:db8::10\n",
            "replace_existing": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert imported.status_code == 303

    refreshed = client.get("/dns")
    assert "Import Zone File" in refreshed.text
    assert "www.atlaso.internal" in refreshed.text
    assert "cname=www.atlaso.internal,core.atlaso.internal" in refreshed.text
    assert "ipv6.atlaso.internal" in refreshed.text


def test_zone_file_import_error_preserves_pasted_zone_text(client):
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    zone_text = "$ORIGIN atlaso.internal.\nbadrecord IN BOGUS unsupported\n"

    imported = client.post(
        "/dns/zones/import",
        data={
            "domain": "atlaso.internal",
            "zone_text": zone_text,
            "replace_existing": "on",
            "csrf": csrf,
        },
    )

    assert imported.status_code == 422
    assert "Import Zone File" in imported.text
    assert "Line 2:" in imported.text
    assert "badrecord IN BOGUS unsupported" in imported.text


def test_vcf_sddc_inventory_requires_tls_confirmation_and_redacts_credentials(client, monkeypatch):
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
    monkeypatch.setattr(ui, "tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr(ui, "inspect_ova", lambda *_args, **_kwargs: descriptor)
    monkeypatch.setattr(ui, "vsphere_inventory", lambda *_args, **_kwargs: {"resource_pools": [], "datastores": [], "folders": [], "hosts": [], "networks": []})
    payload = {"csrf": csrf, "address": "vc.example", "port": 443, "username": "admin", "password": "top-secret", "ova_path": descriptor.path}

    confirmation = client.post("/vcf-helper/sddc-manager/inventory", json=payload)
    assert confirmation.status_code == 409
    assert confirmation.json()["fingerprint"] == "AA:BB"

    ready = client.post("/vcf-helper/sddc-manager/inventory", json={**payload, "confirmed_tls_fingerprint": "AA:BB"})
    assert ready.status_code == 200
    assert "top-secret" not in ready.text
    assert ready.json()["ova"]["properties"][0]["password"] is True


def test_vcf_sddc_deploy_job_persists_no_passwords(client, monkeypatch):
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
    monkeypatch.setattr(ui, "tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr(ui, "inspect_ova", lambda *_args, **_kwargs: descriptor)
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
    from atlaso.app import ui

    assert ui._split_vcf_endpoint_address_port("vc.example:8443") == ("vc.example", 8443)
    assert ui._split_vcf_endpoint_address_port("https://vc.example/sdk", None) == ("vc.example", 443)
    assert ui._split_vcf_endpoint_address_port("[2001:db8::10]:9443") == ("2001:db8::10", 9443)


def test_vcf_sddc_deploy_waits_on_ip_before_new_dns_name(client, monkeypatch):
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
    monkeypatch.setattr(ui, "tls_sha256_fingerprint", lambda *_args, **_kwargs: "AA:BB")
    monkeypatch.setattr(ui, "inspect_ova", lambda *_args, **_kwargs: descriptor)
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

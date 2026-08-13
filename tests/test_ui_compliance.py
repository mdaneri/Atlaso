"""Test ui compliance behavior."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "atlaso" / "app" / "templates"
MATRIX = ROOT / "docs" / "project" / "ui-compliance-matrix.md"
ROUTER_PREFIXES = {
    "router": "/ui/management",
    "management_router": "/ui/management",
    "public_router": "/ui/public",
}


def _html_routes(path: Path) -> set[str]:
    """Return html routes.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    routes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in {"get", "api_route"}
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
            ):
                continue
            renders_html = any(
                keyword.arg == "response_class"
                and isinstance(keyword.value, ast.Name)
                and keyword.value.id == "HTMLResponse"
                for keyword in decorator.keywords
            )
            if renders_html:
                route = str(decorator.args[0].value)
                owner = decorator.func.value
                prefix = ROUTER_PREFIXES.get(owner.id, "") if isinstance(owner, ast.Name) else ""
                routes.add(f"{prefix}{route}" or "/")
    return routes


def test_ui_compliance_matrix_covers_every_html_route_and_template():
    """Verify that ui compliance matrix covers every html route and template."""
    matrix = MATRIX.read_text(encoding="utf-8")
    routes = _html_routes(ROOT / "atlaso" / "app" / "ui.py")
    routes.update(_html_routes(ROOT / "atlaso" / "app" / "web_terminal.py"))
    assert len(routes) >= 45
    for route in sorted(routes):
        assert f"`{route}`" in matrix or f"\n{route}\n" in matrix, route

    for template in TEMPLATES.rglob("*.html"):
        relative = template.relative_to(TEMPLATES).as_posix()
        assert f"`{relative}`" in matrix, relative

    route_rows = [line for line in matrix.splitlines() if line.startswith("| `/")]
    assert route_rows
    assert all("Pass" in line for line in route_rows)


def test_ui_compliance_matrix_covers_every_stable_dialog():
    """Verify that ui compliance matrix covers every stable dialog."""
    matrix = MATRIX.read_text(encoding="utf-8")
    dialog_ids: set[str] = set()
    resource_wizard_ids: set[str] = set()
    for template in TEMPLATES.rglob("*.html"):
        source = template.read_text(encoding="utf-8")
        dialog_ids.update(re.findall(r'<dialog\b[^>]*\bid="(?!\{\{)([^"]+)"', source))
        resource_wizard_ids.update(
            re.findall(r'{%\s+call\s+resource_wizard\(\s*"([^"]+)"', source)
        )
    assert len(dialog_ids) >= 39
    assert len(resource_wizard_ids) >= 20
    for dialog_id in sorted(dialog_ids | resource_wizard_ids):
        assert f"`{dialog_id}`" in matrix, dialog_id


def test_ntp_ui_compliance_matrix_matches_capability_gated_nts_contract():
    """Verify that the NTP matrix row preserves the conditional NTS safety contract."""
    matrix = MATRIX.read_text(encoding="utf-8")
    ntp_row = next(
        line
        for line in matrix.splitlines()
        if line.startswith("| `/ui/management/ntp` ")
    )

    assert "NTS remains disabled" not in ntp_row
    assert "capability-gated NTS client/server controls" in ntp_row
    assert re.search(r"unsupported .*disables controls", ntp_row)
    assert re.search(r"unknown .*preserves desired state .*blocks unsafe apply", ntp_row)
    assert "CA-before-NTP" in ntp_row
    assert "Firewall-owned TCP/4460" in ntp_row
    assert "global `ntpd` apply only" in ntp_row


def test_every_shared_wizard_dialog_has_an_accessible_description():
    """Verify that every shared wizard dialog has an accessible description."""
    for template in TEMPLATES.rglob("*.html"):
        source = template.read_text(encoding="utf-8")
        for match in re.finditer(r"<dialog\b(?P<attributes>[^>]*)>", source):
            attributes = match.group("attributes")
            if "wizard" not in attributes:
                continue
            described_by = re.search(r'aria-describedby="([^"]+)"', attributes)
            assert described_by is not None, f"{template}:{source.count(chr(10), 0, match.start()) + 1}"
            description_id = described_by.group(1)
            if "{{" not in description_id:
                assert f'id="{description_id}"' in source, f"{template}:{description_id}"


def test_ui_compliance_remediation_keeps_explicit_actions_and_focus_return():
    """Verify that ui compliance remediation keeps explicit actions and focus return."""
    template_source = "\n".join(
        template.read_text(encoding="utf-8") for template in TEMPLATES.rglob("*.html")
    )
    assert not re.search(r">\s*(?:Save|Apply|Add)\s*<", template_source)

    app_js = (ROOT / "atlaso" / "app" / "static" / "app.js").read_text(encoding="utf-8")
    assert "const activeLauncher = document.activeElement instanceof HTMLElement ? document.activeElement : null;" in app_js
    assert 'activeLauncher?.closest("details")?.querySelector("summary")' in app_js
    assert "enclosingMenuLauncher instanceof HTMLElement ? enclosingMenuLauncher : activeLauncher" in app_js
    assert "requestAnimationFrame(() => launcher.focus({ preventScroll: true }));" in app_js
    assert 'const accountTrigger = menu.querySelector(".account-menu-trigger");' in app_js
    assert "accountTrigger.focus({ preventScroll: true });" in app_js
    assert not re.search(r"\b(?:window\.)?(?:confirm|prompt|alert)\s*\(", app_js)
    assert 'toast.setAttribute("role", error ? "alert" : "status");' in app_js
    assert 'dismiss.className = "grid-status-toast-dismiss";' in app_js
    assert 'dismiss.textContent = "Dismiss";' in app_js
    assert "if (error) {\n    return;" in app_js
    app_css = (ROOT / "atlaso" / "app" / "static" / "app.css").read_text(encoding="utf-8")
    assert ".grid-status-toast.error.visible" in app_css
    assert "pointer-events: auto;" in app_css[app_css.index(".grid-status-toast.error.visible"):]
    assert 'const submitter = event.submitter;' in app_js
    assert 'submitter.matches("[data-confirm-modal]")' in app_js
    assert "form.requestSubmit(submitter instanceof HTMLElement ? submitter : undefined);" in app_js


def test_automation_collections_have_truthful_server_fallbacks():
    """Verify that automation collections have truthful server fallbacks."""
    source = (TEMPLATES / "automation.html").read_text(encoding="utf-8")
    for grid_id, fallback_id in (
        ("automation-schedules-table", "automation-schedules-fallback"),
        ("automation-executions-table", "automation-executions-fallback"),
        ("automation-scripts-table", "automation-scripts-fallback"),
    ):
        assert f'id="{grid_id}"' in source
        assert f'data-fallback-id="{fallback_id}"' in source
        assert f'<table id="{fallback_id}"' in source

    assert '<dialog id="monitor-chart-modal"' in (
        TEMPLATES / "monitor.html"
    ).read_text(encoding="utf-8")

    assert "#automation-executions-panel[hidden], #scripts[hidden]" in source
    assert "Schedules, executions, and managed scripts are shown" in source
    executions = source.split('id="automation-executions-fallback"', 1)[1].split("</table>", 1)[0]
    assert "<th>Status</th>" in executions
    assert "{{ execution.status }}" in executions


def test_every_autosave_form_has_a_nearby_status_target():
    """Verify that every autosave form has a nearby status target."""
    autosave_count = 0
    for template in TEMPLATES.rglob("*.html"):
        source = template.read_text(encoding="utf-8")
        for match in re.finditer(r"<form\b(?P<attributes>[^>]*)>", source):
            attributes = match.group("attributes")
            if "data-autosave-form" not in attributes:
                continue
            autosave_count += 1
            status = re.search(r'data-autosave-status-id="([^"]+)"', attributes)
            assert status is not None, f"{template}:{source.count(chr(10), 0, match.start()) + 1}"
            assert f'id="{status.group(1)}"' in source, f"{template}:{status.group(1)}"
    # Managed PowerShell modules use a read-only view with a wizard-backed editor,
    # so they are intentionally excluded from the remaining direct autosave forms.
    assert autosave_count == 18

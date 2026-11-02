"""Settings tabs keep existing autosave forms complete and independent."""

from __future__ import annotations

from html.parser import HTMLParser

from tests.routers.ui.helpers import login


class SettingsFormsParser(HTMLParser):
    """Capture form ownership and count nested forms in rendered Settings."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: dict[str, dict[str, object]] = {}
        self.form_depth = 0
        self.nested_forms = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record form associations in the rendered document.

        Args:
            tag: HTML element name.
            attrs: Rendered element attributes.
        """
        values = dict(attrs)
        if tag == "form":
            self.nested_forms = self.nested_forms or self.form_depth > 0
            self.form_depth += 1
            form_id = values.get("id") or f"anonymous-{len(self.forms)}"
            self.forms[str(form_id)] = {"action": values.get("action"), "fields": set()}
        elif tag in {"input", "select", "textarea", "button"} and values.get("name"):
            form_id = values.get("form")
            if form_id is None and self.form_depth:
                form_id = next(reversed(self.forms))
            if form_id in self.forms:
                fields = self.forms[str(form_id)]["fields"]
                assert isinstance(fields, set)
                fields.add(str(values["name"]))

    def handle_endtag(self, tag: str) -> None:
        """Track form nesting boundaries.

        Args:
            tag: Closing element name.
        """
        if tag == "form":
            self.form_depth = max(0, self.form_depth - 1)


def test_settings_tabs_preserve_complete_autosave_form_ownership(client):
    """Every settings tab retains its existing endpoint field set and CSRF owner.

    Args:
        client: Isolated authenticated management browser.
    """
    login(client)
    response = client.get("/ui/management/settings")

    assert response.status_code == 200
    for tab_name in ("General", "Access &amp; Security", "Hardware", "Logging"):
        assert tab_name in response.text

    parser = SettingsFormsParser()
    parser.feed(response.text)
    assert not parser.nested_forms
    assert {
        "fqdn",
        "management_https_enabled",
        "web_terminal_enabled",
        "web_terminal_interfaces_present",
        "root_ssh_enabled",
        "service_dns_target_naming",
        "external_dns_servers",
        "csrf",
    } <= parser.forms["appliance-settings-form"]["fields"]
    assert parser.forms["appliance-settings-form"]["action"] == "/ui/management/settings"
    assert 'data-form-id="appliance-settings-form"' in response.text
    assert {
        "browser_session_idle_timeout_minutes",
        "api_token_max_lifetime_days",
        "csrf",
    } <= parser.forms["authentication-lifetimes-settings-form"]["fields"]
    assert parser.forms["authentication-lifetimes-settings-form"]["action"] == "/ui/management/settings/authentication-lifetimes"
    assert {"vmware_ceip_enabled", "csrf"} <= parser.forms["vmware-ceip-settings-form"]["fields"]
    assert parser.forms["vmware-ceip-settings-form"]["action"] == "/ui/management/settings/vmware-ceip"
    assert {
        "level",
        "syslog_enabled",
        "syslog_host",
        "syslog_port",
        "syslog_protocol",
        "syslog_facility",
        "syslog_level",
        "csrf",
    } <= parser.forms["logging-settings-form"]["fields"]


def test_settings_hardware_page_load_does_not_probe_or_install_guest_tools(client, monkeypatch):
    """Opening Settings leaves host observation and package mutation to explicit actions.

    Args:
        client: Isolated authenticated management browser.
        monkeypatch: Pytest fixture replacing host probes.
    """
    from atlaso.app.ui import SystemAdapter

    calls: list[str] = []
    monkeypatch.setattr(SystemAdapter, "guest_tools_status", lambda self: calls.append("status"))

    login(client)
    response = client.get("/ui/management/settings")

    assert response.status_code == 200
    assert calls == []
    assert "Check packages" in response.text
    assert "Install or repair guest tools" in response.text
    assert "Hardware status has not been checked." in response.text
    assert '<td colspan="7" class="muted">Hardware status has not been checked.</td>' in response.text

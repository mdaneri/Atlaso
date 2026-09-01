"""Test DNS/DHCP management UI transport behavior."""

import json
from pathlib import Path

from tests.routers.ui.helpers import login


def test_dns_settings_derives_listen_addresses_from_selected_interface(client):
    """Verify that dns settings derives listen addresses from selected interface.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns listen interface menu has empty state when no interfaces available.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    assert "data-tag-option=" not in page.text

    app_js = client.get("/static/app.js")
    assert "data-tag-empty" in app_js.text
    assert "visibleOptions" in app_js.text


def test_dns_page_uses_management_dhcp_dns_when_upstreams_are_empty(
    client, monkeypatch
):
    """Verify that dns page uses management dhcp dns when upstreams are empty.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, PhysicalInterface

    login(client)
    monkeypatch.setattr(
        "atlaso.app.services.appliance_settings.observed_management_dhcp_dns_servers",
        lambda interface_name: ["127.0.0.1", "::1", "192.168.167.2"],
    )
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.upstream_servers = ""
        eth0 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
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


def test_dns_page_fails_closed_when_management_dhcp_lease_has_no_upstream(
    client, monkeypatch
):
    """Verify that dns page fails closed when management dhcp lease has no upstream.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, PhysicalInterface

    login(client)
    monkeypatch.setattr(
        "atlaso.app.services.appliance_settings.observed_management_dhcp_dns_servers",
        lambda _name: [],
    )
    with SessionLocal() as db:
        dns_settings = db.execute(select(DnsSettings)).scalar_one()
        dns_settings.enabled = True
        dns_settings.upstream_servers = ""
        eth0 = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        eth0.role = "management"
        eth0.ipv4_method = "dhcp"
        eth0.ip_cidr = None
        eth0.host_ip_cidr = "192.168.167.219/24"
        db.commit()

    page = client.get("/dns")

    assert page.status_code == 200
    assert "systemd-networkd lease did not provide one" in page.text
    assert "# atlaso-dhcp-upstream-required" in page.text
    assert "server=127.0.0.1" not in page.text
    assert "server=::1" not in page.text


def test_dns_and_dhcp_pages_render(client):
    """Verify that dns and dhcp pages render.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    login(client)
    dns = client.get("/dns")
    assert dns.status_code == 200
    assert "DNS Zones" in dns.text
    assert "dns-records-fallback" in dns.text
    assert "dnsmasq" in dns.text
    assert "core.atlaso.internal" in dns.text
    assert "<strong>Avoid .local for VCF.</strong>" not in dns.text
    assert "+ Domain" in dns.text
    assert "Define the DNS domain" in dns.text
    dns_domain_wizard = dns.text.split('id="dns-domain-dialog"', 1)[1].split(
        "</dialog>", 1
    )[0]
    dns_domain_identity = dns_domain_wizard.split(
        'data-atlaso-wizard-step="identity"', 1
    )[1].split("</section>", 1)[0]
    assert (
        '<textarea name="description" rows="3" maxlength="1000"' in dns_domain_identity
    )
    assert "data-dns-domain-wizard-add" in dns.text
    assert "data-dns-domain-enabled-form" in dns.text
    dns_tools_head = dns.text.split('class="dns-zone-tools-head"', 1)[1].split(
        "</form>", 1
    )[0]
    assert dns_tools_head.index('class="tab-buttons tool-tabs"') < dns_tools_head.index(
        "data-dns-domain-enabled-form"
    )
    assert "Import Hosts" in dns.text
    assert "Import Zone File" in dns.text
    assert "Reverse Zones" in dns.text
    assert "Reverse/PTR" in dns.text
    assert "PTR records are generated automatically" in dns.text
    assert "zone-file-editor" in dns.text
    assert "dns-import-form" in dns.text
    assert "dns-import-controls" in dns.text
    assert "data-monaco-editor" in dns.text
    assert 'data-monaco-language="atlaso-hosts"' in dns.text
    assert 'data-monaco-language="atlaso-zone"' in dns.text
    assert "Import zone file into atlaso.internal" in dns.text
    assert "relative hostnames are saved inside this domain" in dns.text
    assert 'data-domain="atlaso.internal"' in dns.text
    assert "A (IPv4)" in dns.text
    assert "AAAA (IPv6)" in dns.text
    assert "CNAME (alias)" in dns.text
    assert "ptr-record=" not in dns.text
    assert "1.49.168.192.in-addr.arpa" in dns.text
    assert 'name="listen_interfaces"' in dns.text
    assert "data-derived-listen-addresses" in dns.text
    assert 'name="conditional_forwarders"' in dns.text
    assert "Conditional forwarders" in dns.text
    assert "domain=server1,server2" in dns.text
    assert "sddc.internal=192.168.10.10,192.168.10.11" in dns.text
    assert dns.text.count("data-tag-editor") >= 1
    assert dns.text.count("data-tag-menu-toggle") >= 1
    assert dns.text.count("data-tag-option=") >= 2
    assert 'data-tag-empty-message="No interfaces available."' in dns.text
    assert 'placeholder="Add interface..."' in dns.text
    assert 'placeholder="Add listen address..."' not in dns.text
    assert "eth1 - access / trunk" not in dns.text
    assert 'action="/ui/management/dns/zones"' in dns.text
    assert 'action="/ui/management/dns/zones/delete"' in dns.text
    assert "data-confirm-modal" in dns.text
    assert "Delete atlaso.internal?" in dns.text
    assert (
        "It will not touch the appliance until global appliance apply runs." in dns.text
    )
    assert 'action="/ui/management/dns/zones/import"' in dns.text
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in dns.text
    assert "atlaso.internal or sitea.internal" in dns.text
    assert "Changes save automatically." in dns.text
    assert "Review appliance changes" in dns.text
    assert "Save desired state" not in dns.text
    assert "Save DNS" not in dns.text
    app_css = client.get("/static/app.css").text
    assert ".dns-zone-tools-head {" in app_css
    assert ".dns-authority-summary-head > strong {\n  font-size: 12px;" in app_css
    assert ".dns-authority-records code {" in app_css
    assert "font-size: 11px;" in app_css

    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert 'menu.querySelectorAll("[data-tag-option]")' in app_js.text
    assert "candidate.dataset.tagOption === value" in app_js.text
    assert 'value.replace(/"/g' not in app_js.text
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
    assert (
        'newDnsRecordRow(domain, tableElement.dataset.suggestedIpv4 || "")'
        in app_js.text
    )
    assert "suggested_ipv4: suggestedAddress" in app_js.text
    assert (
        'data.record_type !== "A" && data.address === data.suggested_ipv4'
        in app_js.text
    )
    assert 'cell.getField() === "host_label"' in app_js.text
    assert "DNS_ACTIVE_ZONE_STORAGE_KEY" in app_js.text
    assert "initializeMonacoEditors" in app_js.text
    assert "const atlasoDnsRecordTables = new WeakMap()" in app_js.text
    assert "function redrawDnsRecordTables" in app_js.text
    assert "atlasoDnsRecordTables.set(tableElement, table)" in app_js.text
    assert "redrawDnsRecordTables(panel)" in app_js.text
    assert "window.AtlasoMonaco" in app_js.text
    assert "enhanceTextarea" in app_js.text
    assert (
        'data-monaco-language="atlaso-kickstart"'
        in Path("atlaso/app/templates/esxi_pxe.html").read_text()
    )
    assert "data-tag-empty" in app_js.text
    assert "No options available." in app_js.text
    assert "AtlasoMonaco.setValue" in app_js.text
    assert "rememberDnsActiveZone(data.domain)" in app_js.text
    assert "dnsZoneTabButtonForDomain(storedDomain)" in app_js.text
    assert "initializeTagEditors" in app_js.text
    assert "initializeEsxiIsoUploadForms" in app_js.text
    assert "XMLHttpRequest" in app_js.text
    assert "X-Atlaso-Upload" in app_js.text
    assert 'pattern: "wizard-backed"' in app_js.text
    assert "esxiIsoUploadWizard = window.AtlasoUiPatterns.createWizard" in app_js.text
    assert 'esxiInstallerIsosTable?.addRow?.(uploaded, true, "__new__")' in app_js.text
    assert "tableElement.atlasoRefreshIsoOptions = async (path, label)" in app_js.text
    assert (
        "isoColumn?.updateDefinition?.({ editorParams: { values: isoValues, autocomplete: true } })"
        in app_js.text
    )
    assert (
        "await hostsElement?.atlasoRefreshIsoOptions?.(uploaded.path, label)"
        in app_js.text
    )
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
    assert 'fetch(managementUiPath("/appliance-apply/status")' in app_js.text
    assert "function updateServerTime" in app_js.text
    assert "window.setInterval(load, 5000)" in app_js.text
    assert "initializeApplianceApplyProgress" in app_js.text
    assert "Submit appliance changes" in app_js.text
    assert "openApplianceApplyReview" in app_js.text
    assert "renderApplianceApplyTask" in app_js.text
    assert "window.AtlasoApplianceApplyPolling.createMonitor" in app_js.text
    assert (
        'throw new Error("Unable to reconcile the completed appliance task.")'
        in app_js.text
    )
    assert (
        "Live task status is temporarily unavailable. Atlaso will retry automatically; "
        "if this persists, open Tasks in another tab."
        in app_js.text
    )
    assert (
        "Applying management settings; Atlaso is reconnecting to task status."
        in app_js.text
    )
    assert "if this persists, open Tasks in another tab" in app_js.text
    assert "const APPLIANCE_APPLY_SUCCESS_AUTO_CLOSE_MS = 15000;" in app_js.text
    assert "function clearApplianceApplyAutoClose()" in app_js.text
    assert "function scheduleApplianceApplyAutoClose(task)" in app_js.text
    assert 'task?.status !== "succeeded"' in app_js.text
    assert 'modal.dataset.taskStatus === "succeeded"' in app_js.text
    assert (
        'elements.modal.addEventListener("close", clearApplianceApplyAutoClose)'
        in app_js.text
    )
    assert "scheduleApplianceApplyAutoClose(task);" in app_js.text
    assert "Management connection warning" in app_js.text
    assert "applyConnectionWarnings" in app_js.text
    assert 'elements.submit.classList.add("hidden")' in app_js.text
    assert (
        'elements.submit.classList.toggle("hidden", units.length === 0)' in app_js.text
    )
    assert '{ title: "Status", field: "status", width: 150' in app_js.text
    assert 'applianceApplyModalTable?.on("rowClick"' in app_js.text
    assert 'atlasoTasksTable?.on("rowClick"' in app_js.text
    assert "data-appliance-apply-modal" in app_js.text
    assert "data-appliance-apply-connection-warning" in dns.text
    assert "data-appliance-apply-poll-warning" in dns.text
    assert ".alert.neutral" in app_css
    assert (
        'class="button primary hidden" type="submit" data-appliance-apply-submit'
        in dns.text
    )
    assert "data-apply-submit-tracker" not in app_js.text
    assert 'index === 0 ? "Applying"' not in app_js.text
    assert "initializeDhcpScopesTable" in app_js.text
    assert "+ Add IP zone here" in app_js.text
    assert "dhcpRangeFormatter" in app_js.text
    assert 'address_family: ""' in app_js.text
    assert 'interface_name: ""' in app_js.text
    assert 'lease_time: ""' in app_js.text
    assert "applyDhcpScopeInterfaceDefaults" in app_js.text
    assert 'formSelector: "[data-dhcp-scope-form]"' in app_js.text
    assert 'dialogId: "dhcp-scope-dialog"' in app_js.text
    assert 'resourceName: "scope"' in app_js.text
    assert (
        'body.set("address_family", form.elements.address_family.value);' in app_js.text
    )
    assert 'body.set("lease_time", form.elements.lease_time.value);' in app_js.text
    assert 'title: "Family"' in app_js.text
    assert "address_family" in app_js.text
    assert 'title: "NTP"' in app_js.text
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
    assert (
        ".dns-records-table {\n  height: clamp(280px, 42vh, 420px);\n"
        "  width: 100%;\n  max-width: 100%;"
        in app_css.text
    )
    assert (
        ".dns-records-table .tabulator-tableholder {\n  overflow-x: auto;"
        in app_css.text
    )
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
    assert "data-domain-options='[\"atlaso.internal\"]'" in dhcp.text
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
    assert 'href="/ui/management/dashboard#appliance-apply-review"' in dhcp.text
    assert "Review appliance changes" in dhcp.text
    assert "Save DHCP" not in dhcp.text
    assert "192.168.50.100" in dhcp.text
    assert "192.168.50.1" in dhcp.text
    reservation_payload = dhcp.text.split("data-reservations='", 1)[1].split("'", 1)[0]
    reservation_rows = json.loads(html.unescape(reservation_payload))
    assert reservation_rows
    assert all("zone_name" in row for row in reservation_rows)


def test_dhcp_zone_defaults_follow_vlan_dns_and_interface_ntp_bindings(client):
    """Verify that dhcp zone defaults follow vlan dns and interface ntp bindings.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, NtpSettings, PhysicalInterface

    with SessionLocal() as db:
        eth2_interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        ).scalar_one()
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
    eth1_vlan = next(
        item for item in defaults["interfaces"] if item["name"] == "eth1.20"
    )
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
    assert (
        'rowData.prefix_length = Number.isInteger(prefix) ? prefix : "";' in app_js.text
    )
    assert (
        'form?.elements.interface_name?.addEventListener("change", refreshNetworkDefaults);'
        in app_js.text
    )
    assert (
        'form?.elements.address_family?.addEventListener("change", refreshNetworkDefaults);'
        in app_js.text
    )


def test_dns_new_record_row_suggests_next_available_ipv4(client):
    """Verify that dns new record row suggests next available ipv4.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

    login(client)
    page = client.get("/dns")

    assert page.status_code == 200
    assert 'data-suggested-ipv4="192.168.50.2"' in page.text
    payload = page.text.split("data-records='", 1)[1].split("'", 1)[0]
    records = json.loads(html.unescape(payload))
    assert any(record["address"] == "192.168.49.1" for record in records)


def test_dns_settings_badge_reflects_desired_state_not_runtime_state(client):
    """Verify that dns settings badge reflects desired state not runtime state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, ServiceState

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(DnsSettings)).scalar_one()
        settings.enabled = True
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "dns")
        ).scalar_one()
        service.enabled = False
        service.running = False
        service.health = "disabled"
        db.commit()

    page = client.get("/dns")
    settings_panel = page.text.split("<h2>DNS Settings</h2>", 1)[1].split("</form>", 1)[
        0
    ]

    assert page.status_code == 200
    assert '<span class="status-pill good">enabled</span>' in settings_panel
    assert '<span class="status-pill muted">disabled</span>' not in settings_panel


def test_dhcp_leases_page_reflects_live_adapter_output(client, monkeypatch):
    """Verify that dhcp leases page reflects live adapter output.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import html

    from sqlalchemy import select

    import atlaso.app.routers.ui.dns_dhcp as dns_dhcp_router
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpReservation, DnsRecord, EsxiPxeHost

    def fake_read_dhcp_leases(self):
        """Return fake read dhcp leases."""
        return AdapterResult(
            command=[
                "sudo",
                "-n",
                "/opt/atlaso/bin/atlaso-helper",
                "dnsmasq",
                "leases",
                "--real",
            ],
            dry_run=False,
            stdout=(
                "1893456000 02:15:5d:00:20:40 192.168.50.140 live-client.atlaso.internal *\n"
                "1893456000 02:15:5d:00:20:41 192.168.1.110 stale-client.atlaso.internal *\n"
            ),
        )

    monkeypatch.setattr(
        "atlaso.app.ui.SystemAdapter.read_dhcp_leases", fake_read_dhcp_leases
    )

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
        reservation = db.execute(
            select(DhcpReservation).where(
                DhcpReservation.mac_address == "02:15:5d:00:20:40"
            )
        ).scalar_one()
        assert reservation.hostname == "live-client.atlaso.internal"
        assert reservation.ip_address == "192.168.50.140"
        assert reservation.enabled is True
        record = db.execute(
            select(DnsRecord).where(
                DnsRecord.hostname == "live-client.atlaso.internal",
                DnsRecord.record_type == "A",
            )
        ).scalar_one()
        assert record.address == "192.168.50.140"

    with SessionLocal() as db:
        from atlaso.app.models import DhcpScope
        from atlaso.app.services.esxi_pxe import save_esxi_pxe_boot_settings

        scope = db.execute(
            select(DhcpScope).where(DhcpScope.name == "SiteA")
        ).scalar_one()
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

    lifecycle_events = []
    monkeypatch.setattr(
        dns_dhcp_router,
        "lock_esxi_host_reference_lifecycle",
        lambda _db: lifecycle_events.append("lock"),
    )
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
    assert lifecycle_events == ["lock"]
    assert pxe_response.headers["location"] == "/ui/management/esxi-pxe#esxi-pxe-hosts"
    with SessionLocal() as db:
        host = db.execute(
            select(EsxiPxeHost).where(EsxiPxeHost.mac_address == "02:15:5d:00:20:42")
        ).scalar_one()
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
        deny = db.execute(
            select(DhcpReservation).where(
                DhcpReservation.mac_address == "02:15:5d:00:20:43"
            )
        ).scalar_one()
        assert deny.enabled is False
        assert deny.description == "Deny DHCP for 02:15:5d:00:20:43."


def test_dns_listen_options_include_access_and_vlans_not_trunks(client):
    """Verify that dns listen options include access and vlans not trunks.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
                role="access",
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
    assert "eth1.60 - VLAN 60 on eth1 / access / 192.168.60.1" in page.text
    assert "eth1 - access / trunk" not in page.text
    assert "eth9 - unused / access / 192.168.90.1" not in page.text
    assert "eth1.70 - VLAN 70 on eth1 / unused / 192.168.70.1" not in page.text
    assert 'data-tag-option="eth1.60"' in page.text
    assert 'data-tag-option="eth9"' not in page.text
    assert 'data-tag-option="eth1.70"' not in page.text
    assert 'data-tag-option="192.168.60.1"' not in page.text


def test_dns_settings_accept_multiple_listen_interfaces(client):
    """Verify that dns settings accept multiple listen interfaces.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns settings autosave returns json.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    assert (
        "ESXi PXE boot services require DHCP to be enabled so clients receive boot files."
        not in response.json()["validation_errors"]
    )
    assert "server=/sddc.internal/192.168.10.10" in response.json()["config_preview"]
    assert "server=/sddc.internal/192.168.10.11" in response.json()["config_preview"]
    refreshed = client.get("/dns")
    assert "server=/sddc.internal/192.168.10.10" in refreshed.text
    assert "server=/sddc.internal/192.168.10.11" in refreshed.text
    assert "sddc.internal=192.168.10.10,192.168.10.11" in refreshed.text


def test_dns_settings_autosave_filters_invalid_listen_interfaces(client):
    """Verify that dns settings autosave filters invalid listen interfaces.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    assert (
        "ESXi PXE boot services require DHCP to be enabled so clients receive boot files."
        not in response.json()["validation_errors"]
    )
    assert "interface=eth2" in response.json()["config_preview"]


def test_dhcp_settings_autosave_returns_json(client):
    """Verify that dhcp settings autosave returns json.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dhcp settings autosave allows service toggle only.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dhcp settings badge reflects desired state not seeded service state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpSettings, ServiceState

    login(client)
    with SessionLocal() as db:
        settings = db.execute(select(DhcpSettings)).scalar_one()
        settings.enabled = True
        state = db.execute(
            select(ServiceState).where(ServiceState.service == "dhcp")
        ).scalar_one()
        state.enabled = False
        state.running = False
        state.health = "disabled"
        db.commit()

    page = client.get("/dhcp")
    settings_panel = page.text.split("<h2>DHCP Settings</h2>", 1)[1].split(
        "</form>", 1
    )[0]

    assert page.status_code == 200
    assert '<span class="status-pill good">enabled</span>' in settings_panel
    assert '<span class="status-pill muted">disabled</span>' not in settings_panel


def test_dhcp_scope_edit_form_updates_ip_zone(client):
    """Verify that dhcp scope edit form updates ip zone.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/dhcp")
    import html

    payload = page.text.split("data-scopes='", 1)[1].split("'", 1)[0]
    scope_wizard = page.text.split('id="dhcp-scope-dialog"', 1)[1].split(
        "</dialog>", 1
    )[0]
    identity_step = scope_wizard.split('data-atlaso-wizard-step="identity"', 1)[
        1
    ].split("</section>", 1)[0]
    services_step = scope_wizard.split('data-atlaso-wizard-step="services"', 1)[
        1
    ].split("</section>", 1)[0]
    assert '<textarea name="description" rows="3" maxlength="1000">' in identity_step
    assert 'name="lease_duration"' in services_step
    assert 'class="form-grid dhcp-lease-services-grid"' in services_step
    assert '<fieldset class="dhcp-lease-time-field">' in services_step
    assert '<legend><span class="field-label"><span>Lease time</span>' in services_step
    assert '<option value="m">Minutes</option>' in services_step
    assert '<option value="h">Hours</option>' in services_step
    assert '<option value="d">Days</option>' in services_step
    app_css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    lease_time_css = app_css.split(".dhcp-lease-time-field {", 1)[1].split("}", 1)[0]
    assert "grid-column: 1 / -1;" in lease_time_css
    assert "border: 1px solid var(--border);" in lease_time_css
    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    assert "leaseTime.dataset.atlasoOriginalLeaseTime" in app_js
    assert "Replace unsupported value:" in app_js
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
    """Verify that dhcp vlan scope can be created without dns server.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
        scope = db.execute(
            select(DhcpScope).where(DhcpScope.name == "VLAN20")
        ).scalar_one()
        assert scope.interface_name == "eth1.20"
        assert scope.dns_server == ""

    app_js = client.get("/static/app.js").text
    required_block = app_js.split("function hasRequiredDhcpScopeFields", 1)[1].split(
        "async function autoSaveDhcpScope", 1
    )[0]
    assert "data.address_family" in required_block
    assert "data.prefix_length" in required_block
    assert "data.lease_time" in required_block
    assert "data.domain_name" in required_block
    assert "data.dns_server" not in required_block
    derived_range_block = app_js.split("function deriveDhcpLeaseRange", 1)[1].split(
        "function isUniqueNewDhcpScopeName", 1
    )[0]
    assert "address >= start && address <= end" in derived_range_block
    assert "addressesBeforeGateway" in derived_range_block
    assert "addressesAfterGateway" in derived_range_block


def test_dhcp_scope_family_cannot_change_after_create(client):
    """Verify that dhcp scope family cannot change after create.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

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
        scope = db.execute(
            select(DhcpScope).where(DhcpScope.id == scope_id)
        ).scalar_one()
        assert scope.address_family == "ipv4"
        assert scope.range_expression == "192.168.50.100-192.168.50.200"


def test_dhcp_reservation_edit_form_updates_row(client):
    """Verify that dhcp reservation edit form updates row.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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

    payload = page.text.split("data-reservations='", 1)[1].split("'", 1)[0]
    rows = json.loads(html.unescape(payload))
    reservation_id = next(
        row["id"]
        for row in rows
        if row["hostname"] == "reserved-client.atlaso.internal"
    )
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
    """Verify that dns zone create adds domain tab.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/dns/zones",
        data={
            "domain": "sitea.internal",
            "description": "Site A services",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    refreshed = client.get("/dns")
    assert "sitea.internal" in refreshed.text
    assert "Site A services" in refreshed.text
    assert 'data-domain="sitea.internal"' in refreshed.text


def test_dhcp_option_wizard_create_and_direct_enablement_edit(client):
    """Verify that dhcp option wizard create and direct enablement edit.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/dhcp")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/dhcp/options",
        data={
            "scope_id": "__global__",
            "option_code": "option:ntp-server",
            "value": "192.168.50.1",
            "description": "wizard option",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert created.status_code == 200, created.text
    option = created.json()["option"]
    assert option["enabled"] is True
    edited = client.post(
        f"/dhcp/options/{option['id']}/edit",
        data={
            "scope_id": "__global__",
            "option_code": option["option_code"],
            "value": option["value"],
            "description": option["description"],
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert edited.status_code == 200
    assert edited.json()["option"]["enabled"] is False


def test_dns_zone_disable_keeps_database_records_but_excludes_rendered_state(client):
    """Verify that dns zone disable keeps database records but excludes rendered state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, DnsSettings

    login(client)
    page = client.get("/dns")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/dns/zones",
        data={
            "domain": "stored.internal",
            "enabled": "on",
            "enabled_present": "1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert created.status_code == 200
    assert created.json()["domain"] == {
        "name": "stored.internal",
        "description": "",
        "enabled": True,
    }
    record = client.post(
        "/dns/records",
        data={
            "hostname": "app",
            "domain": "stored.internal",
            "record_type": "A",
            "address": "192.168.50.210",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert record.status_code == 303

    disabled = client.post(
        "/dns/zones/enabled",
        data={"domain": "stored.internal", "csrf": csrf},
        headers={"X-Atlaso-Grid": "1"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["domain"]["enabled"] is False

    refreshed = client.get("/dns")
    assert "stored.internal · disabled" in refreshed.text
    assert "app.stored.internal" in refreshed.text
    assert "domain=stored.internal" not in refreshed.text
    with SessionLocal() as db:
        settings = db.execute(select(DnsSettings)).scalar_one()
        assert "stored.internal" in settings.disabled_domains
        assert db.execute(
            select(DnsRecord).where(DnsRecord.hostname == "app.stored.internal")
        ).scalar_one()

    enabled = client.post(
        "/dns/zones/enabled",
        data={"domain": "stored.internal", "enabled": "on", "csrf": csrf},
        headers={"X-Atlaso-Grid": "1"},
    )
    assert enabled.status_code == 200
    assert enabled.json()["domain"]["enabled"] is True
    assert "domain=stored.internal" in client.get("/dns").text


def test_dns_reverse_zones_are_closed_native_disclosures_with_authority_summary(client):
    """Verify that dns reverse zones are closed native disclosures with authority summary.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns zone delete removes domain and scoped records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns zone delete keeps at least one domain.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns zone warns for local domain.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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


def test_duplicate_dns_record_form_shows_conflict(client):
    """Verify that duplicate dns record form shows conflict.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns record form scopes relative host to domain.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns record form rejects wrong ip family.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that dns record edit form updates row.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html

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
    record_id = next(
        record["id"]
        for record in records
        if record["hostname"] == "editable.atlaso.internal"
    )
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
    """Verify that hosts file editor replaces dns records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that zone file editor import replaces domain records.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that zone file import error preserves pasted zone text.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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

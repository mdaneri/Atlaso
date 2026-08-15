"""Test Managed LDAP management UI transports."""

from tests.routers.ui.helpers import login


def test_managed_ldap_page_creates_org_user_group_and_shows_secret_once(client):
    """Verify that managed ldap page creates org user group and shows secret once.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/ldap")
    assert page.status_code == 200
    assert "Managed LDAP for VCF Automation" in page.text
    assert 'class="split-workspace service-settings-workspace"' in page.text
    assert 'aria-label="Managed LDAP views"' not in page.text
    assert "LDAP Settings" in page.text
    main_panel_index = page.text.index('<div class="panel wide-panel">')
    settings_rail_index = page.text.index(
        '<aside class="side-stack service-settings-column">'
    )
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
    assert (
        ".service-settings-workspace {\n  grid-template-columns: minmax(0, 1fr) 360px;"
        in app_css
    )
    assert '.tabulator-cell[tabulator-field="uid"] .add-row-hint' in app_css
    assert ".zone-tabs .tab-button" in app_css
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    created = client.post(
        "/ldap/organizations",
        data={
            "name": "Org A",
            "description": "Primary VCF lab organization",
            "slug": "org-a",
            "suffix_dn": "",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    assert created.status_code == 201, created.text
    assert "Copy this credential now" in created.text
    assert 'id="ldap-bind-secret-modal"' in created.text
    assert "data-ldap-bind-secret-auto-open" in created.text
    assert "data-ldap-bind-secret-close" in created.text
    bind_secret_modal = created.text.split('id="ldap-bind-secret-modal"', 1)[1].split(
        "</dialog>", 1
    )[0]
    assert "data-ldap-bind-secret-close autofocus" in bind_secret_modal
    assert "data-copy-value" in created.text
    assert "data-download-value" in created.text
    assert 'data-download-filename="vcf-bind-credential-org-a.txt"' in created.text
    assert "ldap-users-table" in created.text
    assert "ldap-groups-table" in created.text
    assert "Primary VCF lab organization" in created.text
    assert "data-ldap-organization-tabs" in created.text
    assert ">+ Organization</button>" in created.text
    organization_tabs = created.text.split("data-ldap-organization-tabs>", 1)[1].split(
        "</div>", 1
    )[0]
    assert 'role="tab"' in organization_tabs
    assert "data-ldap-organization-open" in organization_tabs
    assert 'id="ldap-organization-dialog"' in created.text
    assert "data-ldap-organization-form" in created.text
    assert 'data-atlaso-wizard-step="enablement"' in created.text
    assert 'name="description"' in created.text
    assert 'id="ldap-user-dialog"' in created.text
    assert "data-ldap-user-form" in created.text
    assert 'id="ldap-group-dialog"' in created.text
    assert "data-ldap-group-form" in created.text
    assert 'name="password_confirmation_present" value="1"' in created.text
    assert 'name="members_present" value="1"' in created.text
    assert "data-ldap-organization-open" in created.text
    assert 'id="ldap-organization-new"' not in created.text
    assert "<summary>Create organization</summary>" not in created.text
    assert "<summary>Add user</summary>" not in created.text
    assert "<summary>Add group</summary>" not in created.text
    assert "Generate test directory" not in created.text
    assert 'name="user_count"' not in created.text
    assert 'name="group_count"' not in created.text
    organization_header = created.text.split('<div class="zone-head">', 1)[1].split(
        "</div>\n          </div>", 1
    )[0]
    assert 'class="zone-actions"' in organization_header
    assert (
        'class="button tiny secondary" type="submit">Rotate bind credential</button>'
        in organization_header
    )
    assert (
        'class="button tiny danger" type="submit">Delete organization</button>'
        in organization_header
    )
    assert 'class="tab-buttons tool-tabs ldap-directory-resource-tabs"' in created.text
    assert (
        "uid=vcf-bind,ou=service-accounts,dc=org-a,dc=ldap,dc=atlaso,dc=internal"
        in created.text
    )
    assert "serviceAccount → employeeType" not in created.text

    organization_id = created.text.split("/ldap/organizations/", 1)[1].split("/", 1)[0]
    assert f'data-ldap-organization-id="{organization_id}"' in created.text
    assert 'data-tab-storage-key="atlaso:ldap:resource-tab"' in created.text
    app_js = client.get("/static/app.js").text
    assert "window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0)" in app_js
    assert 'target.closest("[data-download-value]")' in app_js
    assert (
        'document.addEventListener("DOMContentLoaded", () => initializeDownloadValueButtons())'
        in app_js
    )
    assert (
        'const LDAP_ORGANIZATION_SELECTION_KEY = "atlaso:ldap:organization"' in app_js
    )
    assert "function initializeLdapPageState()" in app_js
    assert "function initializeLdapOrganizationWizard()" in app_js
    ldap_organization_wizard_js = app_js.split(
        "function initializeLdapOrganizationWizard()", 1
    )[1].split("function initializeLdapPageState()", 1)[0]
    assert "window.AtlasoUiPatterns.createWizard({" in ldap_organization_wizard_js
    assert "data-ldap-organization-open" in ldap_organization_wizard_js
    assert (
        '{ id: "enablement", title: "Choose organization state"'
        in ldap_organization_wizard_js
    )
    ldap_page_state_js = app_js.split("function initializeLdapPageState()", 1)[1].split(
        "function attachLdapGridState(", 1
    )[0]
    assert "await fetch(link.href" in ldap_page_state_js
    assert (
        "currentPanel.replaceWith(document.importNode(nextCurrentPanel, true))"
        in ldap_page_state_js
    )
    assert (
        '["ldap-user-dialog", "ldap-group-dialog", "ldap-group-members-modal"]'
        in ldap_page_state_js
    )
    assert "window.history[historyMethod]" in ldap_page_state_js
    assert 'window.addEventListener("popstate"' in ldap_page_state_js
    assert "window.location.replace(validStoredLink.href)" not in ldap_page_state_js
    assert 'tabList.querySelectorAll(".tab-button")' in ldap_page_state_js
    assert "newOrganizationPanel" not in ldap_page_state_js
    assert "initializeLdapDirectoryTables()" in ldap_page_state_js
    assert "initializeTabs()" in ldap_page_state_js
    assert "function attachLdapGridState(" in app_js
    assert "function redrawLdapDirectoryTables(" in app_js
    disabled_helper = client.get(
        f"/vcf-helper?ldap_vcf=1&ldap_organization_id={organization_id}"
    )
    ldap_tile = disabled_helper.text.split("data-vcf-ldap-open", 1)[1].split(">", 1)[0]
    assert "disabled" in ldap_tile
    assert (
        'data-help="Enable Managed LDAP and at least one organization before using this helper."'
        in disabled_helper.text
    )
    assert "Enable Managed LDAP first" in disabled_helper.text

    enabled = client.post(
        "/ldap/settings",
        data={
            "enabled": "on",
            "hostname": "ldap.atlaso.internal",
            "listen_interfaces_present": "1",
            "ldaps_enabled": "on",
            "port": "636",
            "ldap_port": "389",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
        follow_redirects=False,
    )
    assert enabled.status_code == 200
    enabled_payload = enabled.json()
    assert enabled_payload["saved"] is True
    assert enabled_payload["settings"]["enabled"] is True
    assert enabled_payload["service_status"]["label"] in {"live", "pending"}
    assert enabled_payload["appliance_apply_status"]["changed"] is True
    vcf_helper = client.get(
        f"/vcf-helper?ldap_vcf=1&ldap_organization_id={organization_id}"
    )
    assert vcf_helper.status_code == 200
    assert "Managed LDAP for VCF Automation 9.1" in vcf_helper.text
    assert "data-vcf-ldap-auto-open" in vcf_helper.text
    assert f"/ldap/organizations/{organization_id}/vcf-bundle.zip" in vcf_helper.text
    assert f"/ldap/organizations/{organization_id}/vcf/inspect" in vcf_helper.text
    assert f"/ldap/organizations/{organization_id}/vcf/configure" in vcf_helper.text
    assert "serviceAccount → employeeType" in vcf_helper.text
    assert "Load organization" not in vcf_helper.text
    assert "data-vcf-ldap-wizard-form" in vcf_helper.text
    assert "data-vcf-ldap-organization-select" in vcf_helper.text
    assert 'data-atlaso-wizard-step="organization"' in vcf_helper.text
    assert 'data-atlaso-wizard-step="connection"' in vcf_helper.text
    assert 'data-atlaso-wizard-step="trust"' in vcf_helper.text
    assert 'data-atlaso-wizard-step="review"' in vcf_helper.text
    vcf_ldap_modal = vcf_helper.text.split('<dialog id="vcf-ldap-modal"', 1)[1].split(
        "</dialog>", 1
    )[0]
    assert vcf_ldap_modal.count('name="target_url"') == 1
    assert vcf_ldap_modal.count('name="vcf_organization_id"') == 1
    assert vcf_ldap_modal.count('name="username"') == 1
    assert vcf_ldap_modal.count('name="password"') == 1
    assert "Generate LDAP Test Directory" in vcf_helper.text
    assert "data-ldap-generate-open" in vcf_helper.text
    assert "Generate test directory" not in vcf_ldap_modal
    assert "data-ldap-generate-form" in vcf_helper.text
    assert "data-ldap-generate-review" in vcf_helper.text
    vcf_ldap_helper_js = (
        client.get("/static/app.js")
        .text.split("function initializeVcfLdapHelper()", 1)[1]
        .split("function initializeLdapBindSecretModal()", 1)[0]
    )
    assert vcf_ldap_helper_js.count("window.AtlasoUiPatterns.createWizard({") == 2

    page = client.get("/ldap")
    assert "Copy this credential now" not in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    organization_id = page.text.split("/ldap/organizations/", 1)[1].split("/", 1)[0]
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
        operator_id = db.execute(
            select(LdapUser.id).where(LdapUser.uid == "operator")
        ).scalar_one()
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
        data={
            "name": "Operators",
            "description": "VCF operators",
            "enabled": "false",
            "csrf": csrf,
        },
        headers={"Accept": "application/json"},
    )
    assert grid_group.status_code == 201
    assert grid_group.json()["enabled"] is False
    group_id = grid_group.json()["id"]
    refreshed_directory = client.get(f"/ldap?organization_id={organization_id}")
    group_wizard = refreshed_directory.text.split('id="ldap-group-dialog"', 1)[1].split(
        "</dialog>", 1
    )[0]
    membership_step = group_wizard.split('data-atlaso-wizard-step="membership"', 1)[
        1
    ].split("</section>", 1)[0]
    enablement_step = group_wizard.split('data-atlaso-wizard-step="enablement"', 1)[
        1
    ].split("</section>", 1)[0]
    assert (
        f'<option value="user:{operator_id}">User: operator</option>' in membership_step
    )
    assert (
        f'<option value="group:{group_id}" data-member-group-id="{group_id}">Group: Operators</option>'
        in membership_step
    )
    assert 'type="checkbox" name="enabled" checked' in enablement_step
    group_with_members = client.post(
        f"/ldap/groups/{group_id}/edit",
        data={
            "name": "Operators",
            "description": "Reviewed VCF operators",
            "members": [f"user:{operator_id}"],
            "members_present": "1",
            "enabled": "on",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert group_with_members.status_code == 200
    assert group_with_members.json()["enabled"] is True
    assert [
        {key: member[key] for key in ("type", "id", "name")}
        for member in group_with_members.json()["members"]
    ] == [{"type": "user", "id": operator_id, "name": "operator"}]
    direct_group_toggle = client.post(
        f"/ldap/groups/{group_id}/edit",
        data={
            "name": "Operators",
            "description": "Reviewed VCF operators",
            "enabled": "false",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert direct_group_toggle.status_code == 200
    assert direct_group_toggle.json()["enabled"] is False
    assert [
        {key: member[key] for key in ("type", "id", "name")}
        for member in direct_group_toggle.json()["members"]
    ] == [{"type": "user", "id": operator_id, "name": "operator"}]

    app_js = client.get("/static/app.js").text
    ldap_grid_js = app_js.split("function initializeLdapDirectoryTables()", 1)[1].split(
        "function initializeLdapPasswordModal()", 1
    )[0]
    assert "+ Add user here" in ldap_grid_js
    assert "+ Add group here" in ldap_grid_js
    assert 'formSelector: "[data-ldap-user-form]"' in ldap_grid_js
    assert 'formSelector: "[data-ldap-group-form]"' in ldap_grid_js
    assert ldap_grid_js.count("initializeAtlasoResourceWizard({") == 2
    assert 'label: "Reset password"' in ldap_grid_js
    assert 'deleteLabel: "Delete user"' in ldap_grid_js
    assert "inlineEnabled: false" in ldap_grid_js
    assert "enabled: true, members: []" in app_js
    assert "function ldapGroupMembershipFormatter(cell)" in app_js
    assert "formatter: ldapGroupMembershipFormatter" in ldap_grid_js
    assert "<th>Type</th><th>Member</th>" in app_js
    assert "function updateCurrentPageApplyNotice(payload = {})" in app_js
    assert "updateCurrentPageApplyNotice(payload);" in app_js
    assert "function updatePageApplyNotice(status = {})" in app_js
    assert (
        "if (payload.appliance_apply_status) updatePageApplyNotice(payload.appliance_apply_status);"
        in app_js
    )
    assert "function updateLdapSettingsStatus(payload = {})" in app_js
    assert (
        "if (!tableElement.isConnected || tableElement.offsetParent === null) return;"
        in app_js
    )
    bind_secret_js = app_js.split("function initializeLdapBindSecretModal()", 1)[
        1
    ].split("function initializeAutomationTables()", 1)[0]
    assert "closeButton.focus({ preventScroll: true })" in bind_secret_js


def test_managed_ldap_generates_complete_synthetic_directory_once(client):
    """Verify that managed ldap generates complete synthetic directory once.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        LdapGroup,
        LdapOrganization,
        LdapSettings,
        LdapUser,
    )
    from atlaso.app.services.ldap import (
        clear_pending_ldap_password,
        has_pending_ldap_password,
    )

    login(client)
    page = client.get("/ldap")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/ldap/organizations",
        data={
            "name": "Synthetic Org",
            "slug": "synthetic",
            "suffix_dn": "",
            "enabled": "on",
            "csrf": csrf,
        },
    )
    organization_id = int(
        created.text.split("/ldap/organizations/", 1)[1].split("/", 1)[0]
    )

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
    assert (
        "Save the one-time CSV, then submit the Managed LDAP appliance change"
        in generated.text
    )
    assert "Generate test directory" in generated.text
    assert "data-ldap-generate-auto-open" in generated.text
    generator_modal = generated.text.split('<dialog id="ldap-generate-modal"', 1)[
        1
    ].split("</dialog>", 1)[0]
    assert "uid,password,display_name,email,telephone" in generator_modal
    assert 'class="language-csv" data-ldap-generated-credentials' in generator_modal
    assert (
        'data-download-filename="ldap-test-directory-synthetic.csv"' in generator_modal
    )
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
    managed_ldap_modal = generated.text.split('<dialog id="vcf-ldap-modal"', 1)[
        1
    ].split("</dialog>", 1)[0]
    assert "uid,password,display_name,email,telephone" not in managed_ldap_modal
    app_js = client.get("/static/app.js").text
    assert 'generateDialog.addEventListener("close", clearGeneratedResult)' in app_js
    assert 'generateDialog.querySelectorAll("[data-ldap-generated-result]")' in app_js
    assert (
        'window.history.replaceState(window.history.state, "", managementUiPath("/vcf-helper"))'
        in app_js
    )
    assert 'generateDialog.querySelector("[data-ldap-generate-user-count]")' in app_js

    with SessionLocal() as db:
        organization = db.get(LdapOrganization, organization_id)
        users = (
            db.execute(
                select(LdapUser).where(LdapUser.organization_id == organization_id)
            )
            .scalars()
            .all()
        )
        groups = (
            db.execute(
                select(LdapGroup).where(LdapGroup.organization_id == organization_id)
            )
            .scalars()
            .all()
        )
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "generate_ldap_directory")
        ).scalar_one()
        assert organization is not None
        assert len(users) == 6
        assert len(groups) == 3
        assert all(
            user.given_name
            and user.surname
            and user.display_name
            and user.email
            and user.telephone
            for user in users
        )
        assert all(user.password_status == "pending_apply" for user in users)
        assert all(group.description and group.members for group in groups)
        assert event.detail == "users=6; groups=3"
        assert "Aa1!" not in event.detail

    refreshed = client.get(f"/ldap?organization_id={organization_id}")
    assert "uid\tpassword\tdisplay name\temail\ttelephone" not in refreshed.text

    with SessionLocal() as db:
        users = (
            db.execute(
                select(LdapUser).where(LdapUser.organization_id == organization_id)
            )
            .scalars()
            .all()
        )
        for user in users:
            clear_pending_ldap_password(user)
        db.commit()

    helper = client.get(f"/vcf-helper?ldap_organization_id={organization_id}")
    assert "Recover missing passwords (6)" in helper.text
    assert (
        "Generates replacement passwords for enabled users whose one-time passwords are no longer staged"
        in helper.text
    )
    helper_modal = helper.text.split('<dialog id="ldap-generate-modal"', 1)[1].split(
        "</dialog>", 1
    )[0]
    assert "Cancel" in helper_modal
    assert "Generate directory entries" in helper_modal
    assert "Done" not in helper_modal
    modal_css = client.get("/static/app.css").text
    assert "width: min(920px, calc(100vw - 32px));" in modal_css
    assert (
        "#ldap-generate-modal .confirm-modal-actions {\n  flex-wrap: nowrap;"
        in modal_css
    )
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
        users = (
            db.execute(
                select(LdapUser).where(LdapUser.organization_id == organization_id)
            )
            .scalars()
            .all()
        )
        event = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "stage_missing_ldap_passwords"
            )
        ).scalar_one()
        assert all(has_pending_ldap_password(user) for user in users)
        assert event.detail == "users=6"

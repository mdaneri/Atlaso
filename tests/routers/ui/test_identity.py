"""Test extracted identity-management UI transports."""

from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import LdapOrganization, OidcClient, OidcGroupMapping
from atlaso.app.services.oidc import (
    create_client,
    create_group_mapping,
    update_group_mapping,
)
from tests.routers.ui.helpers import login
from tests.test_oidc import _admin_headers, _configure_protocol_client


def test_identity_ui_router_owns_exact_transport_set():
    """Keep the bounded UI route set in the identity domain module."""
    from atlaso.app import ui

    assert {
        (route.path, tuple(sorted(route.methods or ())), route.name)
        for route in ui.identity_router.routes
    } == {
        ("/ui/management/authentication", ("GET",), "authentication"),
        ("/ui/management/openid-connect", ("GET",), "openid_connect"),
        (
            "/ui/management/authentication/oidc/provider",
            ("POST",),
            "update_oidc_provider_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/clients",
            ("POST",),
            "create_oidc_client_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/clients/{client_record_id}/edit",
            ("POST",),
            "update_oidc_client_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/clients/{client_record_id}/integration-export",
            ("GET",),
            "export_oidc_client_integration_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/group-mappings",
            ("POST",),
            "create_oidc_group_mapping_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/group-mappings/{mapping_id}/edit",
            ("POST",),
            "update_oidc_group_mapping_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/group-mappings/{mapping_id}/delete",
            ("POST",),
            "delete_oidc_group_mapping_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/clients/{client_record_id}/rotate-secret",
            ("POST",),
            "rotate_oidc_client_secret_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/clients/{client_record_id}/delete",
            ("POST",),
            "delete_oidc_client_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/signing-keys",
            ("POST",),
            "create_oidc_signing_key_from_ui",
        ),
        (
            "/ui/management/authentication/oidc/signing-keys/{key_id}/delete",
            ("POST",),
            "delete_retired_oidc_signing_key_from_ui",
        ),
        ("/ui/management/authentication/api-tokens", ("POST",), "create_token_from_ui"),
        (
            "/ui/management/authentication/api-tokens/{token_id}/revoke",
            ("POST",),
            "revoke_token_from_ui",
        ),
        ("/ui/management/users", ("GET",), "users_page"),
        ("/ui/management/users/status", ("GET",), "users_status"),
        (
            "/ui/management/users/password-policy",
            ("POST",),
            "update_users_password_policy",
        ),
        ("/ui/management/users", ("POST",), "create_user_from_ui"),
        ("/ui/management/users/{user_id}/edit", ("POST",), "update_user_from_ui"),
        ("/ui/management/users/{user_id}/disable", ("POST",), "disable_user_from_ui"),
        (
            "/ui/management/users/{user_id}/unlock",
            ("POST",),
            "request_user_os_unlock_from_ui",
        ),
        ("/ui/management/users/{user_id}/delete", ("POST",), "delete_user_from_ui"),
        (
            "/ui/management/users/{user_id}/password",
            ("POST",),
            "reset_user_password_from_ui",
        ),
        ("/ui/management/ldap-users", ("GET",), "legacy_ldap_users_redirect"),
    }


def test_api_token_create_and_revoke_ui(client):
    """Verify that api token create and revoke ui.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/authentication")
    token_wizard = page.text.split('id="api-token-dialog"', 1)[1].split("</dialog>", 1)[
        0
    ]
    token_identity = token_wizard.split('data-atlaso-wizard-step="identity"', 1)[
        1
    ].split("</section>", 1)[0]
    assert '<textarea name="description" rows="3" maxlength="1000">' in token_identity
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/authentication/api-tokens",
        data={
            "name": "UI token",
            "description": "test",
            "scopes": "read:dashboard",
            "csrf": csrf,
        },
    )
    assert created.status_code == 200
    assert "Copy this bearer token now" in created.text
    assert "UI token" in created.text


def test_local_users_page_separates_ldap_authentication(client):
    """Verify that local users page separates ldap authentication.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    authentication = client.get("/authentication")
    assert authentication.status_code == 200
    assert "Atlaso LDAP sign-in" in authentication.text
    assert "Managed VCF LDAP service" in authentication.text
    assert "managed separately" in authentication.text

    legacy = client.get("/ldap-users", follow_redirects=False)
    assert legacy.status_code == 307
    assert legacy.headers["location"] == "/ui/management/ldap-users"

    users = client.get("/users")
    assert users.status_code == 200
    assert "Local Users" in users.text
    assert "Managed VCF directory users remain isolated" in users.text
    assert "users-table" in users.text
    assert 'id="user-account-dialog"' in users.text
    assert "data-user-account-form" in users.text
    assert "data-atlaso-resource-review" in users.text
    user_wizard = users.text.split('id="user-account-dialog"', 1)[1].split(
        "</dialog>", 1
    )[0]
    user_identity = user_wizard.split('data-atlaso-wizard-step="identity"', 1)[1].split(
        "</section>", 1
    )[0]
    assert '<textarea name="description" rows="3" maxlength="1000">' in user_identity
    assert "user-password-modal" in users.text
    assert "data-password-toggle" in users.text
    assert "Password Reset" not in users.text
    assert "Set Photon OS password and enable user" in users.text
    assert "Reset Photon OS password" in users.text
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
        data={
            "username": "operator",
            "description": "Lab operator",
            "role": "viewer",
            "shell": "/bin/bash",
            "web_terminal_access": "true",
            "csrf": csrf,
        },
        follow_redirects=True,
    )
    assert created.status_code == 200
    assert "operator" in created.text
    assert "/bin/bash" in created.text
    assert "allowed" in created.text
    assert "disabled" in created.text
    multi_role_created = client.post(
        "/users",
        data={
            "username": "multi-role",
            "roles": ["service-admin", "certificate-operator"],
            "shell": "/sbin/nologin",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert multi_role_created.status_code == 303
    wizard_created = client.post(
        "/users",
        data={
            "username": "wizard-user",
            "roles": ["viewer"],
            "shell": "/bin/bash",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert wizard_created.status_code == 200
    assert wizard_created.json()["user"]["username"] == "wizard-user"
    assert wizard_created.json()["user"]["roles"] == ["viewer"]
    wizard_user_id = wizard_created.json()["user"]["id"]
    wizard_deleted = client.post(
        f"/users/{wizard_user_id}/delete",
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1"},
    )
    assert wizard_deleted.status_code == 204
    stale_role_created = client.post(
        "/users",
        data={
            "username": "demote-me",
            "role": "viewer",
            "roles": "admin",
            "shell": "/sbin/nologin",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert stale_role_created.status_code == 303
    from sqlalchemy import select

    from atlaso.app.models import User

    with SessionLocal() as db:
        operator = db.execute(
            select(User).where(User.username == "operator")
        ).scalar_one()
        assert operator.description == "Lab operator"
        assert operator.web_terminal_access is True
        multi_role_user = db.execute(
            select(User).where(User.username == "multi-role")
        ).scalar_one()
        assert multi_role_user.roles_json == '["service-admin", "certificate-operator"]'
        demote_user = db.execute(
            select(User).where(User.username == "demote-me")
        ).scalar_one()
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
        demote_user = db.execute(
            select(User).where(User.username == "demote-me")
        ).scalar_one()
        assert demote_user.roles_json == '["viewer"]'
    app_js = client.get("/static/app.js")
    assert app_js.status_code == 200
    assert "userActionsFormatter" not in app_js.text
    assert "formatter: userActionsFormatter" not in app_js.text
    assert "openUserPasswordModal" in app_js.text
    assert (
        'row.getData().enabled ? "Reset Photon OS password" : "Set Photon OS password and enable user"'
        in app_js.text
    )
    assert 'enabled: button.dataset.userEnabled === "true"' in app_js.text
    assert "deleteUserFromMenu" not in app_js.text
    assert "Unlock OS account" in app_js.text
    assert "disableUserFromMenu" in app_js.text
    assert "Disable user" in app_js.text
    assert "function initializePasswordToggles(container)" in app_js.text
    assert "function resetPasswordVisibility(container)" in app_js.text
    users_table_js = app_js.text.split("function initializeUsersTable()", 1)[1].split(
        "function initializeUserPasswordForm()", 1
    )[0]
    assert "initializeAtlasoResourceWizard({" in users_table_js
    assert 'height: "100%"' in users_table_js
    assert "initializePasswordToggles(accountForm)" not in users_table_js
    password_form_js = app_js.text.split("function initializeUserPasswordForm()", 1)[
        1
    ].split("function updateCaSettingsPreview", 1)[0]
    assert "initializePasswordToggles(form)" in password_form_js
    assert "resetPasswordVisibility(form)" not in users_table_js
    assert "form.dataset.osPasswordAvailable" not in users_table_js
    assert 'dialogId: "user-account-dialog"' in users_table_js
    assert 'resourceName: "user"' in users_table_js
    assert "editor:" not in users_table_js
    assert "cellEdited:" not in users_table_js
    assert "Select at least one Atlaso role." in users_table_js
    assert "Web SSH access requires an interactive Photon shell." in users_table_js
    assert '{ id: "password"' not in users_table_js
    assert '{ id: "enablement"' not in users_table_js
    enabled_column_js = users_table_js.split('title: "Enabled"', 1)[1].split(
        'title: "OS account"', 1
    )[0]
    assert "editor:" not in enabled_column_js
    assert "validatePasswordMatch" in app_js.text
    assert "initializeNonTabbableHelperControls" in app_js.text
    assert '".help-icon, .password-toggle"' in app_js.text
    assert 'control.setAttribute("tabindex", "-1")' in app_js.text
    assert 'field: "shell"' in app_js.text
    assert 'field: "web_terminal_access"' in app_js.text
    assert 'title: "Web SSH"' in app_js.text
    assert "Temp Password" not in app_js.text
    apply_refresh_js = app_js.text.split(
        "async function refreshUsersAfterApplianceApply", 1
    )[1].split("async function submitApplianceApplyForm", 1)[0]
    assert 'window.location.pathname !== managementUiPath("/users")' in apply_refresh_js
    assert 'selectedUnits.includes("local_users")' in apply_refresh_js
    assert 'fetch(managementUiPath("/users/status")' in apply_refresh_js
    assert (
        "await table.replaceData([...payload.users, newUserRow()])" in apply_refresh_js
    )
    assert 'task?.status !== "succeeded"' in apply_refresh_js
    app_css = client.get("/static/app.css").text
    assert ".users-main-panel {" in app_css
    assert "height: calc(100vh - 144px);" in app_css
    assert ".users-grid {" in app_css
    assert "flex: 1 1 0;" in app_css


def test_local_users_status_returns_current_uncached_grid_rows(
    client, monkeypatch, tmp_path
):
    """Verify that local users status returns current uncached grid rows.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import atlaso.app.ui as ui
    from atlaso.app.adapters.system import AdapterResult

    class StatusAdapter:
        """Return a current Photon account state for the refresh endpoint."""

        dry_run = False

        def local_users_status(self, config_path: str) -> AdapterResult:
            """Return one current Photon account status row.

            Args:
                config_path: Short-lived status input path.
            """
            return AdapterResult(
                command=["atlaso-helper", "local-users", "status", config_path],
                dry_run=False,
                stdout='{"local_users":"status ok","users":[{"username":"admin","state":"present","detail":"password set"}]}',
            )

    monkeypatch.setattr(
        ui,
        "LOCAL_USERS_STAGED_CONFIG_PATH",
        str(tmp_path / "local-users" / "atlaso-users.json"),
    )
    monkeypatch.setattr(ui, "SystemAdapter", StatusAdapter)
    login(client)

    response = client.get("/users/status")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    rows = response.json()["users"]
    admin = next(row for row in rows if row["username"] == "admin")
    assert admin["os_account_state"] == "present"
    assert admin["os_account_detail"] == "password set"
    assert "/users/status" not in client.get("/openapi.json").json()["paths"]


def test_local_user_reset_modal_endpoint_and_remove(client):
    """Verify that local user reset modal endpoint and remove.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json

    from sqlalchemy import select

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
        data={
            "password": "New-temporary1!",
            "confirm_password": "New-temporary1!",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert reset.status_code in {200, 303}

    with SessionLocal() as db:
        enabled_user = db.execute(
            select(User).where(User.username == "remove-me")
        ).scalar_one()
        assert enabled_user.enabled is True

    disabled = client.post(f"/users/{user_id}/disable", data={"csrf": csrf})
    assert disabled.status_code == 200
    with SessionLocal() as db:
        disabled_user = db.execute(
            select(User).where(User.username == "remove-me")
        ).scalar_one()
        assert disabled_user.enabled is False
        assert disabled_user.os_sync_status == "pending"

    reset = client.post(
        f"/users/{user_id}/password",
        data={
            "password": "New-temporary1!",
            "confirm_password": "New-temporary1!",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert reset.status_code in {200, 303}

    unlock = client.post(f"/users/{user_id}/unlock", data={"csrf": csrf})
    assert unlock.status_code == 200
    with SessionLocal() as db:
        staged_user = db.execute(
            select(User).where(User.username == "remove-me")
        ).scalar_one()
        assert staged_user.os_unlock_requested_at is not None
        assert staged_user.os_sync_status == "pending"
    review = client.get("/appliance-apply/review")
    local_users_unit = next(
        unit for unit in review.json()["units"] if unit["id"] == "local_users"
    )
    assert "1 unlock requests" in " ".join(local_users_unit["summary"])

    deleted = client.post(
        f"/users/{user_id}/delete", data={"csrf": csrf}, follow_redirects=False
    )
    assert deleted.status_code == 303
    refreshed = client.get("/users")
    assert "remove-me" not in refreshed.text


def test_local_user_wizard_creates_disabled_account_then_password_flow_enables_it(
    client,
):
    """Verify that local user wizard creates disabled account then password flow enables it.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.models import User
    from atlaso.app.services.local_users import has_pending_os_password

    login(client)
    users = client.get("/users")
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/users",
        data={
            "username": "wizard-disabled",
            "roles": ["viewer"],
            "shell": "/bin/bash",
            "enabled_present": "1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert created.status_code == 200, created.text
    assert created.json()["user"]["enabled"] is False
    assert created.json()["user"]["os_password_available"] is False
    user_id = created.json()["user"]["id"]
    with SessionLocal() as db:
        user = db.execute(
            select(User).where(User.username == "wizard-disabled")
        ).scalar_one()
        assert user.enabled is False
        assert not has_pending_os_password(user)

    staged = client.post(
        f"/users/{user_id}/password",
        data={
            "password": "Strong-wizard1!",
            "confirm_password": "Strong-wizard1!",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert staged.status_code == 303
    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert user.enabled is True
        assert has_pending_os_password(user)


def test_existing_local_user_can_be_enabled_inline_after_password_apply(client):
    """Verify that existing local user can be enabled inline after password apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from datetime import UTC, datetime

    from atlaso.app.models import User
    from atlaso.app.services.local_users import has_pending_os_password

    login(client)
    users = client.get("/users")
    csrf = users.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    created = client.post(
        "/users",
        data={
            "username": "inline-enabled",
            "roles": ["viewer"],
            "shell": "/sbin/nologin",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert created.status_code == 200
    user_id = created.json()["user"]["id"]
    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        user.os_password_applied_at = datetime.now(UTC)
        db.add(user)
        db.commit()

    enabled = client.post(
        f"/users/{user_id}/edit",
        data={
            "username": "inline-enabled",
            "roles": ["viewer"],
            "roles_text": "viewer",
            "shell": "/sbin/nologin",
            "enabled": "on",
            "enabled_present": "1",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Grid": "1"},
    )

    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["user"]["enabled"] is True
    assert enabled.json()["user"]["os_password_available"] is True
    with SessionLocal() as db:
        user = db.get(User, user_id)
        assert user is not None
        assert user.enabled is True
        assert not has_pending_os_password(user)


def test_local_users_password_policy_staging_and_apply_redaction(client):
    """Verify that local users password policy staging and apply redaction.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

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

    rows = json.loads(
        html.unescape(users.text.split("data-users='", 1)[1].split("'", 1)[0])
    )
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
    local_users_unit = next(
        unit for unit in review.json()["units"] if unit["id"] == "local_users"
    )
    assert local_users_unit["label"] == "Local Users"
    assert "pending OS passwords" in " ".join(local_users_unit["summary"])
    assert plaintext not in review.text

    csrf = apply_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    applied = client.post(
        "/appliance-apply", data={"csrf": csrf, "selected_units": "local_users"}
    )
    assert applied.status_code == 200
    assert plaintext not in applied.text

    with SessionLocal() as db:
        job = (
            db.execute(
                select(Job)
                .where(Job.type == "appliance-apply")
                .order_by(Job.created_at.desc())
            )
            .scalars()
            .first()
        )
        assert job is not None
        assert "local-users" in (job.result or "")
        assert plaintext not in (job.result or "")
        user = db.execute(select(User).where(User.username == "sync-me")).scalar_one()
        assert not hasattr(user, "pending_os_password_encrypted")


def test_openid_connect_page_exposes_authorization_code_oidc_ui(client):
    """Verify that openid connect page exposes authorization code oidc ui.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login = client.get("/login")
    csrf = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    authentication_page = client.get("/authentication")
    assert authentication_page.status_code == 200
    assert 'href="/ui/management/openid-connect"' in authentication_page.text
    assert 'id="oidc-provider"' not in authentication_page.text

    page = client.get("/openid-connect")
    assert page.status_code == 200
    assert "OpenID Connect Provider" in page.text
    assert "<h1>OpenID Connect</h1>" in page.text
    assert 'aria-label="OpenID Connect administration"' in page.text
    assert page.text.count('class="tab-button') >= 5
    assert 'id="oidc-group-mappings-table"' in page.text
    assert 'data-fallback-id="oidc-group-mappings-fallback"' in page.text
    assert (
        'class="split-workspace service-settings-workspace oidc-service-workspace"'
        in page.text
    )
    assert 'class="panel wide-panel oidc-administration-panel"' in page.text
    assert 'class="tab-buttons tool-tabs oidc-page-tabs"' in page.text
    assert 'class="tab-panel active" id="oidc-provider"' in page.text
    assert '<aside class="side-stack service-settings-column">' in page.text
    assert page.text.index('class="tab-panels oidc-page-panels"') < page.text.index(
        '<aside class="side-stack service-settings-column">'
    )
    assert "<h2>Issuer DNS</h2>" in page.text
    assert "the only supported issuer host" in page.text
    assert "<span>Listener interfaces</span>" in page.text
    assert 'name="hostname"' in page.text
    assert "oidc.atlaso.internal" in page.text
    assert 'data-tag-name="listen_interfaces"' in page.text
    assert "<span>HTTPS port</span>" in page.text
    assert 'name="port"' in page.text
    assert page.text.count("data-copy-value=") >= 7
    assert 'class="scope-choice-grid"' in page.text
    assert page.text.count('class="scope-choice"') == 4
    assert '<span class="scope-choice-badge">required</span>' in page.text
    assert 'data-atlaso-wizard-nav="state"' in page.text
    assert 'data-atlaso-wizard-step="state"' in page.text
    assert "<h2>Validation</h2>" in page.text
    assert "data-oidc-provider-validation" in page.text
    assert "data-oidc-provider-validation-status" in page.text
    assert "Public services nginx config" in page.text
    assert (
        "/var/lib/atlaso/apply/public-services/atlaso-public-services.conf" in page.text
    )
    assert "data-oidc-config-preview" in page.text
    assert "OIDC HTTPS front door." in page.text
    assert "Exact post-logout URIs (optional)" in page.text
    assert "<noscript>" in page.text
    assert (
        "server-rendered client, signing-key, mapping, and subject tables remain readable"
        in page.text
    )
    assert 'id="oidc-clients-table"' in page.text
    oidc_client_wizard = page.text.split('id="oidc-client-dialog"', 1)[1].split(
        "</dialog>", 1
    )[0]
    oidc_identity = oidc_client_wizard.split('data-atlaso-wizard-step="identity"', 1)[
        1
    ].split("</section>", 1)[0]
    assert '<textarea name="description" rows="3" maxlength="1000">' in oidc_identity
    assert 'id="oidc-keys-table"' in page.text
    assert 'id="oidc-subjects-table"' in page.text
    assert page.text.count("data-atlaso-wizard") >= 2
    assert page.text.count("vcf-sddc-wizard-rail") >= 2
    assert "vcf-sddc-wizard-shell" not in page.text
    assert "Atlaso never guesses" in page.text
    assert "+ Add client here" in page.text
    assert "Register client" not in page.text
    assert 'name="enabled"' in page.text
    assert 'data-autosave-status-id="oidc-provider-autosave-status"' in page.text
    assert page.text.count('class="help-icon"') >= 10
    assert (
        "Rotate signing key" in page.text or "Generate first signing key" in page.text
    )
    javascript = client.get("/static/app.js").text
    assert (
        "Client changes are unavailable because the interactive grid could not initialize."
        in javascript
    )
    assert (
        "Signing-key changes are unavailable because the interactive grid could not initialize."
        in javascript
    )
    assert javascript.count('launcher.setAttribute("aria-disabled", "true")') >= 2
    assert "At least one exact redirect URI is required." in javascript
    assert "is not a valid absolute URI." in javascript


def test_authentication_ui_deletes_bound_client_before_ldap_organization(client):
    """Verify that authentication ui deletes bound client before ldap organization.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """

    with SessionLocal() as db:
        organization = LdapOrganization(
            name="Bound organization",
            slug="bound-organization",
            suffix_dn="dc=bound-organization,dc=example,dc=test",
            enabled=True,
        )
        db.add(organization)
        db.flush()
        client_row, _secret = create_client(
            db,
            name="Bound VCF client",
            organization_id=organization.id,
            redirect_uris=["https://vcf.example.test/identity/callback"],
            post_logout_redirect_uris=[],
            allowed_scopes=["openid", "profile", "email", "groups"],
            allow_loopback_redirects=False,
            access_token_lifetime_seconds=300,
            id_token_lifetime_seconds=300,
            authorization_code_lifetime_seconds=60,
            enabled=True,
        )
        organization_id = organization.id
        client_record_id = client_row.id
        db.commit()

    login = client.get("/login")
    csrf = login.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    page = client.get("/openid-connect")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    assert '"name": "Bound VCF client"' in page.text
    assert 'data-fallback-id="oidc-clients-fallback"' in page.text

    deleted = client.post(
        f"/authentication/oidc/clients/{client_record_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/ui/management/openid-connect#oidc-clients"
    organization_deleted = client.post(
        f"/ldap/organizations/{organization_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert organization_deleted.status_code == 303

    with SessionLocal() as db:
        assert db.get(OidcClient, client_record_id) is None
        assert db.get(LdapOrganization, organization_id) is None


def test_group_mapping_delete_rejects_a_revealed_effective_name_collision(client):
    """Verify that group mapping delete rejects a revealed effective name collision.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """

    client_id, _secret = _configure_protocol_client()
    headers = _admin_headers(client)
    with SessionLocal() as db:
        client_row = db.execute(
            select(OidcClient).where(OidcClient.client_id == client_id)
        ).scalar_one()
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=None,
            external_group_name="Default Admin",
        )
        create_group_mapping(
            db,
            source_type="local_role",
            local_role="viewer",
            ldap_group_id=None,
            oidc_client_id=None,
            external_group_name="Default Viewer",
        )
        admin_override = create_group_mapping(
            db,
            source_type="local_role",
            local_role="admin",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Temporary Admin",
        )
        viewer_override = create_group_mapping(
            db,
            source_type="local_role",
            local_role="viewer",
            ldap_group_id=None,
            oidc_client_id=client_row.id,
            external_group_name="Client Viewer",
        )
        update_group_mapping(
            db,
            row=admin_override,
            oidc_client_id=client_row.id,
            external_group_name="Default Viewer",
        )
        viewer_override_id = viewer_override.id
        db.commit()

    api_delete = client.delete(
        f"/api/v1/oidc/group-mappings/{viewer_override_id}",
        headers=headers,
    )
    assert api_delete.status_code == 422
    assert "not valid in its effective context" in api_delete.json()["detail"]
    with SessionLocal() as db:
        assert db.get(OidcGroupMapping, viewer_override_id) is not None

    login_page = client.get("/login")
    csrf = login_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    signed_in = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert signed_in.status_code == 303
    authentication_page = client.get("/authentication")
    csrf = authentication_page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    ui_delete = client.post(
        f"/authentication/oidc/group-mappings/{viewer_override_id}/delete",
        data={"csrf": csrf},
        headers={"X-Atlaso-Grid": "1"},
        follow_redirects=False,
    )
    assert ui_delete.status_code == 422
    assert "duplicate effective external group names" in ui_delete.json()["detail"]
    with SessionLocal() as db:
        assert db.get(OidcGroupMapping, viewer_override_id) is not None

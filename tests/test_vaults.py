import json
from pathlib import Path

import pytest
from sqlalchemy import select


def login(client):
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def csrf_from_page(text: str) -> str:
    return text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_vault_ui_encrypts_masks_and_explicitly_reveals_password(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Vault, VaultEntry

    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    created = client.post(
        "/vaults",
        data={"csrf": csrf, "name": "Management", "description": "VCF management passwords"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        vault = db.execute(select(Vault).where(Vault.name == "Management")).scalar_one()
        vault_id = vault.id
    entry_response = client.post(
        f"/vaults/{vault_id}/entries",
        data={
            "csrf": csrf,
            "key": "vcf.sddc_manager.admin",
            "description": "SDDC Manager administrator",
            "value": "Correct-Horse-Battery-Staple!",
            "username": "administrator@vsphere.local",
            "resource_name": "sddc-manager.example.internal",
            "uris_json": json.dumps(
                [
                    "https://sddc-manager.example.internal",
                    "ssh://sddc-manager.example.internal:22",
                ]
            ),
        },
        follow_redirects=False,
    )
    assert entry_response.status_code == 303
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        entry_id = entry.id
        assert entry.encrypted_value.startswith("fernet:v1:")
        assert "Correct-Horse" not in entry.encrypted_value
        assert entry.description == "SDDC Manager administrator"
        assert entry.secret_type == "vcf_password"
        assert json.loads(entry.uris_json) == [
            "https://sddc-manager.example.internal",
            "ssh://sddc-manager.example.internal:22",
        ]

    page = client.get("/vaults")
    assert page.status_code == 200
    assert "Correct-Horse-Battery-Staple!" not in page.text
    assert "SDDC Manager administrator" in page.text
    reveal = client.post(
        f"/vaults/{vault_id}/entries/{entry_id}/reveal",
        data={"csrf": csrf},
    )
    assert reveal.status_code == 200
    assert reveal.json() == {"value": "Correct-Horse-Battery-Staple!"}
    assert "no-store" in reveal.headers["cache-control"]
    with SessionLocal() as db:
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "reveal_vault_entry")
        ).scalar_one()
        assert "Correct-Horse-Battery-Staple!" not in (event.detail or "")


def test_vault_ui_copies_entry_without_returning_plaintext(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Vault, VaultEntry
    from atlaso.app.secrets import decrypt_secret

    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    created = client.post(
        "/vaults",
        data={"csrf": csrf, "name": "Copy source", "description": ""},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        vault = db.execute(select(Vault).where(Vault.name == "Copy source")).scalar_one()
        vault_id = vault.id

    source_response = client.post(
        f"/vaults/{vault_id}/entries",
        data={
            "csrf": csrf,
            "key": "vcf.source.admin",
            "description": "Source credential",
            "value": "Copy-Me-Server-Side!",
            "username": "administrator",
            "uris_json": '["https://vcf.example.internal"]',
        },
        follow_redirects=False,
    )
    assert source_response.status_code == 303
    with SessionLocal() as db:
        source = db.execute(select(VaultEntry).where(VaultEntry.key == "vcf.source.admin")).scalar_one()
        source_id = source.id
        source_ciphertext = source.encrypted_value

    copied_response = client.post(
        f"/vaults/{vault_id}/entries",
        data={
            "csrf": csrf,
            "copy_entry_id": source_id,
            "key": "vcf.source.admin.copy",
            "description": "Copied credential",
            "username": "administrator",
            "uris_json": '["https://copy.example.internal"]',
        },
        follow_redirects=False,
    )
    assert copied_response.status_code == 303
    assert "Copy-Me-Server-Side!" not in copied_response.text

    with SessionLocal() as db:
        copied = db.execute(select(VaultEntry).where(VaultEntry.key == "vcf.source.admin.copy")).scalar_one()
        assert copied.encrypted_value != source_ciphertext
        assert decrypt_secret(copied.encrypted_value) == "Copy-Me-Server-Side!"
        assert copied.username == "administrator"
        assert json.loads(copied.uris_json) == ["https://copy.example.internal"]
        event = db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "create_vault_entry",
                AuditEvent.resource_id == str(copied.id),
            )
        ).scalar_one()
        assert f"copied_from_entry_id={source_id}" in (event.detail or "")
        assert "Copy-Me-Server-Side!" not in (event.detail or "")


def test_vault_service_rejects_unsupported_types(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    with SessionLocal() as db:
        vault = Vault(name="Restricted", description="", created_by="admin")
        db.add(vault)
        db.flush()
        with pytest.raises(ValueError, match="limited to VCF passwords and ESX passwords"):
            upsert_vault_entry(
                db,
                vault=vault,
                entry=VaultEntryInput(
                    key="generic.token",
                    secret_type="api_token",
                    value="not-allowed",
                ),
                actor="admin",
            )


@pytest.mark.parametrize(
    ("uris", "message"),
    [
        (("ftp://vcf.example.internal",), "http, https, ssh, or sftp"),
        (("https://admin:secret@vcf.example.internal",), "must not contain credentials"),
        (("ssh://vcf example.internal",), "contain no whitespace"),
        (tuple(f"https://vcf-{index}.example.internal" for index in range(10)), "at most 9"),
    ],
)
def test_vault_uri_validation_rejects_unsupported_or_unsafe_values(uris, message):
    from atlaso.app.services.vaults import normalize_vault_uris

    with pytest.raises(ValueError, match=message):
        normalize_vault_uris(uris)


def test_vault_cli_fails_closed_and_reads_only_scoped_credential(tmp_path, monkeypatch, capsys):
    from atlaso.app import vault_cli

    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setattr("sys.argv", ["atlaso-vault", "get", "--key", "esx.host.root"])
    assert vault_cli.main() == 2
    assert "only inside a scoped managed-script run" in capsys.readouterr().err

    credentials = tmp_path / "credentials"
    credentials.mkdir()
    (credentials / "atlaso-vault").write_text(
        json.dumps({"version": 1, "values": {"esx.host.root": "VMware1!"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credentials))
    assert vault_cli.main() == 0
    assert capsys.readouterr().out == "VMware1!"


def test_dynamic_kickstart_derives_exact_vault_scope_without_caching(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, EsxiKickstartVaultBinding, EsxiPxeHost, Vault
    from atlaso.app.services.esxi_pxe import content_hash
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    content = (
        "vmaccepteula\n"
        "network --hostname={{vault.esx.esx.host.root.username}}\n"
        "rootpw {{vault.esx.esx.host.root.password}}\n"
        "%include {{vault.esx.esx.host.root.uri1}}\n"
    )
    with SessionLocal() as db:
        vault = Vault(name="ESX", description="", created_by="admin")
        db.add(vault)
        db.flush()
        upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="esx.host.root",
                description="ESX root",
                secret_type="esx_password",
                username="root",
                value="VMware1!",
                uris=("https://config.example.internal/esx01.cfg",),
            ),
            actor="admin",
        )
        legacy_vault = Vault(name="Legacy Ignored", description="", created_by="admin")
        db.add(legacy_vault)
        db.flush()
        kickstart = EsxiKickstart(
            name="Vaulted ESX",
            content=content,
            content_hash=content_hash(content),
            enabled=True,
        )
        db.add(kickstart)
        db.flush()
        db.add(EsxiKickstartVaultBinding(kickstart_id=kickstart.id, vault_id=legacy_vault.id))
        db.add(
            EsxiPxeHost(
                hostname="esx01",
                mac_address="00:50:56:aa:bb:cc",
                kickstart_id=kickstart.id,
                enabled=True,
            )
        )
        db.commit()
        path = f"/pxe/esxi/ks/{kickstart.content_hash[:12]}.cfg?mac=005056aabbcc"

    login(client)
    editor_page = client.get("/esxi-pxe")
    assert "vault.esx.esx.host.root.username" in editor_page.text
    assert "vault.esx.esx.host.root.password" in editor_page.text
    assert "vault.esx.esx.host.root.uri1" in editor_page.text
    assert "VMware1!" not in editor_page.text

    response = client.get(path)
    assert response.status_code == 200
    assert "network --hostname=root" in response.text
    assert "rootpw VMware1!" in response.text
    assert "%include https://config.example.internal/esx01.cfg" in response.text
    assert "{{vault." not in response.text
    assert "no-store" in response.headers["cache-control"]

    with SessionLocal() as db:
        vault = db.execute(select(Vault).where(Vault.name == "ESX")).scalar_one()
        vault.name = "Renamed ESX"
        db.add(vault)
        db.commit()

    missing_at_request_time = client.get(path)
    assert missing_at_request_time.status_code == 400
    assert "vault.esx.esx.host.root.password" in missing_at_request_time.text
    assert "VMware1!" not in missing_at_request_time.text


@pytest.mark.parametrize(
    ("marker", "message"),
    [
        ("{{vault.missing.key.password}}", "is not available"),
        ("{{vault.missing.key.token}}", "is not available"),
        ("{{vault.missing.key.password", "unclosed"),
        ("vault.missing.key.password}}", "unmatched"),
    ],
)
def test_kickstart_save_rejects_missing_unsupported_and_malformed_vault_markers(client, marker, message):
    login(client)
    page = client.get("/esxi-pxe")
    csrf = csrf_from_page(page.text)
    response = client.post(
        "/esxi-pxe/kickstarts",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": f"Rejected {message}",
            "description": "",
            "content": f"vmaccepteula\nrootpw {marker}\n",
            "enabled": "on",
        },
    )
    assert response.status_code == 400
    assert message in response.json()["detail"]


def test_kickstart_completion_and_save_validate_metadata_without_decrypting(client, monkeypatch):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    with SessionLocal() as db:
        vault = Vault(name="No Browser Secret", description="", created_by="admin")
        db.add(vault)
        db.flush()
        upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="esx.root",
                secret_type="esx_password",
                value="Never-Decrypted-For-Editing!",
                username="root",
            ),
            actor="admin",
        )
        db.commit()

    import atlaso.app.services.vaults as vault_service

    monkeypatch.setattr(
        vault_service,
        "decrypt_secret",
        lambda *_args: pytest.fail("Editor completion and save validation must not decrypt vault values."),
    )
    login(client)
    page = client.get("/esxi-pxe")
    assert page.status_code == 200
    assert "vault.no_browser_secret.esx.root.password" in page.text
    assert "Never-Decrypted-For-Editing!" not in page.text
    csrf = csrf_from_page(page.text)
    saved = client.post(
        "/esxi-pxe/kickstarts",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": "Metadata only",
            "description": "",
            "content": "vmaccepteula\nrootpw {{vault.no_browser_secret.esx.root.password}}\n",
            "enabled": "on",
        },
    )
    assert saved.status_code == 200
    assert "Never-Decrypted-For-Editing!" not in saved.text


def test_vault_javascript_uses_shared_grid_wizard_and_timed_eye():
    source = Path("atlaso/app/static/app.js").read_text()
    css = Path("atlaso/app/static/app.css").read_text()
    base_template = Path("atlaso/app/templates/base.html").read_text()
    template = Path("atlaso/app/templates/vaults.html").read_text()
    assert "initializeVaultsPage" in source
    assert "AtlasoUiPatterns.createGrid" in source
    assert "AtlasoUiPatterns.createWizard" in source
    assert "data-vault-password-eye" in source
    assert 'title: "Username", field: "username"' in source
    assert 'title: "URI(s)"' in source
    assert 'class="vault-uri-cell"' in source
    assert '<button class="vault-password-eye"' in source
    assert "border: 0;" in css[css.index(".vault-password-eye {"):css.index(".vcf-vault-candidate-list")]
    assert '.vault-password-eye[data-revealed="true"]::after' in css
    assert 'entryPasswordEye.title = "Hide password";' in source
    assert "15000" in source
    assert 'rowContextMenu: (_event, component) =>' in source
    assert 'label: "Edit"' in source
    assert 'label: "Copy"' in source
    assert 'label: "Open"' in source
    assert "menu: uriActions" in source
    assert 'label: "Remove"' in source
    assert "if (row.is_new) return [];" in source
    assert "window.confirm" not in source[source.index("function initializeVaultsPage"):source.index("function initializeVcfVaultImport")]
    assert '<button class="button danger compact" type="button">Delete</button>' not in source
    tab_strip = template.split('<div class="tab-buttons zone-tabs"', 1)[1].split("</div>", 1)[0]
    panel_header = template.split('<div class="panel-head">', 1)[1].split(
        "{% if vault_error %}",
        1,
    )[0]
    assert "data-vault-create-open" in tab_strip
    assert 'aria-haspopup="dialog"' in tab_strip
    assert "data-vault-create-open" not in panel_header
    assert "Password type" not in template
    assert 'name="secret_type"' not in template
    assert "data-vault-entry-review-type" not in template
    assert "<span>Resource</span>" not in template
    assert 'name="resource_name"' not in template
    assert "entryForm.reportValidity()" not in source
    assert "<h3>{{ vault.name }}</h3>" not in template
    assert "vault-create-form-grid" in template
    assert "vault-entry-form-grid" in template
    assert 'data-atlaso-wizard-nav="uris"' in template
    assert "Step 1 of 4" in template
    assert "data-vault-uri-add" in template
    assert "data-confirm-modal" in template
    assert "data-confirm-title=\"Delete {{ vault.name }} vault?\"" in template
    assert 'data-fallback-id="vault-entries-fallback-{{ vault.id }}"' in template
    assert 'id="vault-entries-fallback-{{ vault.id }}"' in template
    assert "openVaultUri" in source
    assert "data-vault-uri-error" in template
    assert "Remote target unavailable" in source
    assert "data-vault-entry-password-eye" in template
    assert "copy_entry_id" in template
    assert "entryPassword.placeholder = copying" in source
    assert "The encrypted value will be copied." in source
    assert "/terminal/remote-launches" in source
    assert 'window.open("about:blank"' not in source
    assert "/terminal/remote#target=" in source
    assert "remoteWindow.location.replace" in source
    assert 'detailLabel: "SHA-256 fingerprint"' in source
    assert "detail: payload.fingerprint" in source
    assert 'id="confirm-modal-detail-group"' in base_template
    assert 'id="confirm-modal-detail-label"' in base_template
    assert 'id="confirm-modal-detail"' in base_template
    assert ".confirm-modal.has-confirm-detail" in css
    assert "overflow-wrap: anywhere;" in css[css.index(".confirm-modal-detail-group"):css.index(".confirm-modal.wide-modal")]
    assert "atlaso-monaco-kickstarts-20260729-1" in base_template
    trust_template = Path("atlaso/app/templates/partials/vcf_trust_modal.html").read_text()
    import_template = Path("atlaso/app/templates/partials/vcf_vault_import_modal.html").read_text()
    depot_template = Path("atlaso/app/templates/partials/vcf_target_depot_modal.html").read_text()
    assert 'name="snapshot_acknowledged"' not in trust_template
    assert trust_template.index("vcf_vault_credential_picker.html") < trust_template.index('data-vcf-trust-step="api"')
    assert import_template.index("vcf_vault_credential_picker.html") < import_template.index('data-atlaso-wizard-step="credentials"')
    assert depot_template.index("vcf_vault_credential_picker.html") < depot_template.index('data-vcf-target-depot-step="api"')
    assert 'data-atlaso-wizard-nav="credential"' in import_template
    assert "Step 1 of 6" in import_template
    assert 'data-atlaso-wizard-nav="tls"' in import_template
    assert "data-vcf-vault-fingerprint-confirm" in import_template
    assert "<span>Server address</span>" in import_template
    assert 'data-atlaso-wizard-nav="credential"' in trust_template
    assert "Step 1 of 5" in trust_template
    assert 'data-atlaso-wizard-nav="tls"' in trust_template
    assert "data-vcf-trust-tls-confirmation" in trust_template
    assert "<span>Server address</span>" in trust_template
    assert 'data-atlaso-wizard-nav="credential"' in depot_template
    assert "Step 1 of 7" in depot_template
    assert 'data-atlaso-wizard-nav="tls"' in depot_template
    assert "addressControl.readOnly = true;" in source
    assert 'filter((uri) => /^https?:\\/\\//i.test(uri)).forEach((endpoint) =>' in source
    assert "option.dataset.endpoint = endpoint;" in source
    assert 'new Option("No HTTP/HTTPS credentials available", "")' in source
    assert 'picker.dataset.addressMode === "url"' in source
    assert "parsedEndpoint.hostname" in source
    assert "parsedEndpoint.host" in source
    assert 'data-address-mode="{{ credential_address_mode | default(\'server\') }}"' in Path(
        "atlaso/app/templates/partials/vcf_vault_credential_picker.html"
    ).read_text(encoding="utf-8")
    assert '{% set credential_address_mode = "url" %}' in Path(
        "atlaso/app/templates/partials/vcf_ldap_modal.html"
    ).read_text(encoding="utf-8")
    assert "hasSelectedVcfVaultCredential(form)" in source
    assert 'inspectTarget({ probeOnly: true })' in source
    assert 'return state === "ready" ? "review" : state === "tls" ? "tls" : false;' in source
    assert 'return state === "ready" ? "selection" : state === "tls" ? "tls" : false;' in source
    assert 'return hasSelectedVcfVaultCredential(form) ? "depot" : "api";' in source
    pxe_template = Path("atlaso/app/templates/esxi_pxe.html").read_text()
    assert "{{vault.<vaultname>.<key>.uri1}}" in pxe_template
    assert "{{vault.<vaultname>.<key>.uri9}}" in pxe_template


def test_vmware_wheel_deploy_exposes_fail_closed_vault_shell_commands():
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    assert 'ln -sfn "$venv/bin/atlaso-vault" /usr/local/bin/atlaso-vault' in deploy
    assert 'ln -sfn "$venv/bin/atlaso-vault" /usr/bin/atlaso-vault' in deploy
    assert "function global:Get-AtlasoVault" in deploy
    assert "/opt/atlaso/.venv/bin/atlaso-vault" in deploy
    assert "[switch]$ResetVaultEntries" in deploy
    assert "DROP TABLE IF EXISTS vault_entries" in deploy


def test_remote_vault_uri_launch_uses_one_use_server_side_ticket(client, monkeypatch):
    from types import SimpleNamespace
    from urllib.parse import parse_qs, urlsplit

    from sqlalchemy import select

    from atlaso.app import web_terminal
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, User, Vault
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    login(client)
    with SessionLocal() as db:
        vault = Vault(name="Remote", description="", created_by="admin")
        db.add(vault)
        db.flush()
        entry, _created = upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="vcf.remote.admin",
                secret_type="vcf_password",
                value="Not-In-The-Browser!",
                username="administrator",
                uris=("ssh://vcf.example.internal:2222",),
            ),
            actor="admin",
        )
        settings = db.execute(select(ApplianceSettings)).scalar_one()
        settings.management_https_enabled = True
        settings.web_terminal_enabled = True
        settings.web_terminal_interfaces_json = '["eth0"]'
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.web_terminal_access = True
        admin.shell = "/bin/bash"
        db.commit()
        vault_id = vault.id
        entry_id = entry.id
        admin_id = admin.id

    monkeypatch.setattr(web_terminal, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    monkeypatch.setattr(web_terminal, "_request_uses_selected_listener", lambda *_args: True)
    monkeypatch.setattr(web_terminal, "_request_is_https", lambda *_args: True)
    monkeypatch.setattr(web_terminal, "_helper_applied", lambda: True)
    monkeypatch.setattr(web_terminal, "_probe_remote_ssh_host", lambda *_args: "SHA256:test-fingerprint")
    monkeypatch.setattr(
        web_terminal,
        "decrypt_secret",
        lambda *_args: pytest.fail("The launch and browser ticket path must not decrypt the password."),
    )
    web_terminal._remote_launches.clear()

    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    launch_data = {
        "csrf": csrf,
        "vault_id": vault_id,
        "entry_id": entry_id,
        "uri_index": 1,
    }
    confirmation = client.post("/terminal/remote-launches", data=launch_data)
    assert confirmation.status_code == 409
    assert confirmation.json() == {
        "error_code": "SSH_HOST_KEY_CONFIRMATION_REQUIRED",
        "target": "vcf.example.internal:2222",
        "hostname": "vcf.example.internal",
        "fingerprint": "SHA256:test-fingerprint",
    }

    launched = client.post(
        "/terminal/remote-launches",
        data={**launch_data, "confirmed_fingerprint": "SHA256:test-fingerprint"},
    )
    assert launched.status_code == 200
    launch_url = launched.json()["url"]
    assert "Not-In-The-Browser!" not in launched.text
    launch_token = parse_qs(urlsplit(launch_url).fragment)["remote-launch"][0]
    assert urlsplit(launch_url).path == "/terminal/remote"
    assert launched.json()["target"] == "vcf.example.internal"

    terminal_page = client.get("/terminal")
    assert terminal_page.status_code == 200
    assert launch_token not in terminal_page.text
    assert "Not-In-The-Browser!" not in terminal_page.text
    terminal_js = client.get("/static/terminal.js").text
    assert 'fragment.get("remote-launch")' in terminal_js
    assert "history.replaceState" in terminal_js
    assert '"Vault Remote Terminal"' in terminal_js
    assert 'panel.dataset.terminalRemoteOnly === "true"' in terminal_js
    assert "document.title = remoteTarget" in terminal_js

    remote_page = client.get("/terminal/remote")
    assert remote_page.status_code == 200
    assert 'data-terminal-remote-only="true"' in remote_page.text
    assert 'data-terminal-heading>Remote terminal</h1>' in remote_page.text
    assert 'aria-label="Interactive remote terminal"' in remote_page.text
    assert "app-shell" not in remote_page.text
    assert "sidebar" not in remote_page.text
    assert "Primary" not in remote_page.text
    assert "/static/terminal.js?v=atlaso-vault-uri-20260727-2" in remote_page.text
    assert "/static/app.css?v=atlaso-monaco-expand-20260729-1" in remote_page.text

    ticket_response = client.post(
        "/terminal/tickets",
        data={
            "csrf": csrf,
            "browser_session_id": "remote_browser_1234",
            "remote_launch": launch_token,
        },
    )
    assert ticket_response.status_code == 200
    assert "Not-In-The-Browser!" not in ticket_response.text
    ticket = web_terminal._consume_ticket(
        ticket_response.json()["ticket"],
        admin_id,
        "admin",
        csrf,
    )
    assert ticket is not None
    assert ticket.remote_entry_id == entry_id
    assert ticket.remote_uri_index == 1
    assert ticket.remote_fingerprint == "SHA256:test-fingerprint"

    replay = client.post(
        "/terminal/tickets",
        data={
            "csrf": csrf,
            "browser_session_id": "remote_browser_5678",
            "remote_launch": launch_token,
        },
    )
    assert replay.status_code == 400

    def unavailable_target(*_args):
        raise ConnectionRefusedError(10061, "Connection refused by remote host")

    monkeypatch.setattr(web_terminal, "_probe_remote_ssh_host", unavailable_target)
    unavailable = client.post("/terminal/remote-launches", data=launch_data)
    assert unavailable.status_code == 422
    assert unavailable.json()["detail"] == (
        "The SSH target vcf.example.internal:2222 is unavailable. "
        "Verify the address, port, and SSH service."
    )
    assert "10061" not in unavailable.text
    assert "Connection refused by remote host" not in unavailable.text


def test_remote_vault_uri_authenticates_server_side_after_rechecking_host_key(client, monkeypatch):
    from atlaso.app import web_terminal
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    with SessionLocal() as db:
        vault = Vault(name="SSH auth", description="", created_by="admin")
        db.add(vault)
        db.flush()
        entry, _created = upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="esx.remote.root",
                secret_type="esx_password",
                value="Server-Side-Only!",
                username="root",
                uris=("sftp://esx.example.internal:2222/depot",),
            ),
            actor="admin",
        )
        db.commit()
        entry_id = entry.id

    class FakeHostKey:
        @staticmethod
        def asbytes():
            return b"verified-host-key"

    class FakeChannel:
        def __init__(self):
            self.pty = None
            self.shell_invoked = False

        def get_pty(self, **kwargs):
            self.pty = kwargs

        def invoke_shell(self):
            self.shell_invoked = True

    class FakeTransport:
        def __init__(self, _socket):
            self.channel = FakeChannel()
            self.authentication = None
            self.closed = False

        def start_client(self, timeout):
            assert timeout == 10

        @staticmethod
        def get_remote_server_key():
            return FakeHostKey()

        def auth_password(self, username, password):
            self.authentication = (username, password)

        def open_session(self, timeout):
            assert timeout == 10
            return self.channel

        def close(self):
            self.closed = True

    transports = []

    def fake_transport(sock):
        transport = FakeTransport(sock)
        transports.append(transport)
        return transport

    monkeypatch.setattr(web_terminal.socket, "create_connection", lambda target, timeout: (target, timeout))
    monkeypatch.setattr(web_terminal.paramiko, "Transport", fake_transport)
    fingerprint = web_terminal._ssh_fingerprint(FakeHostKey())

    transport, channel, display_username = web_terminal._open_remote_ssh_channel(
        entry_id,
        1,
        fingerprint,
        132,
        40,
    )

    assert transport is transports[0]
    assert transport.authentication == ("root", "Server-Side-Only!")
    assert channel.pty == {"term": "xterm-256color", "width": 132, "height": 40}
    assert channel.shell_invoked is True
    assert display_username == "root@esx.example.internal"

    with pytest.raises(RuntimeError, match="host key changed"):
        web_terminal._open_remote_ssh_channel(entry_id, 1, "SHA256:different", 120, 32)
    assert transports[1].authentication is None
    assert transports[1].closed is True


def test_vcf_import_discovers_sddc_manager_and_installer_passwords():
    import httpx

    from atlaso.app.services.vcf_vault_import import (
        _sddc_manager_candidates,
        _vcf_installer_candidates,
    )

    class FakeClient:
        def __init__(self, payloads):
            self.payloads = payloads

        def get(self, path, **_kwargs):
            return httpx.Response(200, json=self.payloads[path])

    class FakeApi:
        def __init__(self, payloads):
            self.client = FakeClient(payloads)

        @staticmethod
        def _raise(response, _message):
            assert response.is_success

    sddc = _sddc_manager_candidates(
        FakeApi(
            {
                "/v1/credentials": {
                    "elements": [
                        {
                            "id": "credential-1",
                            "username": "root",
                            "password": "VMware1!",
                            "resource": {"resourceName": "esx01", "resourceType": "ESXI"},
                        },
                        {
                            "id": "masked",
                            "username": "admin",
                            "password": "********",
                            "resource": {"resourceName": "ignored", "resourceType": "SDDC_MANAGER"},
                        },
                    ]
                }
            }
        )
    )
    assert [(candidate.key, candidate.secret_type, candidate.value) for candidate in sddc] == [
        ("esx.esx01.root", "esx_password", "VMware1!")
    ]

    installer = _vcf_installer_candidates(
        FakeApi(
            {
                "/v1/sddcs/latest": {"id": "sddc-1"},
                "/v1/sddcs/sddc-1/spec": {
                    "hostSpecs": [
                        {"hostname": "esx02", "credentials": {"password": "HostSecret!"}}
                    ],
                    "sddcManagerSpec": {"rootPassword": "ManagerSecret!"},
                },
            }
        )
    )
    assert {candidate.secret_type for candidate in installer} == {"esx_password", "vcf_password"}
    assert {candidate.value for candidate in installer} == {"HostSecret!", "ManagerSecret!"}


def test_settings_archive_excludes_and_restore_clears_vaults(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault
    from atlaso.app.services.settings_archive import export_settings_archive, restore_settings_archive
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    with SessionLocal() as db:
        vault = Vault(name="Not exported", description="", created_by="admin")
        db.add(vault)
        db.flush()
        upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="vcf.password",
                secret_type="vcf_password",
                value="ArchiveMustNotContainMe!",
            ),
            actor="admin",
        )
        db.commit()
        archive = export_settings_archive(db, actor="admin")
        serialized = json.dumps(archive)
        assert "ArchiveMustNotContainMe!" not in serialized
        assert "vault_entries" not in serialized
        restore_settings_archive(db, archive)
        assert db.execute(select(Vault)).scalars().all() == []


def test_worker_stages_selected_vault_and_redacts_captured_output(client, monkeypatch):
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript, Job, Vault
    from atlaso.app.services.automation import create_script_revision
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry, vault_scope_identity
    from atlaso.app.worker import _run_managed_script

    captured = {}

    def fake_run(_self, script_path, interpreter, timeout_seconds, arguments, vault_path):
        captured["vault_path"] = vault_path
        captured["payload"] = json.loads(Path(vault_path).read_text(encoding="utf-8"))
        return AdapterResult(
            command=["atlaso-helper", "automation", "run"],
            dry_run=False,
            stdout="password=WorkerSecret!\n",
            stderr="",
            returncode=0,
        )

    monkeypatch.setattr(SystemAdapter, "run_automation_script", fake_run)
    with SessionLocal() as db:
        vault = Vault(name="Worker", description="", created_by="admin")
        db.add(vault)
        db.flush()
        upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="vcf.worker.password",
                secret_type="vcf_password",
                value="WorkerSecret!",
            ),
            actor="admin",
        )
        script = AutomationScript(name="vault-worker", description="", created_by="admin")
        db.add(script)
        db.flush()
        revision = create_script_revision(
            db,
            script=script,
            interpreter="bash",
            content="atlaso-vault get --key vcf.worker.password",
            timeout_seconds=60,
            actor="admin",
        )
        revision.enabled = True
        db.flush()
        job = Job(
            id="job_vault_worker",
            type="managed-script",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "revision_id": revision.id,
                    "arguments": [],
                    "vault_id": vault.id,
                    "vault_scope": vault_scope_identity(vault),
                }
            ),
        )
        db.add(job)
        db.commit()
        _run_managed_script(db, job)
        payload = json.loads(job.result)
        assert captured["payload"]["values"] == {"vcf.worker.password": "WorkerSecret!"}
        assert payload["stdout"] == "password=[redacted]\n"
        assert "WorkerSecret!" not in job.result
        assert not Path(captured["vault_path"]).exists()


def test_worker_rejects_reused_vault_id_before_decrypting(client, monkeypatch):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript, Job, Vault
    from atlaso.app.services.automation import create_script_revision
    from atlaso.app.services.vaults import vault_scope_identity
    from atlaso.app.worker import _run_managed_script

    with SessionLocal() as db:
        original = Vault(name="Original", description="", created_by="admin")
        db.add(original)
        db.flush()
        original_id = original.id
        original_scope = vault_scope_identity(original)
        db.delete(original)
        db.commit()

        replacement = Vault(name="Replacement", description="", created_by="admin")
        db.add(replacement)
        script = AutomationScript(name="reused-vault-guard", description="", created_by="admin")
        db.add(script)
        db.flush()
        assert replacement.id == original_id
        revision = create_script_revision(
            db,
            script=script,
            interpreter="bash",
            content="atlaso-vault get --key vcf.admin",
            timeout_seconds=60,
            actor="admin",
        )
        revision.enabled = True
        db.flush()
        job = Job(
            id="job_reused_vault_guard",
            type="managed-script",
            status="running",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "revision_id": revision.id,
                    "arguments": [],
                    "vault_id": replacement.id,
                    "vault_scope": original_scope,
                }
            ),
        )
        db.add(job)
        db.commit()
        monkeypatch.setattr(
            "atlaso.app.worker.decrypted_vault_values",
            lambda *_args: pytest.fail("A replacement vault must not be decrypted."),
        )

        with pytest.raises(ValueError, match="no longer matches"):
            _run_managed_script(db, job)


def test_vcf_helper_inspection_returns_metadata_and_import_encrypts_value(client, monkeypatch):
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault, VaultEntry
    from atlaso.app.secrets import decrypt_secret
    from atlaso.app.services.vcf_vault_import import VcfPasswordCandidate

    candidate = VcfPasswordCandidate(
        candidate_id="credential-1",
        key="esx.esx01.root",
        description="Imported ESX root password.",
        secret_type="esx_password",
        username="root",
        resource_name="esx01",
        value="ImportedSecret!",
    )
    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [candidate])
    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    assert client.post(
        "/vaults",
        data={"csrf": csrf, "name": "Imported", "description": ""},
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        vault_id = db.execute(select(Vault).where(Vault.name == "Imported")).scalar_one().id

    source = {
        "csrf": csrf,
        "source_type": "sddc_manager",
        "address": "sddc-manager.example.internal",
        "port": 443,
        "confirmed_fingerprint": "AA:BB",
        "username": "admin",
        "password": "SourcePassword!",
    }
    inspected = client.post("/vcf-helper/vault-import/inspect", json=source)
    assert inspected.status_code == 200
    assert inspected.json()["candidates"] == [candidate.sanitized()]
    assert "ImportedSecret!" not in inspected.text
    assert "no-store" in inspected.headers["cache-control"]

    imported = client.post(
        "/vcf-helper/vault-import",
        json={**source, "vault_id": vault_id, "candidate_ids": ["credential-1"]},
    )
    assert imported.status_code == 200
    assert imported.json()["imported_keys"] == ["esx.esx01.root"]
    assert "ImportedSecret!" not in imported.text
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        assert entry.encrypted_value != "ImportedSecret!"
        assert decrypt_secret(entry.encrypted_value) == "ImportedSecret!"


def test_vcf_helper_vault_picker_resolves_password_only_on_server(client, monkeypatch):
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Vault
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry
    from atlaso.app.services.vcf_vault_import import VcfPasswordCandidate

    login(client)
    with SessionLocal() as db:
        source_vault = Vault(name="VCF targets", description="", created_by="admin")
        other_vault = Vault(name="Other targets", description="", created_by="admin")
        db.add_all([source_vault, other_vault])
        db.flush()
        source_entry, _created = upsert_vault_entry(
            db,
            vault=source_vault,
            entry=VaultEntryInput(
                key="sddc.manager.admin",
                secret_type="vcf_password",
                value="ServerSideOnly!",
                username="admin@local",
                uris=("https://sddc.example.internal:8443",),
            ),
            actor="admin",
        )
        other_entry, _created = upsert_vault_entry(
            db,
            vault=other_vault,
            entry=VaultEntryInput(
                key="installer.admin",
                secret_type="vcf_password",
                value="OtherSecret!",
                username="admin@local",
            ),
            actor="admin",
        )
        db.commit()
        source_vault_id = source_vault.id
        source_entry_id = source_entry.id
        other_entry_id = other_entry.id

    page = client.get("/vcf-helper")
    assert page.status_code == 200
    assert page.text.count("data-vcf-vault-credential-picker") == 4
    assert 'credential_address_field = "target_url"' in Path(
        "atlaso/app/templates/partials/vcf_ldap_modal.html"
    ).read_text(encoding="utf-8")
    options_json = page.text.split(
        '<script id="vcf-vault-credential-options" type="application/json">',
        1,
    )[1].split("</script>", 1)[0]
    options = json.loads(options_json)
    source_metadata = next(item for item in options if item["id"] == source_vault_id)
    source_entry_metadata = source_metadata["entries"][0]
    assert source_entry_metadata["key"] == "sddc.manager.admin"
    assert source_entry_metadata["username"] == "admin@local"
    assert source_entry_metadata["uris"] == ["https://sddc.example.internal:8443"]
    assert "ServerSideOnly!" not in page.text
    csrf = csrf_from_page(page.text)

    captured = {}

    def discover(**kwargs):
        captured.update(kwargs)
        return [
            VcfPasswordCandidate(
                candidate_id="candidate",
                key="vcf.test",
                description="Test",
                secret_type="vcf_password",
                username="admin",
                resource_name="sddc",
                value="Imported!",
            )
        ]

    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", discover)
    payload = {
        "csrf": csrf,
        "source_type": "sddc_manager",
        "address": "sddc.example.internal",
        "port": 8443,
        "confirmed_fingerprint": "AA:BB",
        "credential_vault_id": source_vault_id,
        "credential_entry_id": source_entry_id,
    }
    response = client.post("/vcf-helper/vault-import/inspect", json=payload)
    assert response.status_code == 200
    assert captured["username"] == "admin@local"
    assert captured["password"] == "ServerSideOnly!"
    assert "ServerSideOnly!" not in response.text
    with SessionLocal() as db:
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "use_vcf_helper_vault_credential")
        ).scalar_one()
        assert event.resource_id == str(source_entry_id)
        assert "ServerSideOnly!" not in (event.detail or "")

    mismatched = client.post(
        "/vcf-helper/vault-import/inspect",
        json={**payload, "credential_entry_id": other_entry_id},
    )
    assert mismatched.status_code == 422
    assert mismatched.json()["detail"] == "Choose a valid vault and key."


def test_vcf_helper_vault_picker_never_loads_password_into_browser_state():
    source = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    picker = source.split("function initializeVcfVaultCredentialPickers()", 1)[1].split(
        "function initializeVcfTrustForm()", 1
    )[0]
    assert "Stored vault password will be used" in picker
    assert 'passwordControl.value = ""' in picker
    assert "entry.password" not in picker
    assert "credential_vault_id" in source
    assert "credential_entry_id" in source

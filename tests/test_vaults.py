"""Test vaults behavior."""

import json
from pathlib import Path

import pytest
from sqlalchemy import select


def login(client):
    """Handle login.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def csrf_from_page(text: str) -> str:
    """Return csrf from page.

    Args:
        text: Text content consumed by the operation.
    """
    return text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def _seed_legacy_vcf_import_entry(
    client,
    *,
    natural_key: str,
    secret_value: str,
    username: str,
    resource_name: str,
    secret_type: str,
    source_type: str,
    source_endpoint: str,
    uris: tuple[str, ...],
) -> tuple[str, int]:
    """Create a vault entry in the legacy natural-key format for import regressions.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        natural_key: Existing key written by the previous VCF import behavior.
        secret_value: Existing encrypted value to preserve or rotate.
        username: Account identity persisted on the legacy entry.
        resource_name: Resource identity persisted on the legacy entry.
        secret_type: Vault secret type persisted on the legacy entry.
        source_type: Import source type associated with the legacy entry.
        source_endpoint: Source endpoint identity associated with the legacy entry.
        uris: Operator URI positions associated with the legacy entry.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault, VaultEntry

    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    created = client.post(
        "/vaults",
        data={"csrf": csrf, "name": "Legacy import", "description": ""},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        vault_id = db.execute(select(Vault).where(Vault.name == "Legacy import")).scalar_one().id
    response = client.post(
        f"/vaults/{vault_id}/entries",
        data={
            "csrf": csrf,
            "key": natural_key,
            "description": "Legacy VCF credential",
            "value": secret_value,
            "username": username,
            "resource_name": resource_name,
            "uris_json": json.dumps(uris),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(
            VaultEntry.vault_id == vault_id, VaultEntry.key == natural_key,
        )).scalar_one()
        entry.secret_type = secret_type
        entry.source_type = source_type
        entry.source_endpoint = source_endpoint
        db.commit()
    return csrf, vault_id


def _create_empty_vcf_import_vault(client) -> tuple[str, int]:
    """Create a fresh empty vault and return its CSRF token and ID.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault

    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    created = client.post(
        "/vaults",
        data={"csrf": csrf, "name": "Metadata drift", "description": ""},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        vault_id = db.execute(select(Vault).where(Vault.name == "Metadata drift")).scalar_one().id
    return csrf, vault_id


def _canonical_test_vcf_candidate(
    *,
    candidate_id: str,
    natural_key: str,
    value: str,
    username: str = "admin",
    resource_name: str = "manager.example.internal",
    secret_type: str = "vcf_password",
    uris: tuple[str, ...] = ("https://manager.example.internal",),
):
    """Build a candidate with the import service's stable canonical key.

    Args:
        candidate_id: Stable source identity for the candidate.
        natural_key: Legacy key retained for guarded compatibility rotation.
        value: Current fake source password.
        username: Candidate account identity.
        resource_name: Candidate resource identity.
        secret_type: Candidate vault secret type.
        uris: Fresh source endpoint metadata.
    """
    from dataclasses import replace

    from atlaso.app.services.vcf_vault_import import VcfPasswordCandidate

    candidate = VcfPasswordCandidate(
        candidate_id=candidate_id,
        key=natural_key,
        description="Current fake VCF credential",
        secret_type=secret_type,
        username=username,
        resource_name=resource_name,
        value=value,
        uris=uris,
        natural_key=natural_key,
    )
    canonical_key = f"vcf.imported.id_{candidate.identity_id.removeprefix('vcf-')}"
    return replace(candidate, key=canonical_key)


def _post_fake_vcf_import(client, monkeypatch, *, csrf: str, vault_id: int, candidates, address: str):
    """Submit an import from a fake source without making an authenticated request.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace TLS and discovery dependencies.
        csrf: CSRF token obtained from the test client.
        vault_id: Target vault ID.
        candidates: Fake candidate sequence exposed by the discovery stub.
        address: Fake source address for this import attempt.
    """
    from atlaso.app import ui

    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: list(candidates))
    source = {
        "csrf": csrf,
        "source_type": "sddc_manager",
        "address": address,
        "port": 443,
        "confirmed_fingerprint": "AA:BB",
        "username": "admin",
        "password": "FixtureSourcePassword!",
    }
    return client.post(
        "/vcf-helper/vault-import",
        json={
            **source,
            "vault_id": vault_id,
            "candidate_ids": [candidate.selection_id for candidate in candidates],
        },
    )


def test_vault_ui_encrypts_masks_and_explicitly_reveals_password(client):
    """Verify that vault ui encrypts masks and explicitly reveals password.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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


def test_vault_delete_blocks_enabled_kickstart_marker_dependencies(client):
    """Verify that vault delete blocks enabled kickstart marker dependencies.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, Vault
    from atlaso.app.services.esxi_pxe import content_hash
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    with SessionLocal() as db:
        vault = Vault(name="Kickstart", description="", created_by="admin")
        db.add(vault)
        db.flush()
        upsert_vault_entry(
            db,
            vault=vault,
            entry=VaultEntryInput(
                key="esx.root",
                secret_type="esx_password",
                value="DeleteGuardSecret!",
            ),
            actor="admin",
        )
        source = "rootpw {{vault.kickstart.esx.root.password}}\n"
        kickstart = EsxiKickstart(
            name="Dependent ESXi",
            content=source,
            content_hash=content_hash(source),
            enabled=True,
        )
        db.add(kickstart)
        db.commit()
        vault_id = vault.id
        kickstart_id = kickstart.id

    blocked = client.post(
        f"/vaults/{vault_id}/delete",
        data={"csrf": csrf},
    )
    assert blocked.status_code == 409
    assert "Remove this vault from these enabled Kickstarts first: Dependent ESXi." in blocked.text
    assert "DeleteGuardSecret!" not in blocked.text
    with SessionLocal() as db:
        assert db.get(Vault, vault_id) is not None
        kickstart = db.get(EsxiKickstart, kickstart_id)
        kickstart.enabled = False
        db.commit()

    deleted = client.post(
        f"/vaults/{vault_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    with SessionLocal() as db:
        assert db.get(Vault, vault_id) is None


def test_vault_ui_copies_entry_without_returning_plaintext(client):
    """Verify that vault ui copies entry without returning plaintext.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that vault service rejects unsupported types.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
    """Verify that vault uri validation rejects unsupported or unsafe values.

    Args:
        uris: Uris supplied to the test scenario.
        message: Human-readable message associated with the operation.
    """
    from atlaso.app.services.vaults import normalize_vault_uris

    with pytest.raises(ValueError, match=message):
        normalize_vault_uris(uris)


def test_vault_cli_fails_closed_and_reads_only_scoped_credential(tmp_path, monkeypatch, capsys):
    """Verify that vault cli fails closed and reads only scoped credential.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
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
    """Verify that dynamic kickstart derives exact vault scope without caching.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        EsxiKickstart,
        EsxiKickstartVaultBinding,
        EsxiPxeHost,
        Vault,
    )
    from atlaso.app.services.esxi_pxe import content_hash, kickstart_template_variables
    from atlaso.app.services.vaults import (
        VaultEntryInput,
        kickstart_vault_values_for_markers,
        upsert_vault_entry,
    )

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
        resolved = kickstart_vault_values_for_markers(
            db,
            kickstart_template_variables(content)[0],
        )

    login(client)
    editor_page = client.get("/esxi-pxe")
    assert "vault.esx.esx.host.root.username" in editor_page.text
    assert "vault.esx.esx.host.root.password" in editor_page.text
    assert "vault.esx.esx.host.root.uri1" in editor_page.text
    assert "VMware1!" not in editor_page.text

    assert resolved == {
        "esx.esx.host.root.password": "VMware1!",
        "esx.esx.host.root.uri1": "https://config.example.internal/esx01.cfg",
        "esx.esx.host.root.username": "root",
    }
    response = client.get(path)
    assert response.status_code == 404
    assert "VMware1!" not in response.text

    with SessionLocal() as db:
        vault = db.execute(select(Vault).where(Vault.name == "ESX")).scalar_one()
        vault.name = "Renamed ESX"
        db.add(vault)
        db.commit()

    with SessionLocal() as db:
        with pytest.raises(ValueError, match="vault.esx.esx.host.root.password"):
            kickstart_vault_values_for_markers(
                db,
                kickstart_template_variables(content)[0],
            )


@pytest.mark.parametrize(
    ("marker", "case_name"),
    [
        ("{{vault.missing.key.password}}", "missing"),
        ("{{vault.missing.key.token}}", "unsupported"),
        ("{{vault.missing.key.password", "unclosed"),
        ("vault.missing.key.password}}", "unmatched"),
    ],
)
def test_kickstart_save_rejects_missing_unsupported_and_malformed_vault_markers(client, marker, case_name):
    """Verify that kickstart save rejects missing unsupported and malformed vault markers.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        marker: Marker supplied to the test scenario.
        case_name: Case name supplied to the test scenario.
    """
    login(client)
    page = client.get("/esxi-pxe")
    csrf = csrf_from_page(page.text)
    response = client.post(
        "/esxi-pxe/kickstarts",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "name": f"Rejected {case_name}",
            "description": "",
            "content": f"vmaccepteula\nrootpw {marker}\n",
            "enabled": "on",
        },
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Kickstart source is invalid. Review its variable and vault markers."
    assert marker not in response.text


def test_kickstart_marker_parser_handles_adversarial_braces_without_regex_backtracking():
    """Verify that kickstart marker parser handles adversarial braces without regex backtracking."""
    from atlaso.app.services.esxi_pxe import kickstart_template_variables

    names, invalid = kickstart_template_variables("{{{{" + (" " * 100_000) + "}}}}")

    assert names == set()
    assert invalid


def test_kickstart_json_errors_do_not_expose_database_exception_details(client):
    """Verify that kickstart json errors do not expose database exception details.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/esxi-pxe")
    csrf = csrf_from_page(page.text)
    payload = {
        "csrf": csrf,
        "name": "Duplicate-safe Kickstart",
        "description": "",
        "content": "vmaccepteula\nrootpw --iscrypted placeholder\n",
    }

    created = client.post("/esxi-pxe/kickstarts", headers={"Accept": "application/json"}, data=payload)
    duplicate = client.post("/esxi-pxe/kickstarts", headers={"Accept": "application/json"}, data=payload)

    assert created.status_code == 200
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"] == "A Kickstart with that name already exists."
    assert "sql" not in duplicate.text.lower()
    assert "integrityerror" not in duplicate.text.lower()


def test_kickstart_completion_and_save_validate_metadata_without_decrypting(client, monkeypatch):
    """Verify that kickstart completion and save validate metadata without decrypting.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    """Verify that vault javascript uses shared grid wizard and timed eye."""
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
    assert "issue-779-7" in base_template
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
    assert "Vault access is declared only with" not in pxe_template
    assert "{{vault.<vaultname>.<key>.uri1}}" not in pxe_template
    assert "{{vault.<vaultname>.<key>.uri9}}" not in pxe_template


def test_vmware_wheel_deploy_exposes_fail_closed_vault_shell_commands():
    """Verify that vmware wheel deploy exposes fail closed vault shell commands."""
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    assert 'ln -sfn "$venv/bin/atlaso-vault" /usr/local/bin/atlaso-vault' in deploy
    assert 'ln -sfn "$venv/bin/atlaso-vault" /usr/bin/atlaso-vault' in deploy
    assert "function global:Get-AtlasoVault" in deploy
    assert "/opt/atlaso/.venv/bin/atlaso-vault" in deploy
    assert 'touch "$powershell_home/profile.ps1"' not in deploy
    assert '>>"$powershell_home/profile.ps1"' not in deploy
    assert "/usr/share/powershell)" in deploy
    assert "/opt/microsoft/powershell/7)" in deploy
    assert "PowerShell executable must be root-owned, executable, and non-writable" in deploy
    assert "'%u:%g:%a:%F'" not in deploy
    assert 'if [ ! -f "$powershell_binary" ]' in deploy
    assert "PowerShell profile directory must be a canonical directory" in deploy
    assert "PowerShell profile directory must be owned by root" in deploy
    assert "PowerShell profile directory must not be writable by group or other" in deploy
    assert "PowerShell global profile path must be a regular file or absent" in deploy
    assert 'mktemp "$powershell_home/.atlaso-profile.XXXXXX"' in deploy
    assert 'mv -fT -- "$powershell_profile_temporary" "$powershell_profile"' in deploy
    assert 'inactive_powershell_profile="$inactive_powershell_home/profile.ps1"' in deploy
    assert 'cmp -s -- "$inactive_powershell_profile" "$powershell_profile"' in deploy
    assert 'rm -f -- "$inactive_powershell_profile"' in deploy
    assert "Inactive PowerShell global profile is not Atlaso-owned" in deploy
    preflight_definition = deploy.index("preflight_powershell_layouts() {")
    preflight_comment = deploy.index(
        "# Validate every supported PowerShell path before package or service mutation."
    )
    preflight_body = deploy[preflight_definition:preflight_comment]
    assert "/usr/share/powershell)" in preflight_body
    assert "/opt/microsoft/powershell/7)" in preflight_body
    assert "PowerShell executable must be root-owned, executable" in preflight_body
    assert "PowerShell profile directory must be a canonical directory" in preflight_body
    assert "PowerShell profile directory must be owned by root" in preflight_body
    assert "PowerShell profile directory must not be writable" in preflight_body
    assert "PowerShell global profile path must be a regular file or absent" in preflight_body
    assert "Inactive PowerShell global profile is not Atlaso-owned" in preflight_body
    assert deploy.count("preflight_powershell_layouts") == 3
    first_preflight_call = deploy.index("preflight_powershell_layouts", preflight_comment)
    dependency_install = deploy.index(
        '"$python" -m pip install --force-reinstall --no-compile --no-deps '
        '"$runtime_dependency_path"'
    )
    wheel_install = deploy.index(
        '"$python" -m pip install --force-reinstall --no-compile --no-deps "$wheel"'
    )
    service_stop = deploy.index(
        "systemctl stop atlaso-worker.service atlaso.service"
    )
    second_preflight_call = deploy.index(
        "preflight_powershell_layouts", first_preflight_call + 1
    )
    profile_install = deploy.index(
        'powershell_profile_temporary="$(mktemp '
        '"$powershell_home/.atlaso-profile.XXXXXX")"'
    )
    assert first_preflight_call < dependency_install < wheel_install < service_stop
    assert service_stop < second_preflight_call < profile_install
    assert "ATLASO_GLOBAL_POWERSHELL_PROFILE" in deploy
    assert ". '/opt/atlaso/bin/atlaso-vault-profile.ps1'" in deploy
    delimiter = "<<'ATLASO_GLOBAL_POWERSHELL_PROFILE'\n"
    deployed_profile = deploy.split(delimiter, 1)[1].split(
        "\nATLASO_GLOBAL_POWERSHELL_PROFILE", 1
    )[0]
    canonical_profile = Path("image/common/powershell/profile.ps1").read_text(
        encoding="utf-8"
    ).rstrip("\n")
    assert deployed_profile == canonical_profile
    assert "[switch]$ResetVaultEntries" in deploy
    assert "DROP TABLE IF EXISTS vault_entries" in deploy


def test_remote_vault_uri_launch_uses_one_use_server_side_ticket(client, monkeypatch):
    """Verify that remote vault uri launch uses one use server side ticket.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    assert urlsplit(launch_url).path == "/ui/management/terminal/remote"
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
    assert "/static/terminal.js?v=issue-287-2" in remote_page.text
    assert "/static/app.css?v=issues-515-519-10-605-1-660-3" in remote_page.text

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
        """Handle unavailable target.

        Args:
            *_args: Additional positional arguments accepted by the callable.


        Raises:
            ConnectionRefusedError: If the operation encounters an invalid state.
        """
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
    """Verify that remote vault uri authenticates server side after rechecking host key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
        """Represent fake host key."""
        @staticmethod
        def asbytes():
            """Return asbytes."""
            return b"verified-host-key"

    class FakeChannel:
        """Represent fake channel.

        Attributes:
            pty: Pty captured or supplied by this test helper.
            shell_invoked: Shell invoked captured or supplied by this test helper.
        """
        def __init__(self):
            """Initialize the fake channel."""
            self.pty = None
            self.shell_invoked = False

        def get_pty(self, **kwargs):
            """Return pty.

            Args:
                **kwargs: Additional keyword arguments accepted by the callable.
            """
            self.pty = kwargs

        def invoke_shell(self):
            """Run shell."""
            self.shell_invoked = True

    class FakeTransport:
        """Represent fake transport.

        Attributes:
            channel: Channel captured or supplied by this test helper.
            authentication: Authentication captured or supplied by this test helper.
            closed: Closed captured or supplied by this test helper.
        """
        def __init__(self, _socket):
            """Initialize the fake transport.

            Args:
                _socket: Socket supplied to the test scenario.
            """
            self.channel = FakeChannel()
            self.authentication = None
            self.closed = False

        def start_client(self, timeout):
            """Handle start client.

            Args:
                timeout: Maximum time to wait for completion.
            """
            assert timeout == 10

        @staticmethod
        def get_remote_server_key():
            """Return remote server key."""
            return FakeHostKey()

        def auth_password(self, username, password):
            """Handle auth password.

            Args:
                username: Account name used for authentication or lookup.
                password: Password supplied for the immediate authenticated operation.
            """
            self.authentication = (username, password)

        def open_session(self, timeout):
            """Return open session.

            Args:
                timeout: Maximum time to wait for completion.
            """
            assert timeout == 10
            return self.channel

        def close(self):
            """Handle close."""
            self.closed = True

    transports = []

    def fake_transport(sock):
        """Return fake transport.

        Args:
            sock: Sock supplied to the test scenario.
        """
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
    """Verify that vcf import discovers sddc manager and installer passwords."""
    import httpx

    from atlaso.app.services.vcf_vault_import import (
        _sddc_manager_candidates,
        _vcf_installer_candidates,
    )

    class FakeClient:
        """Represent fake client.

        Attributes:
            payloads: Payloads captured or supplied by this test helper.
        """
        def __init__(self, payloads):
            """Initialize the fake client.

            Args:
                payloads: Payloads supplied to the test scenario.
            """
            self.payloads = payloads

        def get(self, path, **_kwargs):
            """Return operation.

            Args:
                path: Filesystem or URL path to read, validate, or update.
                **_kwargs: Additional keyword arguments accepted by the test double.
            """
            return httpx.Response(200, json=self.payloads[path]) if path in self.payloads else httpx.Response(403)

    class FakeApi:
        """Represent fake api.

        Attributes:
            client: Client captured or supplied by this test helper.
        """
        def __init__(self, payloads):
            """Initialize the fake api.

            Args:
                payloads: Payloads supplied to the test scenario.
            """
            self.client = FakeClient(payloads)

        @staticmethod
        def _raise(response, _message):
            """Handle raise.

            Args:
                response: HTTP or command response being inspected.
                _message: Human-readable message associated with the operation.
            """
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
    """Verify that settings archive excludes and restore clears vaults.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )
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
    """Verify that worker stages selected vault and redacts captured output.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript, Job, Vault
    from atlaso.app.services.automation import create_script_revision
    from atlaso.app.services.vaults import (
        VaultEntryInput,
        upsert_vault_entry,
        vault_scope_identity,
    )
    from atlaso.app.worker import _run_managed_script

    captured = {}

    def fake_run(_self, script_path, interpreter, timeout_seconds, arguments, vault_path):
        """Return fake run.

        Args:
            _self:  self supplied by the caller.
            script_path: Filesystem path for the script.
            interpreter: Interpreter supplied by the caller.
            timeout_seconds: Maximum time to wait, in seconds.
            arguments: Arguments supplied by the caller.
            vault_path: Filesystem path for the vault.
        """
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
    """Verify that worker rejects reused vault id before decrypting.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
    """Verify that vcf helper inspection returns metadata and import encrypts value.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault, VaultEntry
    from atlaso.app.secrets import decrypt_secret
    from atlaso.app.services.vcf_vault_import import VcfPasswordCandidate

    candidate = VcfPasswordCandidate(
        candidate_id="ImportedSecret!",
        key="esx.esx01.root",
        description="Imported ESX root password.",
        secret_type="esx_password",
        username="root",
        resource_name="esx01",
        value="ImportedSecret!",
        uris=("https://esx01.example.internal",),
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
    assert inspected.json()["candidates"][0]["candidate_id"] == candidate.selection_id
    assert candidate.candidate_id not in inspected.text
    assert "ImportedSecret!" not in inspected.text
    assert "no-store" in inspected.headers["cache-control"]

    imported = client.post(
        "/vcf-helper/vault-import",
        json={**source, "vault_id": vault_id, "candidate_ids": [candidate.selection_id]},
    )
    assert imported.status_code == 200
    assert imported.json()["imported_keys"] == ["esx.esx01.root"]
    assert "ImportedSecret!" not in imported.text
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        assert entry.encrypted_value != "ImportedSecret!"
        assert decrypt_secret(entry.encrypted_value) == "ImportedSecret!"
        assert json.loads(entry.uris_json) == ["https://esx01.example.internal"]
        entry.uris_json = json.dumps(["https://operator.example.internal", "ssh://operator.example.internal"])
        db.commit()
    helper_page = client.get("/vcf-helper")
    options = json.loads(helper_page.text.split(
        '<script id="vcf-vault-credential-options" type="application/json">', 1,
    )[1].split("</script>", 1)[0])
    imported_options = next(item for item in options if item["id"] == vault_id)
    assert imported_options["entries"][0]["uris"] == [
        "https://operator.example.internal", "ssh://operator.example.internal",
    ]
    assert "ImportedSecret!" not in helper_page.text
    from dataclasses import replace

    refreshed_candidate = replace(candidate, uris=())
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [refreshed_candidate])
    rotated = client.post(
        "/vcf-helper/vault-import",
        json={**source, "vault_id": vault_id, "candidate_ids": [refreshed_candidate.selection_id]},
    )
    assert rotated.status_code == 200
    assert rotated.json()["rotated"] == 1
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        assert json.loads(entry.uris_json) == ["https://operator.example.internal", "ssh://operator.example.internal"]
    duplicate = client.post(
        "/vcf-helper/vault-import",
        json={
            **source,
            "vault_id": vault_id,
            "candidate_ids": [candidate.selection_id, candidate.selection_id],
        },
    )
    assert duplicate.status_code == 422


@pytest.mark.parametrize(
    "mismatch, candidate_uris, expected_source_type, expected_address, expected_port",
    [
        ({"source_type": "vcf_installer"}, ("https://fresh.example.internal",), "vcf_installer", "sddc-manager.example.internal", 443),
        ({"address": "rotated-source.example.internal"}, (), "sddc_manager", "rotated-source.example.internal", 443),
        ({"resource_name": "different-resource"}, ("ssh://fresh.example.internal",), "sddc_manager", "sddc-manager.example.internal", 443),
        ({"username": "different-account"}, (), "sddc_manager", "sddc-manager.example.internal", 443),
        ({"secret_type": "vcf_password"}, ("https://fresh.example.internal",), "sddc_manager", "sddc-manager.example.internal", 443),
    ],
)
def test_vcf_import_replaces_operator_uris_when_source_or_account_changes(
    client,
    monkeypatch,
    mismatch,
    candidate_uris,
    expected_source_type,
    expected_address,
    expected_port,
):
    """Replace operator URI positions unless every source and account identity field matches.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery dependencies.
        mismatch: One source or account identity field to change for the second import.
        candidate_uris: Current discovery URIs, including the empty-URI case.
        expected_source_type: Source type expected on the updated vault entry.
        expected_address: Source address expected on the updated vault entry.
        expected_port: Source port expected on the updated vault entry.
    """
    from dataclasses import replace

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Vault, VaultEntry
    from atlaso.app.secrets import decrypt_secret
    from atlaso.app.services.vcf_vault_import import VcfPasswordCandidate

    candidate = VcfPasswordCandidate(
        candidate_id="credential-source-rotation",
        key="esx.esx01.root",
        description="Imported ESX root password.",
        secret_type="esx_password",
        username="root",
        resource_name="esx01",
        value="InitialImportedSecret!",
        uris=("https://discovered.example.internal",),
    )
    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [candidate])
    login(client)
    page = client.get("/vaults")
    csrf = csrf_from_page(page.text)
    assert client.post(
        "/vaults",
        data={"csrf": csrf, "name": "Source rotation", "description": ""},
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        vault_id = db.execute(select(Vault).where(Vault.name == "Source rotation")).scalar_one().id

    source = {
        "csrf": csrf,
        "source_type": "sddc_manager",
        "address": "sddc-manager.example.internal",
        "port": 443,
        "confirmed_fingerprint": "AA:BB",
        "username": "admin",
        "password": "SourcePassword!",
    }
    first = client.post(
        "/vcf-helper/vault-import",
        json={**source, "vault_id": vault_id, "candidate_ids": [candidate.selection_id]},
    )
    assert first.status_code == 200
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        entry.uris_json = json.dumps(["https://operator.example.internal", "ssh://operator.example.internal"])
        db.commit()

    changed_candidate = replace(
        candidate,
        value="CurrentImportedSecret!",
        uris=candidate_uris,
        **{name: value for name, value in mismatch.items() if name in {"resource_name", "username", "secret_type"}},
    )
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [changed_candidate])
    changed_source = {**source, **{key: value for key, value in mismatch.items() if key in {"source_type", "address"}}}
    rotated = client.post(
        "/vcf-helper/vault-import",
        json={**changed_source, "vault_id": vault_id, "candidate_ids": [changed_candidate.selection_id]},
    )

    assert rotated.status_code == 200
    assert rotated.json()["rotated"] == 1
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        assert json.loads(entry.uris_json) == list(candidate_uris)
        assert decrypt_secret(entry.encrypted_value) == "CurrentImportedSecret!"
        assert entry.source_type == expected_source_type
        assert entry.source_endpoint == f"{expected_address}:{expected_port}"
        assert entry.resource_name == changed_candidate.resource_name
        assert entry.username == changed_candidate.username
        assert entry.secret_type == changed_candidate.secret_type


@pytest.mark.parametrize(
    "field, changed_value",
    [
        ("username", "changed-admin"),
        ("resource_name", "other-manager.example.internal"),
        ("uris", ("https://changed-manager.example.internal",)),
        ("secret_type", "esx_password"),
        ("key", "vcf.changed.key"),
        ("description", "Changed after review"),
    ],
)
def test_vcf_import_rejects_candidate_metadata_drift_since_inspection(
    client, monkeypatch, field, changed_value
):
    """Reject an import when the selected candidate metadata changed after inspection.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
        field: Candidate metadata field changed between inspect and import.
        changed_value: Updated metadata value returned by the source on import.
    """
    from dataclasses import replace

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry

    csrf, vault_id = _create_empty_vcf_import_vault(client)
    candidate = _canonical_test_vcf_candidate(
        candidate_id="metadata-drift-credential",
        natural_key="vcf.manager.admin",
        value="FixtureCredentialPassword!",
    )
    inspected_token = candidate.selection_id
    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [candidate])
    source = {
        "csrf": csrf,
        "source_type": "sddc_manager",
        "address": "sddc-manager.example.internal",
        "port": 443,
        "confirmed_fingerprint": "AA:BB",
        "username": "admin",
        "password": "FixtureSourcePassword!",
    }
    inspected = client.post("/vcf-helper/vault-import/inspect", json=source)
    assert inspected.status_code == 200
    assert inspected.json()["candidates"][0]["candidate_id"] == inspected_token

    changed_candidate = replace(candidate, **{field: changed_value})
    assert changed_candidate.selection_id != inspected_token
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [changed_candidate])
    imported = client.post(
        "/vcf-helper/vault-import",
        json={**source, "vault_id": vault_id, "candidate_ids": [inspected_token]},
    )

    assert imported.status_code == 422
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        assert entries == []


def test_vcf_import_accepts_password_refresh_when_reviewed_metadata_is_unchanged(client, monkeypatch):
    """Import the latest password when source identity and reviewed metadata remain stable.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
    """
    from dataclasses import replace

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    csrf, vault_id = _create_empty_vcf_import_vault(client)
    candidate = _canonical_test_vcf_candidate(
        candidate_id="password-refresh-credential",
        natural_key="vcf.manager.admin",
        value="FixtureCredentialOldPassword!",
    )
    current_candidate = replace(candidate, value="FixtureCredentialCurrentPassword!")
    assert current_candidate.identity_id == candidate.identity_id
    assert current_candidate.selection_id == candidate.selection_id
    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [candidate])
    source = {
        "csrf": csrf,
        "source_type": "sddc_manager",
        "address": "sddc-manager.example.internal",
        "port": 443,
        "confirmed_fingerprint": "AA:BB",
        "username": "admin",
        "password": "FixtureSourcePassword!",
    }
    inspected = client.post("/vcf-helper/vault-import/inspect", json=source)
    assert inspected.status_code == 200
    selection_id = inspected.json()["candidates"][0]["candidate_id"]
    assert selection_id == candidate.selection_id

    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [current_candidate])
    imported = client.post(
        "/vcf-helper/vault-import",
        json={**source, "vault_id": vault_id, "candidate_ids": [selection_id]},
    )

    assert imported.status_code == 200
    with SessionLocal() as db:
        entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
        assert entry.key == candidate.key
        assert decrypt_secret(entry.encrypted_value) == "FixtureCredentialCurrentPassword!"


def test_vcf_import_rotates_matching_legacy_key_and_keeps_operator_uris(client, monkeypatch):
    """Rotate one matching legacy key while preserving its operator URI positions.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    natural_key = "vcf.legacy.admin"
    operator_uris = ("https://operator-a.example.internal", "ssh://operator-b.example.internal")
    csrf, vault_id = _seed_legacy_vcf_import_entry(
        client,
        natural_key=natural_key,
        secret_value="LegacySecret!",
        username="admin",
        resource_name="manager.example.internal",
        secret_type="vcf_password",
        source_type="sddc_manager",
        source_endpoint="sddc-manager.example.internal:443",
        uris=operator_uris,
    )
    candidate = _canonical_test_vcf_candidate(
        candidate_id="matching-legacy-credential",
        natural_key=natural_key,
        value="CurrentSecret!",
    )

    response = _post_fake_vcf_import(
        client,
        monkeypatch,
        csrf=csrf,
        vault_id=vault_id,
        candidates=[candidate],
        address="sddc-manager.example.internal",
    )

    assert response.status_code == 200
    assert response.json()["imported_keys"] == [natural_key]
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        assert len(entries) == 1
        entry = entries[0]
        assert entry.key == natural_key
        assert decrypt_secret(entry.encrypted_value) == "CurrentSecret!"
        assert json.loads(entry.uris_json) == list(operator_uris)
        assert entry.source_type == "sddc_manager"
        assert entry.source_endpoint == "sddc-manager.example.internal:443"


@pytest.mark.parametrize(
    "entry_kind, stored_address, current_address, expected_endpoint",
    [
        (
            "canonical",
            "SDDC-MANAGER.Example.Internal.",
            "sddc-manager.example.internal",
            "sddc-manager.example.internal:443",
        ),
        (
            "legacy",
            "sddc-manager.example.internal",
            "SDDC-MANAGER.Example.Internal.",
            "sddc-manager.example.internal:443",
        ),
        (
            "canonical",
            "2001:0db8:0000:0000:0000:0000:0000:0010",
            "2001:db8::10",
            "2001:db8::10:443",
        ),
        (
            "legacy",
            "2001:db8::10",
            "2001:0db8:0000:0000:0000:0000:0000:0010",
            "2001:db8::10:443",
        ),
    ],
)
def test_vcf_import_preserves_operator_uris_for_equivalent_source_spellings(
    client, monkeypatch, entry_kind, stored_address, current_address, expected_endpoint
):
    """Preserve operator URI positions when equivalent source spellings rotate a credential.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
        entry_kind: Existing canonical or legacy key format under test.
        stored_address: Host spelling persisted before the password refresh.
        current_address: Equivalent source spelling used by the refresh request.
        expected_endpoint: Canonical host and port expected after the refresh.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    natural_key = "vcf.legacy.admin"
    operator_uris = ("https://operator-a.example.internal", "ssh://operator-b.example.internal")
    candidate = _canonical_test_vcf_candidate(
        candidate_id=f"equivalent-source-{entry_kind}-{stored_address}",
        natural_key=natural_key,
        value="InitialEquivalentSourceSecret!",
        uris=(),
    )
    if entry_kind == "legacy":
        csrf, vault_id = _seed_legacy_vcf_import_entry(
            client,
            natural_key=natural_key,
            secret_value="PriorEquivalentSourceSecret!",
            username="admin",
            resource_name=candidate.resource_name,
            secret_type=candidate.secret_type,
            source_type="sddc_manager",
            source_endpoint=f"{stored_address}:443",
            uris=operator_uris,
        )
    else:
        csrf, vault_id = _create_empty_vcf_import_vault(client)
        first_import = _post_fake_vcf_import(
            client,
            monkeypatch,
            csrf=csrf,
            vault_id=vault_id,
            candidates=[candidate],
            address=stored_address,
        )
        assert first_import.status_code == 200
        with SessionLocal() as db:
            entry = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalar_one()
            entry.source_endpoint = f"{stored_address}:443"
            entry.uris_json = json.dumps(operator_uris)
            db.commit()

    refreshed = _canonical_test_vcf_candidate(
        candidate_id=candidate.candidate_id,
        natural_key=natural_key,
        value="CurrentEquivalentSourceSecret!",
        uris=(),
    )
    rotated = _post_fake_vcf_import(
        client,
        monkeypatch,
        csrf=csrf,
        vault_id=vault_id,
        candidates=[refreshed],
        address=current_address,
    )

    assert rotated.status_code == 200
    expected_key = natural_key if entry_kind == "legacy" else candidate.key
    assert rotated.json()["imported_keys"] == [expected_key]
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        assert len(entries) == 1
        entry = entries[0]
        assert entry.key == expected_key
        assert decrypt_secret(entry.encrypted_value) == "CurrentEquivalentSourceSecret!"
        assert json.loads(entry.uris_json) == list(operator_uris)
        assert entry.source_type == "sddc_manager"
        assert entry.source_endpoint == expected_endpoint


def test_vcf_import_does_not_preserve_operator_uris_across_source_port_change(client, monkeypatch):
    """Treat a changed source port as a different identity when rotating operator URIs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    natural_key = "vcf.legacy.port_guard"
    operator_uris = ("https://operator.example.internal",)
    csrf, vault_id = _seed_legacy_vcf_import_entry(
        client,
        natural_key=natural_key,
        secret_value="PriorPortGuardSecret!",
        username="admin",
        resource_name="manager.example.internal",
        secret_type="vcf_password",
        source_type="sddc_manager",
        source_endpoint="sddc-manager.example.internal:443",
        uris=operator_uris,
    )
    candidate = _canonical_test_vcf_candidate(
        candidate_id="changed-source-port-credential",
        natural_key=natural_key,
        value="NewPortGuardSecret!",
        uris=(),
    )
    monkeypatch.setattr(ui, "_confirmed_tls_fingerprint", lambda *_args: ("AA:BB", None))
    monkeypatch.setattr(ui, "discover_vcf_passwords", lambda **_kwargs: [candidate])
    response = client.post(
        "/vcf-helper/vault-import",
        json={
            "csrf": csrf,
            "source_type": "sddc_manager",
            "address": "sddc-manager.example.internal",
            "port": 8443,
            "confirmed_fingerprint": "AA:BB",
            "username": "admin",
            "password": "FixtureSourcePassword!",
            "vault_id": vault_id,
            "candidate_ids": [candidate.selection_id],
        },
    )

    assert response.status_code == 200
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        by_key = {entry.key: entry for entry in entries}
        assert set(by_key) == {natural_key, candidate.key}
        assert decrypt_secret(by_key[natural_key].encrypted_value) == "PriorPortGuardSecret!"
        assert json.loads(by_key[natural_key].uris_json) == list(operator_uris)
        assert decrypt_secret(by_key[candidate.key].encrypted_value) == "NewPortGuardSecret!"
        assert json.loads(by_key[candidate.key].uris_json) == []
        assert by_key[candidate.key].source_endpoint == "sddc-manager.example.internal:8443"


def test_vcf_import_source_mismatch_keeps_legacy_entry_and_creates_canonical_key(client, monkeypatch):
    """Keep an old entry unchanged when the import source endpoint no longer matches.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    natural_key = "vcf.legacy.admin"
    old_uris = ("https://operator.example.internal",)
    csrf, vault_id = _seed_legacy_vcf_import_entry(
        client,
        natural_key=natural_key,
        secret_value="LegacySecret!",
        username="admin",
        resource_name="manager.example.internal",
        secret_type="vcf_password",
        source_type="sddc_manager",
        source_endpoint="sddc-manager.example.internal:443",
        uris=old_uris,
    )
    candidate = _canonical_test_vcf_candidate(
        candidate_id="changed-source-credential",
        natural_key=natural_key,
        value="NewSourceSecret!",
        uris=("https://new-source.example.internal",),
    )

    response = _post_fake_vcf_import(
        client,
        monkeypatch,
        csrf=csrf,
        vault_id=vault_id,
        candidates=[candidate],
        address="new-sddc-manager.example.internal",
    )

    assert response.status_code == 200
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        by_key = {entry.key: entry for entry in entries}
        assert set(by_key) == {natural_key, candidate.key}
        assert decrypt_secret(by_key[natural_key].encrypted_value) == "LegacySecret!"
        assert json.loads(by_key[natural_key].uris_json) == list(old_uris)
        assert decrypt_secret(by_key[candidate.key].encrypted_value) == "NewSourceSecret!"
        assert json.loads(by_key[candidate.key].uris_json) == ["https://new-source.example.internal"]
        assert by_key[candidate.key].source_endpoint == "new-sddc-manager.example.internal:443"


def test_ambiguous_legacy_key_does_not_rotate_existing_entry(client, monkeypatch):
    """Leave a legacy key untouched when multiple current candidates share its identity tuple.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    natural_key = "vcf.legacy.admin"
    old_uris = ("https://operator.example.internal",)
    csrf, vault_id = _seed_legacy_vcf_import_entry(
        client,
        natural_key=natural_key,
        secret_value="LegacySecret!",
        username="admin",
        resource_name="manager.example.internal",
        secret_type="vcf_password",
        source_type="sddc_manager",
        source_endpoint="sddc-manager.example.internal:443",
        uris=old_uris,
    )
    candidates = [
        _canonical_test_vcf_candidate(
            candidate_id="ambiguous-credential-a",
            natural_key=natural_key,
            value="AmbiguousSecretA!",
        ),
        _canonical_test_vcf_candidate(
            candidate_id="ambiguous-credential-b",
            natural_key=natural_key,
            value="AmbiguousSecretB!",
        ),
    ]

    response = _post_fake_vcf_import(
        client,
        monkeypatch,
        csrf=csrf,
        vault_id=vault_id,
        candidates=candidates,
        address="sddc-manager.example.internal",
    )

    assert response.status_code == 200
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        by_key = {entry.key: entry for entry in entries}
        assert set(by_key) == {natural_key, *(candidate.key for candidate in candidates)}
        assert decrypt_secret(by_key[natural_key].encrypted_value) == "LegacySecret!"
        assert json.loads(by_key[natural_key].uris_json) == list(old_uris)
        assert decrypt_secret(by_key[candidates[0].key].encrypted_value) == "AmbiguousSecretA!"
        assert decrypt_secret(by_key[candidates[1].key].encrypted_value) == "AmbiguousSecretB!"


def test_legacy_natural_key_rotation_is_stable_with_different_resource_peer(client, monkeypatch):
    """Rotate the matching legacy account when a peer shares its normalized natural key.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace discovery and TLS confirmation.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VaultEntry
    from atlaso.app.secrets import decrypt_secret

    natural_key = "vcf.shared.admin"
    csrf, vault_id = _seed_legacy_vcf_import_entry(
        client,
        natural_key=natural_key,
        secret_value="LegacySecret!",
        username="admin",
        resource_name="manager-a.example.internal",
        secret_type="vcf_password",
        source_type="sddc_manager",
        source_endpoint="sddc-manager.example.internal:443",
        uris=("https://operator.example.internal",),
    )
    matching = _canonical_test_vcf_candidate(
        candidate_id="peer-a-credential",
        natural_key=natural_key,
        value="MatchingCurrentSecret!",
        resource_name="manager-a.example.internal",
    )
    other_resource = _canonical_test_vcf_candidate(
        candidate_id="peer-b-credential",
        natural_key=natural_key,
        value="OtherResourceSecret!",
        resource_name="manager-b.example.internal",
    )

    response = _post_fake_vcf_import(
        client,
        monkeypatch,
        csrf=csrf,
        vault_id=vault_id,
        candidates=[matching, other_resource],
        address="sddc-manager.example.internal",
    )

    assert response.status_code == 200
    with SessionLocal() as db:
        entries = db.execute(select(VaultEntry).where(VaultEntry.vault_id == vault_id)).scalars().all()
        by_key = {entry.key: entry for entry in entries}
        assert set(by_key) == {natural_key, other_resource.key}
        assert decrypt_secret(by_key[natural_key].encrypted_value) == "MatchingCurrentSecret!"
        assert json.loads(by_key[natural_key].uris_json) == ["https://operator.example.internal"]
        assert decrypt_secret(by_key[other_resource.key].encrypted_value) == "OtherResourceSecret!"


def test_vcf_helper_vault_picker_resolves_password_only_on_server(client, monkeypatch):
    """Verify that vcf helper vault picker resolves password only on server.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
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
        """Return discover.

        Args:
            **kwargs: Additional keyword arguments accepted by the callable.
        """
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
    """Verify that vcf helper vault picker never loads password into browser state."""
    source = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    picker = source.split("function initializeVcfVaultCredentialPickers()", 1)[1].split(
        "function initializeVcfTrustForm()", 1
    )[0]
    assert "Stored vault password will be used" in picker
    assert 'passwordControl.value = ""' in picker
    assert "entry.password" not in picker
    assert "credential_vault_id" in source
    assert "credential_entry_id" in source

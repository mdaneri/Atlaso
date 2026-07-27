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
            "secret_type": "vcf_password",
            "value": "Correct-Horse-Battery-Staple!",
            "username": "administrator@vsphere.local",
            "resource_name": "sddc-manager.example.internal",
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


def test_dynamic_kickstart_resolves_assigned_vault_without_caching(client):
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import EsxiKickstart, EsxiKickstartVaultBinding, EsxiPxeHost, Vault
    from atlaso.app.services.esxi_pxe import content_hash
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry

    content = "vmaccepteula\nrootpw {{vault.esx.host.root}}\n"
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
                value="VMware1!",
            ),
            actor="admin",
        )
        kickstart = EsxiKickstart(
            name="Vaulted ESX",
            content=content,
            content_hash=content_hash(content),
            enabled=True,
        )
        db.add(kickstart)
        db.flush()
        db.add(EsxiKickstartVaultBinding(kickstart_id=kickstart.id, vault_id=vault.id))
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

    response = client.get(path)
    assert response.status_code == 200
    assert "rootpw VMware1!" in response.text
    assert "{{vault." not in response.text
    assert "no-store" in response.headers["cache-control"]


def test_vault_javascript_uses_shared_grid_wizard_and_timed_eye():
    source = Path("atlaso/app/static/app.js").read_text()
    assert "initializeVaultsPage" in source
    assert "AtlasoUiPatterns.createGrid" in source
    assert "AtlasoUiPatterns.createWizard" in source
    assert "data-vault-password-eye" in source
    assert "15000" in source


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
    from atlaso.app.services.vaults import VaultEntryInput, upsert_vault_entry
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
                {"revision_id": revision.id, "arguments": [], "vault_id": vault.id}
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

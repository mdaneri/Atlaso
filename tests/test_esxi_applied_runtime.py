"""Exercise the real ESXi Apply projection, persistence, and boot admission chain."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

import atlaso.app.services.network_boot as boot
import atlaso.app.ui as ui
from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    EsxiKickstart,
    EsxiPxeHost,
    Job,
    JobStep,
    NetworkBootEsxiBootCapability,
    Setting,
)
from atlaso.app.secrets import decrypt_secret


@pytest.fixture()
def applied_boot_fixture(client, monkeypatch, tmp_path):
    """Supply an isolated host while retaining real Apply orchestration and storage."""
    root = tmp_path / 'pxe'
    monkeypatch.setattr(ui, 'ESXI_PXE_STAGED_CONFIG_PATH', str(root / 'staged.json'))
    monkeypatch.setattr(boot, 'ESXI_PXE_HTTP_BASE', root / 'http')
    monkeypatch.setattr(boot, 'ESXI_TFTP_ROOT', root / 'tftp')
    monkeypatch.setattr(boot, 'prune_superseded_shredos_media', lambda db: 0)
    # Logging is independently covered; avoid default host paths in this fixture.
    monkeypatch.setattr(ui, 'log_appliance_apply_submission', lambda *a, **k: None)
    source = 'rootpw fixture-only-not-a-real-password\nreboot\n'
    with SessionLocal() as db:
        kickstart = EsxiKickstart(name='runtime-probe', content=source, content_hash=hashlib.sha256(source.encode()).hexdigest(), enabled=True)
        db.add(kickstart)
        db.flush()
        host = EsxiPxeHost(hostname='runtime-probe', mac_address='00:50:56:aa:bb:cc', ip_address='192.0.2.10', kickstart_id=kickstart.id, installer_iso_path='/fixture/esxi.iso', variables_json='{}', enabled=True)
        db.add(host)
        db.commit()
        host_id, kickstart_id = host.id, kickstart.id

    state = SimpleNamespace(dry_run=False, failure=False, after_apply=None, staged=[], counter=0)

    def units(db, **kwargs):
        host = db.get(EsxiPxeHost, host_id)
        kickstart = db.get(EsxiKickstart, kickstart_id)
        manifest = {
            'kind': 'atlaso-esxi-pxe',
            'boot': {'http_port': 8080, 'listen_address': '192.0.2.1'},
            'network_boot': {'environments': boot.desired_environment_manifest_rows(db)},
            'hosts': [{'id': host.id, 'hostname': host.hostname, 'mac_address': host.mac_address, 'ip_address': host.ip_address, 'kickstart_id': kickstart.id, 'installer_iso_path': host.installer_iso_path, 'enabled': host.enabled, 'variables': json.loads(host.variables_json), 'host_uuid': '12345678-1234-1234-1234-123456789abc'}],
            'kickstarts': [{'id': kickstart.id, 'enabled': True, 'content': kickstart.content, 'content_hash': kickstart.content_hash}],
            'artifacts': [{'host_id': host.id, 'hostname': host.hostname, 'mac_key': '01-00-50-56-aa-bb-cc', 'kickstart_id': kickstart.id, 'is_default': False, 'image_http_url': 'http://192.0.2.1:8080/pxe/esxi/images/fixture'}],
        }
        raw = json.dumps(manifest, indent=2, sort_keys=True)
        return [ui.make_appliance_apply_unit(unit_id='esxi_pxe', label='ESXi PXE', page_url='/esxi-pxe', context={'esxi_pxe_config_path': str(root / 'staged.json'), 'esxi_kickstarts': [kickstart]}, summary=['fixture'], validation_errors=[], config_path=str(root / 'staged.json'), config_preview=raw, baseline=ui.load_appliance_apply_baselines(db).get('esxi_pxe'), snapshot_marker={'protected_runtime_manifest': 1})]

    class Adapter:
        def __init__(self, **kwargs):
            self.dry_run = state.dry_run

        def validate_esxi_pxe_config(self, path):
            return AdapterResult(['fixture-validate'], self.dry_run)

        def apply_esxi_pxe_config(self, path):
            if not self.dry_run:
                state.staged.append(Path(path).read_text(encoding='utf-8'))
            if state.after_apply:
                state.after_apply()
            return AdapterResult(['fixture-apply'], self.dry_run, returncode=int(state.failure))

    monkeypatch.setattr(ui, 'SystemAdapter', Adapter)
    monkeypatch.setattr(ui, 'appliance_apply_units', units)

    def apply():
        state.counter += 1
        job_id = f'job_runtime_probe_{state.counter}'
        with SessionLocal() as db:
            unit = units(db)[0]
            job = Job(id=job_id, type='appliance-apply', status='pending', created_by='admin', result=json.dumps({'selected_units': ['esxi_pxe'], 'captured_units': [{'unit_id': 'esxi_pxe', 'snapshot_hash': unit['snapshot_hash']}], 'units': [], 'dry_run': False}))
            db.add(job)
            db.add(JobStep(id=f'{job_id}:esxi_pxe', job=job, component_key='esxi_pxe', label='ESXi PXE', position=1, status='pending', result='{}'))
            db.commit()
        ui.run_appliance_apply_job(job_id)
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            assert job.status == ('failed' if state.failure else 'succeeded'), job.error
            assert source not in job.result
        return job_id

    state.apply = apply
    state.units = units
    state.host_id = host_id
    state.kickstart_id = kickstart_id
    return state


@pytest.mark.parametrize('content', [
    'rootpw fixture-only-not-a-real-password\nreboot\n',
    'rootpw {{vault.fixture.root.password}}\nreboot\n',
    '# password is managed separately\nreboot\n',
])
def test_real_apply_retains_exact_encrypted_source_and_creates_console_claim(applied_boot_fixture, content):
    """A redacted preview must coexist with usable exact applied authorization state."""
    fixture = applied_boot_fixture
    with SessionLocal() as db:
        kickstart = db.get(EsxiKickstart, fixture.kickstart_id)
        kickstart.content = content
        kickstart.content_hash = hashlib.sha256(content.encode()).hexdigest()
        db.commit()
    fixture.apply()
    with SessionLocal() as db:
        baseline = ui.load_appliance_apply_baselines(db)['esxi_pxe']
        assert content not in json.dumps(baseline)
        assert json.loads(baseline['config_preview'])['kickstarts'][0]['content'] == '[redacted]'
        assert decrypt_secret(baseline['runtime_config_encrypted']) == fixture.staged[0]
        assert boot._applied_esxi_pxe_manifest(db)['kickstarts'][0]['content'] == content
        assert not fixture.units(db)[0]['changed']
        row = json.loads(baseline['config_preview'])['hosts'][0]
        assert (row['ip_address'], row['mac_address'], row['host_uuid']) == ('192.0.2.10', '00:50:56:aa:bb:cc', '12345678-1234-1234-1234-123456789abc')
        menu = boot.render_network_boot_menu(db, mac_address='00:50:56:aa:bb:cc', request_origin='http://192.0.2.1:8080')
        assert 'Console code:' in menu
        assert 'cannot be authorized' not in menu
        assert content not in menu
        claim = db.scalars(select(NetworkBootEsxiBootCapability)).one()
        assert claim.authorized_at is None and claim.token_hash is None
        assert not boot.esxi_boot_readiness_warnings(db, [db.get(EsxiPxeHost, fixture.host_id)])


@pytest.mark.parametrize('dry_run,failure', [(True, False), (False, True)])
def test_unsuccessful_real_apply_preserves_previous_protected_runtime(applied_boot_fixture, dry_run, failure):
    """Dry runs and helper failures cannot publish a new runtime snapshot."""
    fixture = applied_boot_fixture
    fixture.apply()
    with SessionLocal() as db:
        previous = ui.load_appliance_apply_baselines(db)['esxi_pxe']['runtime_config_encrypted']
        host = db.get(EsxiPxeHost, fixture.host_id)
        host.ip_address = '192.0.2.11'
        db.commit()
    fixture.dry_run, fixture.failure = dry_run, failure
    fixture.apply()
    with SessionLocal() as db:
        assert ui.load_appliance_apply_baselines(db)['esxi_pxe']['runtime_config_encrypted'] == previous
        assert boot._applied_esxi_pxe_manifest(db)['hosts'][0]['ip_address'] == '192.0.2.10'
        assert fixture.units(db)[0]['changed']
        with pytest.raises(ValueError, match='differs from applied state'):
            boot.create_esxi_boot_claim(db, host_id=fixture.host_id, request_origin='http://192.0.2.1:8080')


def test_apply_concurrent_edit_stays_pending_and_does_not_replace_staged_snapshot(applied_boot_fixture):
    """A desired edit during helper execution must not become applied evidence."""
    fixture = applied_boot_fixture

    def concurrent_edit():
        with SessionLocal() as db:
            db.get(EsxiPxeHost, fixture.host_id).ip_address = '192.0.2.11'
            db.commit()

    fixture.after_apply = concurrent_edit
    fixture.apply()
    with SessionLocal() as db:
        assert boot._applied_esxi_pxe_manifest(db)['hosts'][0]['ip_address'] == '192.0.2.10'
        assert fixture.units(db)[0]['changed']
        assert boot.esxi_boot_readiness_warnings(db, [db.get(EsxiPxeHost, fixture.host_id)])


def test_media_activation_receipt_does_not_create_another_pending_apply(applied_boot_fixture):
    """A successful Apply activates captured media without changing desired input."""
    fixture = applied_boot_fixture
    with SessionLocal() as db:
        state = next(row for row in boot.ensure_environment_rows(db) if row.key == 'memtest86plus')
        state.enabled = True
        state.desired_version = '8.10'
        db.commit()
    fixture.apply()
    with SessionLocal() as db:
        state = next(row for row in boot.ensure_environment_rows(db) if row.key == 'memtest86plus')
        assert state.active_version == '8.10'
        assert not fixture.units(db)[0]['changed']


def test_invalid_encrypted_snapshot_fails_closed_without_legacy_fallback(applied_boot_fixture):
    """Corrupt protected evidence cannot silently reactivate a legacy preview."""
    fixture = applied_boot_fixture
    fixture.apply()
    with SessionLocal() as db:
        baselines = ui.load_appliance_apply_baselines(db)
        baselines['esxi_pxe']['runtime_config_preview'] = fixture.staged[0]
        baselines['esxi_pxe']['runtime_config_encrypted'] = 'fernet:v1:invalid'
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
    with SessionLocal() as db:
        assert boot._applied_esxi_pxe_manifest(db) == {}
        assert fixture.units(db)[0]['changed']
        warnings = boot.esxi_boot_readiness_warnings(db, [db.get(EsxiPxeHost, fixture.host_id)])
        assert warnings and 'real ESXi PXE Apply' in warnings[0]
        assert 'invalid' not in warnings[0]


def test_legacy_redacted_snapshot_recovers_only_through_real_apply(applied_boot_fixture):
    """Upgrades preserve failure until real Apply records a new protected snapshot."""
    fixture = applied_boot_fixture
    with SessionLocal() as db:
        unit = fixture.units(db)[0]
        ui.update_appliance_apply_baselines(db, [unit], {'esxi_pxe'})
        db.commit()
        with pytest.raises(ValueError, match='revision is invalid'):
            boot._applied_esxi_boot_context(db, host_id=fixture.host_id)
    fixture.dry_run = True
    fixture.apply()
    with SessionLocal() as db:
        assert fixture.units(db)[0]['changed']
        assert 'runtime_config_encrypted' not in ui.load_appliance_apply_baselines(db)['esxi_pxe']
    fixture.dry_run = False
    fixture.apply()
    with SessionLocal() as db:
        assert boot._applied_esxi_boot_context(db, host_id=fixture.host_id)
        # Neither internal baseline field belongs to portable settings archives.
        from atlaso.app.services.settings_archive import SAFE_SETTING_KEYS
        assert boot.APPLIANCE_APPLY_BASELINES_KEY not in SAFE_SETTING_KEYS
        baseline_row = db.scalar(select(Setting).where(Setting.key == boot.APPLIANCE_APPLY_BASELINES_KEY))
        assert 'fixture-only-not-a-real-password' not in baseline_row.value

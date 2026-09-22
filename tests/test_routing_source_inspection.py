"""Validate the predeployment source inspector without appliance changes."""

import json
from types import SimpleNamespace

import pytest

from scripts.interop import routing_source_inspection as inspection


def test_source_inspection_keeps_missing_intent_and_service_truth(monkeypatch):
    """An old source without routing support is evidence, never an invented pass.

    Args:
        monkeypatch: Isolate native commands and installed metadata.
    """
    calls = []

    def run(command, **kwargs):
        """Return the fixed native service response.

        Args:
            command: Fixed read-only systemctl invocation.
            **kwargs: Bounded subprocess options.
        """
        calls.append((command, kwargs))
        return SimpleNamespace(stdout='LoadState=not-found\nActiveState=inactive\nUnitFileState=\n', returncode=0)

    monkeypatch.setattr(inspection.subprocess, 'run', run)
    monkeypatch.setattr(inspection.importlib.metadata, 'version', lambda _name: '0.9.367')
    monkeypatch.setattr(inspection, 'public_intent', lambda: None)
    evidence = inspection.source_evidence()
    assert evidence['phase'] == 'before-lifecycle-deployment'
    assert evidence['routing_intent'] is None
    assert evidence['routing_service']['LoadState'] == 'not-found'
    assert calls[0][0][:3] == ['systemctl', 'show', 'atlaso-route-domains.service']
    assert calls[0][1]['timeout'] == 10


@pytest.mark.parametrize('fault', [None, 'secret-field', 'invalid-interface', 'oversized'])
def test_source_intent_allows_only_public_network_fields(tmp_path, monkeypatch, fault):
    """Reject arbitrary file content instead of writing it to retained evidence.

    Args:
        tmp_path: Owned validation output directory.
        monkeypatch: Supply Linux no-follow constant for an ordinary Windows test file.
        fault: Invalid intent field or bound.
    """
    monkeypatch.setattr(inspection.os, 'O_NOFOLLOW', getattr(inspection.os, 'O_NOFOLLOW', 0), raising=False)
    row = {'name': 'eth0', 'mac': '00:50:56:20:00:01', 'table': 100}
    payload = {'schema': 1, 'interfaces': [row]}
    if fault == 'secret-field':
        payload['password'] = 'must-not-appear'
    elif fault == 'invalid-interface':
        row['name'] = 'must-not-appear;'
    path = tmp_path / 'routing-intent.json'
    path.write_text('x' * 65537 if fault == 'oversized' else json.dumps(payload))
    if fault:
        with pytest.raises(ValueError) as error:
            inspection.public_intent(path)
        assert 'must-not-appear' not in str(error.value)
    else:
        assert inspection.public_intent(path) == {**payload, 'held_addresses': []}


@pytest.mark.parametrize('flag', [True, False, None, 'true', 1, 0, {}, []])
def test_source_intent_validates_optional_management_flag(tmp_path, monkeypatch, flag):
    """Accept emitted Boolean eligibility without widening the public allowlist.

    Args:
        tmp_path: Owned validation output directory.
        monkeypatch: Supply the Linux no-follow constant on Windows.
        flag: Candidate management eligibility value.
    """
    monkeypatch.setattr(inspection.os, 'O_NOFOLLOW', getattr(inspection.os, 'O_NOFOLLOW', 0), raising=False)
    row = {'name': 'eth1', 'mac': '02:00:00:00:00:01', 'table': 200, 'management_ui': flag}
    payload = {'schema': 1, 'interfaces': [row], 'held_addresses': []}
    path = tmp_path / 'routing-intent.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    if type(flag) is bool:
        assert inspection.public_intent(path) == payload
        row['unexpected'] = 'must-not-appear'
        path.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ValueError) as error:
        inspection.public_intent(path)
    assert 'must-not-appear' not in str(error.value)

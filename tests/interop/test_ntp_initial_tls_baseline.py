"""The initial applied leaf settles before independent NTP-only transitions."""

import ssl
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as fixture  # noqa: E402 - Native acceptance consumer.

CURRENT = "192.168.77.10"
APPLIED = {"sha256": "a" * 64, "ip_sans": [CURRENT]}
BOOTSTRAP = {"sha256": "b" * 64, "ip_sans": ["192.168.167.185"]}


@pytest.fixture
def baseline(monkeypatch, tmp_path):
    """Replace TLS and Apply boundaries while retaining real convergence control.

    Args:
        monkeypatch: Scoped transport and monotonic-clock replacements.
        tmp_path: Original synthetic journal root.
    """
    clock = [0.0]
    monkeypatch.setattr(fixture, "time", SimpleNamespace(monotonic=lambda: clock[0],
                                                        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds)))
    raw = Mock()
    client = SimpleNamespace(url="https://original.fixture.test",
                             peer=SimpleNamespace(open_socket=Mock(return_value=raw), topology_guard=Mock()))
    probe = SimpleNamespace(tls_identity=Mock(side_effect=[BOOTSTRAP, APPLIED, APPLIED]))
    constructor = Mock(return_value=probe)
    monkeypatch.setattr(fixture, "Client", constructor)
    apply = Mock(return_value={"job_id": "baseline-job", "status": "succeeded"})
    monkeypatch.setattr(fixture, "apply_once", apply)
    return SimpleNamespace(client=client, probe=probe, constructor=constructor, apply=apply, raw=raw,
                           clock=clock, output=tmp_path, plan={"current_address": CURRENT, "ca_path": "original-ca.pem"})


def test_one_successful_initial_baseline_convergence_keeps_original_trust(baseline):
    """Bootstrap-address drift permits one separately journaled setup task.

    Args:
        baseline: Original verified client and controlled leaf observations.
    """
    result = fixture.initial_tls_baseline(baseline.client, baseline.plan, baseline.output, "operator", "synthetic")
    assert result["tls"] == APPLIED and result["equal_applied_leaf_samples"] == 2
    baseline.apply.assert_called_once_with(baseline.client, baseline.output, "ntp-native-baseline", "operator", "synthetic")
    args, kwargs = baseline.constructor.call_args
    assert args == ("https://original.fixture.test", "original-ca.pem") and kwargs["connect_ip"] == CURRENT
    assert kwargs["peer"].open_socket(CURRENT) is baseline.raw
    baseline.raw.settimeout.assert_called_once_with(8)


def test_already_applied_leaf_never_submits_an_extra_apply(baseline):
    """A normal settled first Apply needs only two equal verified samples.

    Args:
        baseline: Original transport stand-in with an already applied leaf.
    """
    baseline.probe.tls_identity.side_effect = [APPLIED, APPLIED, APPLIED]
    result = fixture.initial_tls_baseline(baseline.client, baseline.plan, baseline.output, "operator", "synthetic")
    assert result["convergence_task"] is None
    baseline.apply.assert_not_called()


def test_an_intermediate_leaf_cannot_be_mistaken_for_settled_identity(baseline):
    """Two consecutive equal applied leaves are required after a refresh.

    Args:
        baseline: Controlled original transport and leaf sequence.
    """
    intermediate = {"sha256": "c" * 64, "ip_sans": [CURRENT]}
    baseline.probe.tls_identity.side_effect = [BOOTSTRAP, intermediate, APPLIED, APPLIED]
    result = fixture.initial_tls_baseline(baseline.client, baseline.plan, baseline.output, "operator", "synthetic")
    assert result["tls"] == APPLIED and result["elapsed_seconds"] == 4
    assert baseline.apply.call_count == 1


@pytest.mark.parametrize("failure", ["failed-task", "trust", "unsettled"])
def test_failed_or_untrusted_baseline_is_not_replayed(baseline, failure):
    """No failure path renews the task or downgrades CA/hostname checks.

    Args:
        baseline: Original setup and TLS transport stand-ins.
        failure: Failed task, invalid certificate or missing applied-address leaf.
    """
    if failure == "failed-task":
        baseline.apply.return_value = {"job_id": "baseline-job", "status": "failed"}
    elif failure == "trust":
        baseline.probe.tls_identity.side_effect = ssl.SSLCertVerificationError("synthetic mismatch")
    else:
        baseline.probe.tls_identity.side_effect = None
        baseline.probe.tls_identity.return_value = BOOTSTRAP
    with pytest.raises((fixture.Refusal, ssl.SSLCertVerificationError)):
        fixture.initial_tls_baseline(baseline.client, baseline.plan, baseline.output, "operator", "synthetic")
    assert baseline.apply.call_count <= 1 and baseline.clock[0] <= 120

"""The initial applied leaf settles before independent NTP-only transitions."""

import itertools
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
def baseline(monkeypatch):
    """Replace TLS and Apply boundaries while retaining real convergence control.

    Args:
        monkeypatch: Scoped transport and monotonic-clock replacements.
    """
    clock = [0.0]
    monkeypatch.setattr(fixture, "time", SimpleNamespace(monotonic=lambda: clock[0],
                                                        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds)))
    raw = Mock()
    client = SimpleNamespace(url="https://original.fixture.test",
                             peer=SimpleNamespace(open_socket=Mock(return_value=raw), topology_guard=Mock()))
    probe = SimpleNamespace(tls_identity=Mock(side_effect=[BOOTSTRAP, BOOTSTRAP]))
    constructor = Mock(return_value=probe)
    monkeypatch.setattr(fixture, "Client", constructor)
    apply = Mock(side_effect=AssertionError("TLS observation must never submit Apply"))
    monkeypatch.setattr(fixture, "apply_once", apply)
    return SimpleNamespace(client=client, probe=probe, constructor=constructor, apply=apply, raw=raw,
                           clock=clock, plan={"current_address": CURRENT, "ca_path": "original-ca.pem"})


def test_original_dns_hostname_baseline_preserves_trust_without_apply(baseline):
    """A verified original DNS name remains bound even with a bootstrap IP SAN.

    Args:
        baseline: Original verified client and controlled leaf observations.
    """
    result = fixture.initial_tls_baseline(baseline.client, baseline.plan)
    assert result["tls"] == BOOTSTRAP and result["equal_verified_leaf_samples"] == 2
    assert result["no_apply_submitted"] is True
    baseline.apply.assert_not_called()
    args, kwargs = baseline.constructor.call_args
    assert args == ("https://original.fixture.test", "original-ca.pem") and kwargs["connect_ip"] == CURRENT
    assert kwargs["peer"].open_socket(CURRENT) is baseline.raw
    baseline.raw.settimeout.assert_called_once_with(8)


def test_already_applied_leaf_never_submits_an_extra_apply(baseline):
    """A normal settled first Apply needs only two equal verified samples.

    Args:
        baseline: Original transport stand-in with an already applied leaf.
    """
    baseline.probe.tls_identity.side_effect = [APPLIED, APPLIED]
    result = fixture.initial_tls_baseline(baseline.client, baseline.plan)
    assert result["no_apply_submitted"] is True and result["tls"] == APPLIED
    baseline.apply.assert_not_called()


def test_an_intermediate_leaf_cannot_be_mistaken_for_settled_identity(baseline):
    """Two consecutive equal applied leaves are required after a refresh.

    Args:
        baseline: Controlled original transport and leaf sequence.
    """
    intermediate = {"sha256": "c" * 64, "ip_sans": [CURRENT]}
    baseline.probe.tls_identity.side_effect = [intermediate, APPLIED, APPLIED]
    result = fixture.initial_tls_baseline(baseline.client, baseline.plan)
    assert result["tls"] == APPLIED and result["elapsed_seconds"] == 4
    baseline.apply.assert_not_called()


@pytest.mark.parametrize("failure", ["trust", "unsettled"])
def test_untrusted_or_unsettled_baseline_never_submits_apply(baseline, failure):
    """No failure path submits a task or downgrades CA/hostname checks.

    Args:
        baseline: Original setup and TLS transport stand-ins.
        failure: Invalid certificate or continuously changing leaf identity.
    """
    if failure == "trust":
        baseline.probe.tls_identity.side_effect = ssl.SSLCertVerificationError("synthetic mismatch")
    else:
        baseline.probe.tls_identity.side_effect = itertools.cycle([BOOTSTRAP, APPLIED])
    with pytest.raises((fixture.Refusal, ssl.SSLCertVerificationError)):
        fixture.initial_tls_baseline(baseline.client, baseline.plan)
    assert baseline.apply.call_count == 0 and baseline.clock[0] <= 120


@pytest.mark.parametrize("target,port", [("192.168.77.99", 443), (CURRENT, 8443)])
def test_tls_observation_cannot_redirect_the_original_transport(baseline, target, port):
    """Sampling retains only the receipt-bound management address and HTTPS port.

    Args:
        baseline: Original trusted origin and controlled transport.
        target: Altered destination to refuse.
        port: Altered destination port to refuse.
    """
    fixture.initial_tls_baseline(baseline.client, baseline.plan)
    with pytest.raises(fixture.Refusal, match="destination_changed"):
        baseline.constructor.call_args.kwargs["peer"].open_socket(target, port)

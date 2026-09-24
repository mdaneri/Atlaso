"""Exercise admission and bounded transport before real private fixture operations."""

import base64
import copy
import json

import pytest

from scripts.interop.routing_overlap import OverlapPrerequisiteError
from scripts.interop.routing_overlap_runner import (
    ControllerFailure,
    FixtureSession,
    bounded_json_command,
    run_client_phase,
    scenario_failure_result,
)
from scripts.interop.routing_overlap_scenario import (
    ApplyOutcomeUnknown,
    RestorationIncomplete,
)
from tests import test_routing_overlap_lifecycle


@pytest.fixture
def descriptor():
    """Extend independently generated topology with observed control addresses.

    """
    value = copy.deepcopy(test_routing_overlap_lifecycle.topology_inputs.__wrapped__())
    owner = value.pop('owner')
    value['schema'] = 1
    value['receipt_bytes'] = {key: base64.b64encode(raw).decode() for key, raw in value['receipt_bytes'].items()}
    value['peers'] = {}
    for number, role in enumerate(('client-a', 'client-b'), 20):
        address = f'192.168.167.{number}'
        value['peers'][role] = {'host': address, 'ssh_public_key': 'unused', 'controller': '/tmp/atlaso-overlap-' + 'a' * 32 + '.py'}
        for link in value['guest_links']:
            link.setdefault('addresses', [])
            if link['role'] == role and link['interface'] == 'eth0':
                link['addresses'] = [address + '/24']
    return value, owner


@pytest.mark.parametrize('fault', ['other-interface', 'outside-control', 'duplicate-peer', 'controller-path'])
def test_control_peer_requires_actual_admitted_nic(descriptor, fault):
    """Reject a spoofed control address before any SSH connection exists.

    Args:
        descriptor: Synthetic original topology and live guest observations.
        fault: One conflicting connection or script identity.
    """
    value, owner = descriptor
    if fault == 'other-interface':
        for link in value['guest_links']:
            if link['role'] == 'client-a' and link['interface'] == 'eth0':
                link['addresses'] = []
    elif fault == 'outside-control':
        value['peers']['client-a']['host'] = '192.0.2.10'
    elif fault == 'duplicate-peer':
        value['peers']['client-b']['host'] = value['peers']['client-a']['host']
    else:
        value['peers']['client-a']['controller'] = '/tmp/controller.py; false'
    with pytest.raises(ValueError):
        FixtureSession(value, owner, 'alpine', 'fixture-only')


def test_session_admission_is_side_effect_free(descriptor):
    """Public admission opens no SSH connection and binds the complete descriptor.

    Args:
        descriptor: Synthetic original topology and live guest observations.
    """
    value, owner = descriptor
    session = FixtureSession(value, owner, 'alpine', 'fixture-only')
    assert not session.clients
    assert len(session.digest) == 64
    session.close()


@pytest.mark.parametrize(("failure", "exit_code", "unknown", "incomplete"), [
    (OverlapPrerequisiteError("scenario failed"), 2, False, False),
    (ApplyOutcomeUnknown("accepted task unresolved"), 3, True, False),
    (RestorationIncomplete("baseline Apply failed"), 3, False, True),
])
def test_scenario_exit_preserves_fixture_until_restoration_is_proven(
    failure, exit_code, unknown, incomplete,
):
    """A definite restoration failure must bypass client stop and VM cleanup.

    Args:
        failure: Classified scenario failure reason.
        exit_code: Expected fixture-preservation exit status.
        unknown: Whether completion of the mutation is uncertain.
        incomplete: Whether restoration remains incomplete.
    """
    result, actual_exit = scenario_failure_result(failure, "a" * 64)
    assert actual_exit == exit_code
    assert result["apply_outcome_unknown"] is unknown
    assert result["restoration_incomplete"] is incomplete
    assert result["preserve_fixture"] is (exit_code == 3)


def test_bootstrap_rolls_back_only_client_with_validated_start_receipt():
    """A missing client-a receipt still stops already started client-b."""
    from unittest.mock import Mock

    fixture = Mock()

    def action(role, operation):
        """Return a receipt except for the client-a start.

        Args:
            role: Client role selected by the phase.
            operation: Requested client controller operation.
        """
        if (role, operation) == ('client-a', 'start'):
            raise TimeoutError('missing receipt')
        return {'role': role, 'operation': operation}

    fixture.action.side_effect = action
    with pytest.raises(TimeoutError, match='missing receipt'):
        run_client_phase(fixture, 'bootstrap')
    assert fixture.action.call_args_list == [
        (('client-b', 'start'),), (('client-a', 'start'),), (('client-b', 'stop'),),
    ]


def test_stop_attempts_other_client_after_first_failure():
    """A failed client-a stop cannot prevent client-b cleanup."""
    from unittest.mock import Mock

    fixture = Mock()

    def action(role, operation):
        """Fail client-a stop while permitting client-b stop.

        Args:
            role: Client role selected by the phase.
            operation: Requested client controller operation.
        """
        if role == 'client-a':
            raise TimeoutError('unavailable')
        return {'role': role, 'operation': operation}

    fixture.action.side_effect = action
    with pytest.raises(ValueError, match='fixture client stop failed'):
        run_client_phase(fixture, 'stop')
    assert fixture.action.call_args_list == [
        (('client-a', 'stop'),), (('client-b', 'stop'),),
    ]


def test_bootstrap_reports_failed_rollback_without_trusting_missing_receipt():
    """A failed rollback stays explicit and never targets the uncertain peer."""
    from unittest.mock import Mock

    fixture = Mock()

    def action(role, operation):
        """Fail the uncertain start and the proven peer rollback.

        Args:
            role: Client role selected by the phase.
            operation: Requested client controller operation.
        """
        if (role, operation) == ('client-a', 'start'):
            raise TimeoutError('missing receipt')
        if (role, operation) == ('client-b', 'stop'):
            raise TimeoutError('stop unavailable')
        return {'role': role, 'operation': operation}

    fixture.action.side_effect = action
    with pytest.raises(ValueError, match='fixture bootstrap rollback failed'):
        run_client_phase(fixture, 'bootstrap')
    assert fixture.action.call_args_list == [
        (('client-b', 'start'),), (('client-a', 'start'),), (('client-b', 'stop'),),
    ]


class Channel:
    """Minimal bounded command channel with observable cleanup."""

    def __init__(self, output, code=0):
        """Record queued output and terminal status.

        Args:
            output: Bytes returned by the simulated guest.
            code: Guest process exit status.
        """
        self.output, self.code, self.closed = output, code, False

    def settimeout(self, _value):
        """Accept a bounded timeout.

        Args:
            _value: Requested socket bound.
        """

    def exec_command(self, _command):
        """Accept a fixed controller command.

        Args:
            _command: Safe script command under test.
        """

    def sendall(self, _payload):
        """Accept public controller stdin.

        Args:
            _payload: Encoded request bytes.
        """

    def shutdown_write(self):
        """Finish controller stdin."""

    def recv_ready(self):
        """Report pending output."""
        return bool(self.output)

    def recv(self, _size):
        """Consume the queued output.

        Args:
            _size: Maximum chunk requested by the caller.
        """
        value, self.output = self.output, b''
        return value

    def recv_stderr_ready(self):
        """Expose no stderr content."""
        return False

    def exit_status_ready(self):
        """Report terminal status available."""
        return True

    def recv_exit_status(self):
        """Return terminal status."""
        return self.code

    def close(self):
        """Record release of the channel."""
        self.closed = True


@pytest.mark.parametrize('output,code,ok', [(b'{"schema":1,"ok":true}', 0, True),
    (b'private error omitted', 2, False), (b'x' * 262145, 0, False), (b'{}', 0, False)], ids=['valid', 'exit-error', 'oversized', 'invalid'])
def test_controller_errors_close_without_echoing_output(output, code, ok):
    """Successful and failed controller exchanges always release their channel.

    Args:
        output: Simulated guest bytes.
        code: Simulated process exit status.
        ok: Whether the result is a valid bounded controller reply.
    """
    channel = Channel(output, code)
    from unittest.mock import Mock
    client = Mock()
    client.get_transport.return_value.open_session.return_value = channel
    if ok:
        assert bounded_json_command(client, 'fixed', {}) == json.loads(output)
    else:
        with pytest.raises(ValueError) as failure:
            bounded_json_command(client, 'fixed', {})
        assert 'private error' not in str(failure.value)
    assert channel.closed


def test_controller_refusal_exposes_only_digest():
    """A guest refusal is correlatable without copying guest text to logs."""
    import hashlib
    from unittest.mock import Mock

    private = 'fixture requires an initially non-forwarding client'
    channel = Channel(json.dumps({'schema': 1, 'ok': False, 'error': private}).encode(), 2)
    client = Mock()
    client.get_transport.return_value.open_session.return_value = channel
    with pytest.raises(ControllerFailure) as failure:
        bounded_json_command(client, 'fixed', {})
    assert hashlib.sha256(private.encode()).hexdigest()[:16] in str(failure.value)
    assert private not in str(failure.value)
    assert channel.closed

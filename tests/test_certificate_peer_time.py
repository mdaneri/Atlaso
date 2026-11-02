"""Focused checks for the real private NTP fixture admission."""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_peer_time as clock  # noqa: E402 - Local receipt-bound interop module.

PEER = "192.168.77.1"
CLIENTS = ["192.168.77.10", "192.168.77.30", "192.168.77.40"]


class Peer:
    def __init__(self, *, change: str = ""):
        """Provide genuine-status-shaped public observations with one optional defect.

        Args:
            change: Public observation defect to inject.
        """
        self.change = change
        self.queried = False

    def command(self, command: str, stdin: bytes = b"") -> bytes:
        """Return isolated test observations; never contact a native peer.

        Args:
            command: Fixed read-only command selected by the verifier.
            stdin: Public UDP-query program carried over its SSH stdin.
        """
        config = clock.peer_time_files(PEER, CLIENTS)[clock.CONFIG]
        if command.startswith("for service"):
            return b"competing" if self.change == "competing" else b"chronyd_only\n"
        if command == "cat " + clock.CONFIG:
            return (config + ("allow all\n" if self.change == "file" else "")).encode()
        if command == "sudo -n chronyc -n tracking":
            reference = datetime.fromtimestamp(time.time() - (10000 if self.change == "stale" else 5), timezone.utc)
            return ("Stratum : 3\nSystem time : " + ("0.5" if self.change == "offset" else "0.000002")
                    + " seconds slow of NTP time\nLeap status : " + ("Not synchronised" if self.change == "unsynced" else "Normal")
                    + "\nRef time (UTC) : " + reference.strftime("%a %b %d %H:%M:%S %Y") + "\nUpdate interval : 60 seconds\n").encode()
        if command == "date -u +%s":
            return str(int(time.time()) + (30 if self.change == "clock" else 0)).encode()
        if command == "sudo -n chronyc -n sources":
            return ("^* " + (PEER if self.change == "self" else "192.0.2.8") + " 2 10 377 3 +0us\n").encode()
        if command == "sudo -n chronyd -p":
            if self.change == "scope":
                config += "allow 0.0.0.0/0\n"
            if self.change == "local":
                config += "local stratum 3\n"
            return config.encode()
        assert command == "python3 -I -B -"
        assert b"reply[24:32]==nonce" in stdin and b"client.recvfrom" in stdin
        assert b"reply[0]>>6!=3" in stdin and b"time.time())<2" in stdin
        self.queried = True
        return json.dumps({"stratum": 3, "real_udp_reply": self.change != "reply"}).encode()


def test_private_server_does_not_replace_the_existing_clock_authority():
    """Restrict service to the fixture while retaining genuine upstream discipline."""
    files = clock.peer_time_files(PEER, CLIENTS)
    config = files[clock.CONFIG]
    assert "bindaddress 192.168.77.1\n" in config and "bindaddress ::1\n" in config
    assert config.count("allow ") == 4
    assert "server " not in config and "local " not in config and "refclock" not in config
    installer = files[clock.INSTALLER]
    assert installer.index("chronyc waitsync") < installer.index('cp -p "$base"')
    assert "open-vm-tools-timesync" in installer
    assert "rc-service chronyd restart" in installer and "rc-service open-vm-tools" not in installer


def test_real_status_and_udp_query_are_both_required():
    """A native run needs independently observed synchronization and a real reply."""
    peer = Peer()
    result = clock.verify_peer_time(peer, PEER, CLIENTS)
    assert result["real_udp_reply"] is True and result["synchronized"] is True
    assert peer.queried is True


@pytest.mark.parametrize("change,reason", [
    ("competing", "competing_controller"), ("file", "configuration_changed"),
    ("unsynced", "not_synchronized"), ("self", "not_synchronized"),
    ("scope", "effective_scope_changed"), ("local", "synthetic_source_refused"), ("reply", "reply_invalid"),
    ("stale", "freshness_unproven"), ("offset", "freshness_unproven"),
])
def test_time_admission_refuses_unproven_or_expanded_serving(change, reason):
    """Reject unsafe time fixtures instead of treating service activity as health.

    Args:
        change: Defect in the fake public readback.
        reason: Required fixed refusal suffix.
    """
    with pytest.raises(clock.Refusal, match=reason):
        clock.verify_peer_time(Peer(change=change), PEER, CLIENTS)


def test_ntp_peer_does_not_adopt_the_windows_observers_clock_as_authority():
    """A healthy real NTP source remains authoritative if the observer is skewed."""
    result = clock.verify_peer_time(Peer(change="clock"), PEER, CLIENTS)
    assert result["synchronized"] is True and result["system_offset_seconds"] == 0.000002

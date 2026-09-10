"""Verify privacy boundaries and degraded recovery without touching a live appliance."""

import io
import json
import sqlite3
import sys
import time
import zipfile

import pytest

from atlaso.diagnostics import (
    Collector,
    EvidenceError,
    Options,
    Projection,
    read_source,
    write_new,
)


def test_options_defaults_and_bounds():
    options = Options.parse({})
    assert Options.parse({"correlation_id": "job_123456abcdef"}).correlation_id == "job_123456abcdef"
    assert not options.anonymize and not options.detailed_logs and options.scopes == ()
    with pytest.raises(ValueError):
        Options.parse({"scopes": ["/etc/shadow"]})
    with pytest.raises(ValueError):
        Options.parse({"since": "2026-01-01", "until": "2026-01-02"})
    with pytest.raises(ValueError):
        Options.parse({"correlation_id": "password=secret"})
    with pytest.raises(ValueError):
        Options.parse({"log_lines": 1000000})


def test_anonymization_consistent_but_ips_and_mac_preserved():
    projection = Projection(True)
    assert projection.identifier("myhost.example", "hostname") == "hostname0001"
    assert projection.identifier("MYHOST.EXAMPLE.", "hostname") == "hostname0001"
    assert projection.identifier("alice", "user") == "user0001"
    assert projection.identifier("alice", "user") == "user0001"
    assert projection.identifier("bob", "user") == "user0002"
    assert projection.identifier("192.0.2.1", "hostname") == "192.0.2.1"
    assert Projection(True).identifier("different", "hostname") == "hostname0001"
    assert projection.identifier("https://user:password@host", "hostname") is None


def test_degraded_capture_and_secret_free_entire_archive(tmp_path, monkeypatch):
    monkeypatch.setattr("atlaso.diagnostics.os.geteuid", lambda: 0, raising=False)
    options = Options.parse({"anonymize": True, "detailed_logs": True})
    collector = Collector(options, database=tmp_path / "absent.db")

    def command(args):
        if args[0] == "systemctl":
            return "ActiveState=failed\nSubState=failed\nNRestarts=3\nUser=alice\nEnvironment=TOPSECRET\nExecStart=customer document\n"
        return json.dumps({"_HOSTNAME": "private.example", "MESSAGE": "Authorization: Bearer TOPSECRET customer document https://alice:TOPSECRET@host", "PASSWORD": "TOPSECRET", "__REALTIME_TIMESTAMP": "12345", "PRIORITY": "3"})

    monkeypatch.setattr(collector, "command", command)
    monkeypatch.setattr("atlaso.diagnostics.platform.node", lambda: "private.example")
    data, manifest = collector.capture()
    assert manifest["status"] == "ready_with_omissions"
    assert not (tmp_path / "absent.db").exists()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        text = b"\n".join(archive.read(name) for name in archive.namelist()).decode()
        for excluded in ("TOPSECRET", "customer document", "private.example", "alice", "PASSWORD", "Authorization"):
            assert excluded not in text
        assert "hostname0001" in text and "user0001" in text
        assert "failed" in text and "NRestarts" in text
        assert "mapping_included" in text
        assert all(not name.startswith("/") and ".." not in name for name in archive.namelist())


def test_unknown_content_omitted_with_no_exception_leak(tmp_path, monkeypatch):
    collector = Collector(Options.parse({}), database=tmp_path / "missing")

    def fail(*args):
        raise ValueError("private-key=TOPSECRET")

    monkeypatch.setattr(collector, "command", fail)
    data, manifest = collector.capture()
    assert any(item["status"] == "failed" for item in manifest["collectors"])
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert all(b"TOPSECRET" not in archive.read(name) for name in archive.namelist())


def test_cancel_stops_and_timeout_preserves_partial(tmp_path):
    collector = Collector(Options.parse({}), database=tmp_path / "missing", cancelled=lambda: True)
    with pytest.raises(EvidenceError, match="cancelled"):
        collector.capture()
    collector = Collector(Options.parse({}), database=tmp_path / "missing")
    collector.deadline = time.monotonic() - 1
    _, manifest = collector.capture()
    assert all(item["status"] == "timed_out" for item in manifest["collectors"])


def test_file_limits_and_no_overwrite(tmp_path):
    target = tmp_path / "bundle.zip"
    write_new(target, b"safe")
    with pytest.raises(FileExistsError):
        write_new(target, b"replacement")
    assert target.read_bytes() == b"safe"
    with pytest.raises(EvidenceError, match="truncated"):
        read_source(target, limit=2)


def test_symlink_source_rejected(tmp_path):
    target = tmp_path / "secret"
    target.write_text("TOPSECRET")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Host does not grant symlink creation.")
    with pytest.raises(EvidenceError):
        read_source(link)


def test_recovery_does_not_import_application_database():
    # Importing the CLI itself must never run init_db or consume app settings.
    import ast
    from pathlib import Path

    tree = ast.parse(Path("atlaso/diagnostics.py").read_text())
    assert not any(isinstance(node, ast.ImportFrom) and (node.module or "").startswith("atlaso.app") for node in ast.walk(tree))
    assert sys.modules["atlaso.diagnostics"]


def test_readonly_database_projection_excludes_task_payloads(tmp_path):
    path = tmp_path / "test.db"
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE settings(key TEXT,value TEXT); CREATE TABLE jobs(id TEXT,type TEXT,status TEXT,created_at TEXT,started_at TEXT,finished_at TEXT,result TEXT);")
        db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)", ("0" * 36, "appliance-update", "failed", "2026-01-02 12:00:00", None, None, "TOPSECRET"))
        db.execute("CREATE TABLE network_boot_environments(key TEXT,enabled INTEGER)")
    before = path.read_bytes()
    options = Options.parse({"scopes": ["pxe"], "since": "2026-01-02T00:00:00Z", "until": "2026-01-03T00:00:00Z"})
    evidence = Collector(options, database=path).database_evidence()
    assert "TOPSECRET" not in json.dumps(evidence)
    assert evidence["tasks"][0]["status"] == "failed"
    assert path.read_bytes() == before


def test_optional_sources_project_identifiers_and_reject_payloads(monkeypatch, tmp_path):
    """Seed every optional file/command projection with data that must stay in memory."""
    monkeypatch.setattr("atlaso.diagnostics.os.geteuid", lambda: 0, raising=False)
    collector = Collector(Options.parse({"scopes": ["network", "terminal", "update", "pxe"], "anonymize": True}), database=tmp_path / "missing")
    secret = "TOPSECRET customer payload https://alice:TOPSECRET@host"

    def command(args):
        if args[0] == "ip":
            return json.dumps([{"ifname": "eth0", "address": "00:11:22:33:44:55", "local": "192.0.2.2", "dst": "192.0.2.0/24", "gateway": "192.0.2.1", "customer": secret, "addr_info": [{"local": "192.0.2.2", "prefixlen": 24, "secret": secret}]}])
        if args[0] == "ss":
            return "tcp LISTEN 0 128 192.0.2.2:443 0.0.0.0:* users:TOPSECRET\n"
        if args[0] == "resolvectl":
            return "Global: 192.0.2.53 " + secret
        if args[0] in {"iptables-save", "ip6tables-save"}:
            return ':INPUT DROP [0:0]\n-A INPUT -s 192.0.2.0/24 -p tcp --dport 443 -m comment --comment "TOPSECRET customer payload" -j ACCEPT\n'
        return "ActiveState=active\nEnvironment=" + secret

    def read(path, limit=262144):
        if path.name == "atlaso.conf":
            return b'listen 192.0.2.2:443 ssl;\nserver_name private.example;\nproxy_set_header X-Atlaso-Listener-Address $server_addr;\nproxy_set_header Authorization TOPSECRET;\nssl_certificate_key TOPSECRET;\n'
        return json.dumps({"status": "succeeded", "candidate_version": "0.9.341", "job_id": "job_123456abcdef", "secret": secret, "commands": [secret]}).encode()

    monkeypatch.setattr(collector, "command", command)
    monkeypatch.setattr("atlaso.diagnostics.read_source", read)
    monkeypatch.setattr("atlaso.diagnostics.ordinary_path", lambda path: None)
    monkeypatch.setattr("atlaso.diagnostics.os.readlink", lambda path: "/opt/atlaso/releases/0.9.341")
    payload = json.dumps([collector.network(), collector.listeners(), collector.resolver(), collector.firewall(), collector.nginx(), collector.update()])
    assert "TOPSECRET" not in payload and "customer" not in payload and "private.example" not in payload
    assert "192.0.2.2" in payload and "00:11:22:33:44:55" in payload and "hostname0001" in payload
    assert "job_123456abcdef" in payload and "x-atlaso-listener-address" in payload


def test_command_overflow_and_deadline_kill_child(monkeypatch):
    """Bound a real pipe producer and a hanging child without source stderr leaks."""
    monkeypatch.setattr("atlaso.diagnostics.shutil.which", lambda *args, **kwargs: sys.executable)
    collector = Collector(Options.parse({}))
    with pytest.raises(EvidenceError, match="truncated"):
        collector.command(["python", "-c", "import sys; sys.stdout.write('x' * 300000); sys.stdout.flush()"])
    collector.deadline = time.monotonic() + 0.3
    started = time.monotonic()
    with pytest.raises(EvidenceError, match="timed_out"):
        collector.command(["python", "-c", "import time; time.sleep(30)"])
    assert time.monotonic() - started < 5

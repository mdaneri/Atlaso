"""Exercise depot-specific address overlap before listener activation."""

import ssl
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("scenario", ["trusted", "wrong-hostname", "untrusted"])
def test_depot_readiness_real_tls(tmp_path, scenario):
    """Exercise actual certificate verification against an isolated loopback server.

    Args:
        tmp_path: Task-owned certificate and key directory.
        scenario: Certificate trust or hostname condition to exercise.
    """
    helper = load_helper_module()

    def certificate(stem):
        """Create a short-lived test identity.

        Args:
            stem: Unique local certificate basename.
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "depot.example")])
        now = datetime.now(UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("depot.example")]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        cert_path = tmp_path / f"{stem}.pem"
        key_path = tmp_path / f"{stem}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        return cert_path, key_path

    cert_path, key_path = certificate("server")
    trusted_path = certificate("other")[0] if scenario == "untrusted" else cert_path
    requests = []

    class Handler(BaseHTTPRequestHandler):
        """Serve only the expected depot readiness route."""

        def do_GET(self):
            """Record the request and return its route status."""
            requests.append((self.path, self.headers.get("Host")))
            self.send_response(200 if self.path == "/PROD/login" else 404)
            self.end_headers()

        def log_message(self, _format, *args):
            """Keep synthetic HTTP requests out of task output.

            Args:
                _format: Unused log format.
                *args: Unused log values.
            """

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_port
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.05), daemon=True)
    thread.start()
    try:
        hostname = "wrong.example" if scenario == "wrong-hostname" else "depot.example"
        text = f"server_name {hostname};\nssl_certificate {trusted_path.as_posix()};\nlisten 127.0.0.1:{port} ssl;\n"
        assert helper._vcf_depot_endpoint_ready(text) is (scenario == "trusted")
        assert requests == ([("/PROD/login", f"depot.example:{port}")] if scenario == "trusted" else [])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert server.socket.fileno() == -1


@pytest.mark.parametrize("desired,occupied,overlaps", [
    (("192.0.2.1", 8443), ("192.0.2.1", 8443), True),
    (("192.0.2.1", 8443), ("192.0.2.1", 443), False),
    (("192.0.2.1", 8443), ("192.0.2.2", 8443), False),
    (("192.0.2.1", 8443), ("0.0.0.0", 8443), True),
    (("0.0.0.0", 8443), ("192.0.2.1", 8443), True),
    (("2001:db8::1", 8443), ("2001:db8::2", 8443), False),
    (("2001:db8::1", 8443), ("::", 8443), True),
    (("192.0.2.1", 8443), ("::", 8443), True),
    (("2001:db8::1", 8443), ("0.0.0.0", 8443), False),
    (("192.0.2.1", 8443), ("::ffff:192.0.2.1", 8443), True),
])
def test_depot_listener_overlap(desired, occupied, overlaps):
    """Distinguish actual bind overlap from independent address or port use.

    Args:
        desired: Proposed listener tuple.
        occupied: Existing listener tuple.
        overlaps: Expected overlap decision.
    """
    helper = load_helper_module()
    assert helper._vcf_depot_listener_overlap(desired, occupied) is overlaps


@pytest.mark.parametrize("line,owned,allowed", [
    ("", False, True),
    ('LISTEN 0 128 192.0.2.1:8443 0.0.0.0:* users:(("nginx",pid=42,fd=8))', True, True),
    ('LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:(("other",pid=42,fd=8))', False, False),
    ('LISTEN 0 128 192.0.2.2:8443 0.0.0.0:*', False, True),
    ('LISTEN 0 128 192.0.2.1:443 0.0.0.0:*', False, True),
    ('LISTEN 0 128 192.0.2.1:8443 0.0.0.0:*', False, False),
    ('unparseable inventory', False, False),
])
def test_depot_listener_inventory(monkeypatch, line, owned, allowed):
    """Allow independent listeners and verified nginx sharing only.

    Args:
        monkeypatch: Dependency replacement fixture.
        line: Synthetic kernel listener inventory.
        owned: Whether the reported process is service nginx.
        allowed: Expected admission outcome.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_nginx_binary", lambda: "/usr/sbin/nginx")
    monkeypatch.setattr(helper, "_vcf_depot_listener_is_nginx", lambda *_args: owned)

    def inventory(command, **kwargs):
        """Return a bounded synthetic IPv4 inventory.

        Args:
            command: Requested inventory command.
            **kwargs: Timeout configuration.
        """
        assert kwargs["timeout"] == 5
        return subprocess.CompletedProcess(command, 0, line if command[-1] == "-4" else "", "")

    monkeypatch.setattr(helper, "_run", inventory)
    error = helper._vcf_depot_listener_admission("listen 192.0.2.1:8443 ssl;\n")
    assert (error == "") is allowed


@pytest.mark.parametrize("address,pids,allowed", [
    ("[::]", [42], True),
    ("[::]", [42, 99], False),
    ("[2001:db8::2]", [99], True),
])
def test_ipv6_listener_inventory_requires_every_owner(monkeypatch, address, pids, allowed):
    """Reject mixed owners on overlapping IPv6 sockets while allowing distinct binds.

    Args:
        monkeypatch: Dependency replacement fixture.
        address: Occupied IPv6 listener address.
        pids: Processes sharing the reported listener.
        allowed: Expected admission decision.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_nginx_binary", lambda: "/usr/sbin/nginx")
    monkeypatch.setattr(helper, "_vcf_depot_listener_is_nginx", lambda pid, _path: pid == 42)
    owners = ",".join(f'(\"process\",pid={pid},fd=8)' for pid in pids)
    line = f"LISTEN 0 128 {address}:8443 [::]:* users:({owners})"

    def inventory(command, **_kwargs):
        """Supply IPv6-only socket evidence.

        Args:
            command: Requested inventory family.
            **_kwargs: Bounded execution options.
        """
        return subprocess.CompletedProcess(command, 0, line if command[-1] == "-6" else "", "")

    monkeypatch.setattr(helper, "_run", inventory)
    error = helper._vcf_depot_listener_admission("listen [2001:db8::1]:8443 ssl;\n")
    assert (error == "") is allowed


@pytest.mark.parametrize("outcome", ["missing", "timeout", "failed"])
def test_inventory_failure_blocks_admission(monkeypatch, outcome):
    """Fail closed when the kernel inventory cannot be obtained.

    Args:
        monkeypatch: Dependency replacement fixture.
        outcome: Inventory failure to simulate.
    """
    helper = load_helper_module()
    monkeypatch.setattr(helper, "_nginx_binary", lambda: "/usr/sbin/nginx")

    def inventory(command, **_kwargs):
        """Simulate unavailable socket evidence.

        Args:
            command: Inventory command.
            **_kwargs: Bounded execution options.
        """
        if outcome == "missing":
            raise FileNotFoundError("ss")
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, 5)
        return subprocess.CompletedProcess(command, 1, "", "failure")

    monkeypatch.setattr(helper, "_run", inventory)
    assert helper._vcf_depot_listener_admission("listen 192.0.2.1:8443 ssl;")


@pytest.mark.parametrize("exe,cgroup,expected", [
    ("nginx", "0::/system.slice/nginx.service\n", True),
    ("other", "0::/system.slice/nginx.service\n", False),
    ("nginx", "0::/system.slice/other.service\n", False),
    ("nginx", "0::/system.slice/fake-nginx.service\n", False),
    ("missing", "", False),
])
def test_listener_requires_executable_and_service(monkeypatch, tmp_path, exe, cgroup, expected):
    """A process name alone cannot establish nginx listener ownership.

    Args:
        monkeypatch: Dependency replacement fixture.
        tmp_path: Isolated test root.
        exe: Executable identity to report.
        cgroup: Synthetic process service membership.
        expected: Whether identity is verified.
    """
    helper = load_helper_module()
    nginx = tmp_path / "nginx"
    nginx.write_text("synthetic")
    original_resolve = Path.resolve
    original_read = Path.read_text

    def resolve(path, *args, **kwargs):
        """Model the proc executable link.

        Args:
            path: Path being resolved.
            *args: Positional path options.
            **kwargs: Keyword path options.
        """
        if path.as_posix() == "/proc/42/exe":
            if exe == "missing":
                raise FileNotFoundError("process exited")
            return original_resolve(nginx) if exe == "nginx" else tmp_path / "other"
        return original_resolve(path, *args, **kwargs)

    def read(path, *args, **kwargs):
        """Model proc cgroup evidence.

        Args:
            path: Path being read.
            *args: Positional read options.
            **kwargs: Keyword read options.
        """
        if path.as_posix() == "/proc/42/cgroup":
            return cgroup
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "read_text", read)
    assert helper._vcf_depot_listener_is_nginx(42, nginx) is expected


def test_admission_rejection_precedes_depot_mutation(monkeypatch, tmp_path):
    """Reject an occupied port before credentials, permissions or nginx change.

    Args:
        monkeypatch: Dependency replacement fixture.
        tmp_path: Isolated configuration root.
    """
    helper = load_helper_module()
    config = tmp_path / "depot.conf"
    config.write_text("listen 192.0.2.1:8443 ssl;\n")
    monkeypatch.setattr(helper, "_validate_vcf_depot_config_path", lambda _path: config)
    monkeypatch.setattr(helper, "_vcf_depot_config_errors", lambda _path: [])
    monkeypatch.setattr(helper, "_vcf_depot_listener_admission", lambda _text: "occupied")

    def forbidden(*_args):
        """Detect premature mutation.

        Args:
            *_args: Unexpected mutation arguments.
        """
        pytest.fail("mutation preceded admission")

    for name in ("_write_vcf_depot_htpasswd", "_remove_vcf_depot_htpasswd", "_prepare_vcf_depot_web_tree", "_install_nginx_site"):
        monkeypatch.setattr(helper, name, forbidden)
    assert helper._handle_vcf_offline_depot("apply-https", [str(config)]) == 2


@pytest.mark.parametrize("status,expected", [(b"HTTP/1.1 200 OK\r\n", True), (b"HTTP/1.1 503 Error\r\n", False)])
def test_depot_readiness_checks_tls_name_and_selected_port(monkeypatch, status, expected):
    """Verify the configured endpoint without relying on DNS or disabling TLS checks.

    Args:
        monkeypatch: Dependency replacement fixture.
        status: Synthetic HTTP status line.
        expected: Expected readiness result.
    """
    helper = load_helper_module()
    secured = MagicMock()
    secured.__enter__.return_value = secured
    secured.recv.side_effect = [bytes([value]) for value in status] * 3
    connection = MagicMock()
    connection.__enter__.return_value = connection
    context = SimpleNamespace(verify_flags=0, wrap_socket=MagicMock(return_value=secured))
    create_context = MagicMock(return_value=context)
    connect = MagicMock(return_value=connection)
    monkeypatch.setattr(helper.ssl, "create_default_context", create_context)
    monkeypatch.setattr(helper.socket, "create_connection", connect)
    text = "server_name depot.example;\nssl_certificate /trusted/depot.pem;\nlisten 192.0.2.1:8443 ssl;\n"
    assert helper._vcf_depot_endpoint_ready(text) is expected
    create_context.assert_called_once_with(cafile="/trusted/depot.pem")
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert connect.call_args.args[0] == ("192.0.2.1", 8443)
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "depot.example"
    assert b"Host: depot.example:8443" in secured.sendall.call_args.args[0]


@pytest.mark.parametrize("stage", ["connect", "handshake", "drip"])
def test_depot_readiness_shares_deadline(monkeypatch, stage):
    """Stop at the shared deadline even when a peer keeps delivering bytes.

    Args:
        monkeypatch: Dependency replacement fixture.
        stage: Network stage that consumes the remaining budget.
    """
    helper = load_helper_module()
    now = [0.0]
    secured = MagicMock()
    secured.__enter__.return_value = secured
    connection = MagicMock()
    connection.__enter__.return_value = connection

    def connect(*_args, **_kwargs):
        """Consume time while establishing the connection.

        Args:
            *_args: Socket destination.
            **_kwargs: Socket options.
        """
        now[0] += 30 if stage == "connect" else 0
        return connection

    def wrap(*_args, **_kwargs):
        """Consume time during TLS negotiation.

        Args:
            *_args: Connected socket.
            **_kwargs: TLS identity options.
        """
        now[0] += 30 if stage == "handshake" else 0
        return secured

    def receive(_size):
        """Drip bytes without ever finishing the status line.

        Args:
            _size: Requested byte count.
        """
        now[0] += 4
        return b"H"

    context = SimpleNamespace(verify_flags=0, wrap_socket=MagicMock(side_effect=wrap))
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helper.ssl, "create_default_context", lambda **_kwargs: context)
    monkeypatch.setattr(helper.socket, "create_connection", connect)
    secured.recv.side_effect = receive
    text = "server_name depot.example;\nssl_certificate /trusted/depot.pem;\nlisten 192.0.2.1:8443 ssl;\n"
    assert helper._vcf_depot_endpoint_ready(text) is False
    if stage == "connect":
        context.wrap_socket.assert_not_called()
    elif stage == "handshake":
        secured.sendall.assert_not_called()
    else:
        assert secured.recv.call_count == 8
        assert secured.settimeout.call_args.args == (2.0,)


@pytest.mark.parametrize("failure", ["none", "flush", "replace"])
def test_depot_atomic_publication_preserves_complete_previous_file(monkeypatch, tmp_path, failure):
    """An interrupted candidate write cannot truncate the live rollback target.

    Args:
        monkeypatch: Failure injection fixture.
        tmp_path: Managed destination directory.
        failure: Publication boundary that fails.
    """
    helper = load_helper_module()
    target = tmp_path / "depot.conf"
    target.write_bytes(b"previous complete site")
    replace = Path.replace

    def publish(path, destination):
        """Check both complete versions immediately before replacement.

        Args:
            path: Complete sibling candidate.
            destination: Existing live site.
        """
        assert path.parent == target.parent
        assert target.read_bytes() == b"previous complete site"
        assert path.read_bytes() == b"candidate complete site"
        if failure == "replace":
            raise OSError("injected rename failure")
        return replace(path, destination)

    def flush(path):
        """Fail before publication when durable candidate storage fails.

        Args:
            path: Candidate file to flush.
        """
        assert path != target
        assert target.read_bytes() == b"previous complete site"
        if failure == "flush":
            raise OSError("injected flush failure")

    monkeypatch.setattr(Path, "replace", publish)
    monkeypatch.setattr(helper, "_fsync_file", flush)
    if failure == "none":
        helper._replace_vcf_depot_file(target, b"candidate complete site", 0o644)
    else:
        with pytest.raises(OSError):
            helper._replace_vcf_depot_file(target, b"candidate complete site", 0o644)
    assert target.read_bytes() == (b"candidate complete site" if failure == "none" else b"previous complete site")
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("failure", ["none", "syntax", "reload", "readiness", "rollback"])
def test_depot_activation_restores_previous_files(monkeypatch, tmp_path, capsys, failure):
    """Keep the previous depot and shared nginx running when activation fails.

    Args:
        monkeypatch: Dependency replacement fixture.
        tmp_path: Isolated managed-file root.
        capsys: Captured operator diagnostics.
        failure: Activation failure to inject.
    """
    helper = load_helper_module()
    site = tmp_path / "depot.conf"
    auth = tmp_path / "depot.htpasswd"
    site.write_text("previous depot")
    auth.write_text("synthetic previous authentication")
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site)
    monkeypatch.setattr(helper, "VCF_DEPOT_HTPASSWD_PATH", auth)
    monkeypatch.setattr(helper, "_nginx_site_conflict", lambda *_args: "")
    monkeypatch.setattr(helper, "_install_nginx_include", lambda: None)
    monkeypatch.setattr(helper, "_prepare_vcf_depot_web_tree", lambda _text: None)
    monkeypatch.setattr(helper, "_vcf_depot_auth_required", lambda _text: False)
    commands = []
    validations = []

    def validate():
        """Fail the candidate syntax check once when requested."""
        validations.append(True)
        return subprocess.CompletedProcess([], int(failure == "syntax" and len(validations) == 1), "", "")

    def run(command, **_kwargs):
        """Record service actions and fail only the candidate reload.

        Args:
            command: Service command.
            **_kwargs: Bounded execution options.
        """
        commands.append(command)
        reloads = sum("reload" in item for item in commands)
        failed = (failure == "reload" and "reload" in command and reloads == 1) or (failure == "rollback" and "reload" in command)
        return subprocess.CompletedProcess(command, int(failed), "", "")

    monkeypatch.setattr(helper, "_nginx_test_command", validate)
    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_vcf_depot_endpoint_ready", lambda text: text == "previous depot" or failure != "readiness")
    result = helper._apply_vcf_depot_site("candidate depot", disabled=False)
    assert result == (0 if failure == "none" else 2)
    assert all("restart" not in command and "stop" not in command for command in commands)
    if failure == "none":
        assert site.read_text() == "candidate depot"
        assert not auth.exists()
    else:
        assert site.read_text() == "previous depot"
        assert auth.read_text() == "synthetic previous authentication"
    if failure == "rollback":
        assert "Depot rollback needs attention" in capsys.readouterr().err


@pytest.mark.parametrize("disabled,active,failure,enablement", [
    (False, False, "none", "disabled"),
    (True, False, "none", "disabled"),
    (True, True, "none", "enabled"),
    (False, False, "readiness", "disabled"),
    (False, False, "partial-start", "disabled"),
    (False, False, "timeout", "disabled"),
    (False, False, "readiness", "enabled"),
    (False, False, "readiness", "enabled-runtime"),
    (False, False, "readiness", "static"),
    (False, False, "cleanup-stop", "disabled"),
    (False, False, "cleanup-timeout", "disabled"),
    (False, False, "cleanup-is-active", "disabled"),
    (False, False, "cleanup-disable", "disabled"),
    (False, False, "cleanup-is-enabled", "disabled"),
])
def test_depot_first_activation_and_disable(monkeypatch, tmp_path, capsys, disabled, active, failure, enablement):
    """Start nginx only for an enabled endpoint and reload an existing service.

    Args:
        monkeypatch: Dependency replacement fixture.
        tmp_path: Isolated managed-file root.
        capsys: Captured incomplete-rollback diagnostics.
        disabled: Whether this operation removes the endpoint.
        active: Initial nginx service state.
        failure: Failure after attempting first activation.
        enablement: Initial service enablement that rollback must preserve.
    """
    helper = load_helper_module()
    site = tmp_path / "depot.conf"
    auth = tmp_path / "depot.htpasswd"
    cleanup_failure = failure.startswith("cleanup-")
    if disabled or cleanup_failure:
        site.write_text("previous depot")
        auth.write_text("synthetic authentication")
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site)
    monkeypatch.setattr(helper, "VCF_DEPOT_HTPASSWD_PATH", auth)
    monkeypatch.setattr(helper, "_nginx_site_conflict", lambda *_args: "")
    monkeypatch.setattr(helper, "_install_nginx_include", lambda: None)
    monkeypatch.setattr(helper, "_prepare_vcf_depot_web_tree", lambda _text: None)
    monkeypatch.setattr(helper, "_vcf_depot_auth_required", lambda _text: False)
    monkeypatch.setattr(helper, "_nginx_test_command", lambda: subprocess.CompletedProcess([], 0, "", ""))
    ready = MagicMock(return_value=failure != "readiness" and not cleanup_failure)
    monkeypatch.setattr(helper, "_vcf_depot_endpoint_ready", ready)
    commands = []

    def run(command, **_kwargs):
        """Record service changes with a controlled initial state.

        Args:
            command: Service command.
            **_kwargs: Bounded execution options.
        """
        commands.append(command)
        if cleanup_failure and command[1] == failure.removeprefix("cleanup-"):
            if command[1] not in {"is-active", "is-enabled"} or sum(item[1] == command[1] for item in commands) > 1:
                return subprocess.CompletedProcess(command, 2, "unknown", "")
        if failure == "cleanup-timeout" and command[1] == "stop":
            raise subprocess.TimeoutExpired(command, 30)
        if "is-enabled" in command:
            return subprocess.CompletedProcess(command, int(enablement == "disabled"), f"{enablement}\n", "")
        if "enable" in command:
            if failure == "timeout":
                raise subprocess.TimeoutExpired(command, 30)
            if failure == "partial-start":
                return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 3 if "is-active" in command and not active else 0, "", "")

    monkeypatch.setattr(helper, "_run", run)
    assert helper._apply_vcf_depot_site("candidate depot", disabled=disabled) == (0 if failure == "none" else 2)
    mutations = [command for command in commands if "is-active" not in command and "is-enabled" not in command]
    expected = [] if disabled and not active else [["systemctl", "reload", "nginx"]] if active else [["systemctl", "enable", "--now", "nginx"]]
    if not active and not disabled and enablement != "disabled":
        expected = [["systemctl", "start", "nginx"]]
    if failure != "none":
        expected.append(["systemctl", "stop", "nginx"])
        if enablement == "disabled":
            expected.append(["systemctl", "disable", "nginx"])
    assert mutations == expected
    assert site.exists() == (cleanup_failure or (not disabled and failure == "none"))
    if cleanup_failure:
        assert site.read_text() == "previous depot"
        assert auth.read_text() == "synthetic authentication"
        assert "Depot rollback needs attention" in capsys.readouterr().err
    else:
        assert not auth.exists()
    assert ready.call_count == int(not disabled and failure not in {"partial-start", "timeout"})

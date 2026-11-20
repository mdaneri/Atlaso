"""Pinned SSH transport for the existing receipt/release native RPM protocol.

Runs only in the refresh owner's bounded Windows job. The SDK credential is
obtained once, after host-key admission, and never leaves this process. One
connection serves the phase; every native child retains its own original receipt,
release barrier, independent Linux deadline and complete process-group proof.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import io
import json
import os
import shlex
import socket
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import Path, PureWindowsPath
from typing import Any

MAX_FILE = 512 * 1024**2
MAX_TREE = 16 * 1024**3
MAX_LINE = 9 * 1024**2


def fingerprint(key: Any) -> str:
    """Calculate the console-compatible fingerprint without trusting an endpoint.

    Args:
        key: Negotiated SSH public key.
    """
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def mapped_path(value: str, roots: list[str]) -> str:
    """Map only admitted local drive paths into the private remote mirror.

    Args:
        value: Exact absolute Windows input or output path.
        roots: Plan-selected allowed paths, never host-wide filesystem roots.
    """
    path = PureWindowsPath(value)
    if (not path.is_absolute() or len(path.drive) != 2 or path.drive[1] != ":"
            or any(part in (".", "..") or "\0" in part or ":" in part for part in path.parts[1:])):
        raise ValueError("native_ssh_path_invalid")
    matching = [PureWindowsPath(root) for root in roots if path.is_relative_to(PureWindowsPath(root))]
    if not matching:
        raise ValueError("native_ssh_path_outside_plan")
    for root in matching:
        relative = path.relative_to(root)
        if not {part.casefold() for part in relative.parts} & {
                ".git", ".atlaso-local", ".venv", "node_modules"}:
            break
    else:
        raise ValueError("native_ssh_private_path_refused")
    if any(part.casefold() in {".env", ".git", ".atlaso-local"} for part in path.parts):
        raise ValueError("native_ssh_private_path_refused")
    return "files/" + path.drive[0].lower() + "/" + "/".join(path.parts[1:])


def emit(value: dict) -> None:
    """Emit only the bounded protocol, never credential or arbitrary console text.

    Args:
        value: Public protocol record.
    """
    print(json.dumps(value, separators=(",", ":")), flush=True)


def read_message() -> dict:
    """Read one bounded parent protocol message."""
    raw = sys.stdin.buffer.readline(MAX_LINE + 1)
    if not raw or len(raw) > MAX_LINE:
        raise ValueError("native_ssh_owner_disconnected")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("native_ssh_protocol_invalid")
    return value


class Session:
    """Own one phase's transport, original remote root and mirrored public inputs."""

    def __init__(self, context: dict, transport: Any, sftp: Any) -> None:
        """Bind a previously pinned and authenticated transport.

        Args:
            context: Immutable phase context published by the refresh owner.
            transport: Authenticated Paramiko transport.
            sftp: SFTP connection belonging to that transport.
        """
        self.context, self.transport, self.sftp = context, transport, sftp
        self.deadline = context["deadline_epoch"]
        self.original: dict = {}
        self.root = "/var/tmp/atlaso-rpm-" + context["remote_id"]
        self.cache: dict[str, str] = {}
        self.databases: dict[str, tuple[int, int]] = {}
        self.clean = True
        self.catalog: str | None = None
        self.workspace_source = (Path(__file__).parent / "native_rpm_ssh_workspace.py").read_bytes()
        self.supervisor_source = (Path(__file__).parent / "native_rpm_tools_guest.py").read_bytes()

    def remaining(self) -> float:
        """Keep every transport operation inside its original deadline."""
        remaining = self.deadline - time.time()
        if remaining < 2:
            raise TimeoutError("native_ssh_original_deadline_expired")
        return remaining

    def control(self, operation: str, **fields: Any) -> dict:
        """Run only the fixed standard-library workspace owner over the pinned channel.

        Args:
            operation: Workspace create, verify, file-inventory or removal operation.
            **fields: Bounded workspace-relative selectors.
        """
        program = "import base64;exec(compile(base64.b64decode(" + repr(
            base64.b64encode(self.workspace_source).decode()) + "),'<atlaso-workspace>','exec'))"
        channel = self.transport.open_session(timeout=min(10, self.remaining()))
        remaining = self.remaining()
        if remaining < 7:
            raise TimeoutError("native_ssh_original_deadline_expired")
        channel.settimeout(min(125, remaining))
        try:
            # Workspace owners also need an independent guest deadline if the
            # Windows job or SSH connection disappears during a filesystem read.
            duration = min(120, remaining - 6)
            channel.exec_command("/usr/bin/timeout --kill-after=5s " + str(duration)
                                 + "s /usr/bin/python3 -I -S -B -c " + shlex.quote(program))
            request = {"operation": operation, "scope": self.context["remote_id"],
                       "task_id": self.context["task_id"], "source_commit": self.context["source_commit"],
                       "original": self.original, **fields}
            channel.sendall(json.dumps(request).encode() + b"\n")
            channel.shutdown_write()
            raw = channel.makefile("rb").read(MAX_LINE + 1)
            if len(raw) > MAX_LINE or channel.recv_exit_status() != 0:
                raise RuntimeError("native_ssh_workspace_refused")
            response = json.loads(raw)
            if set(response) != {"result"}:
                raise RuntimeError("native_ssh_workspace_protocol_invalid")
            return response["result"]
        finally:
            channel.close()

    def directory(self, relative: str) -> str:
        """Create ordinary private mirror directories without accepting links.

        Args:
            relative: Constrained relative mirror path.
        """
        path = self.root
        for part in relative.split("/"):
            if part in ("", ".", "..") or "\\" in part:
                raise ValueError("native_ssh_directory_invalid")
            path += "/" + part
            try:
                self.sftp.mkdir(path, mode=0o700)
            except OSError:
                value = self.sftp.lstat(path)
                if not stat.S_ISDIR(value.st_mode) or value.st_uid != self.original["uid"]:
                    raise ValueError("native_ssh_directory_changed") from None
        return path

    def transfer(self, local: Path) -> str:
        """Mirror one ordinary public input, retaining Windows no-follow pins while reading.

        Args:
            local: Plan-admitted local file or bounded directory.
        """
        from scripts.completed_task_files import WindowsFiles

        relative = mapped_path(str(local), self.context["allowed_roots"])
        files = WindowsFiles()
        with files.ancestors(local), ExitStack() as pins:
            value = local.lstat()
            is_directory = stat.S_ISDIR(value.st_mode)
            pins.enter_context(files.opened(local, directory=is_directory))
            if is_directory:
                remote = self.directory(relative)
                count, total = 0, 0
                for base, directories, names in os.walk(local, followlinks=False):
                    for name in [*directories, *names]:
                        path = Path(base) / name
                        entry = path.lstat()
                        count += 1
                        total += entry.st_size if stat.S_ISREG(entry.st_mode) else 0
                        if (count > 20000 or total > MAX_TREE or stat.S_ISLNK(entry.st_mode)
                                or getattr(entry, "st_file_attributes", 0) & 0x400):
                            raise ValueError("native_ssh_tree_invalid")
                        if stat.S_ISDIR(entry.st_mode):
                            self.directory(mapped_path(str(path), self.context["allowed_roots"]))
                        else:
                            self.transfer(path)
                return remote
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size > MAX_FILE:
                raise ValueError("native_ssh_input_invalid")
            self.directory(relative.rsplit("/", 1)[0])
            with local.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
                if relative in self.cache and self.cache[relative] != digest:
                    raise ValueError("native_ssh_input_digest_changed")
                if self.cache.get(relative) != digest:
                    try:
                        self.sftp.lstat(self.root + "/" + relative)
                    except FileNotFoundError:
                        pass
                    else:
                        raise ValueError("native_ssh_input_destination_exists")
                    stream.seek(0)
                    self.sftp.putfo(stream, self.root + "/" + relative, file_size=value.st_size,
                                    callback=lambda *_: self.remaining(), confirm=True)
                    self.sftp.chmod(self.root + "/" + relative, 0o600)
                observed = self.control("files", paths=[relative])[relative]
                if len(observed) != 1 or observed[0]["sha256"] != digest:
                    raise ValueError("native_ssh_transferred_digest_changed")
                self.cache[relative] = digest
            after = local.lstat()
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
                    value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns):
                raise ValueError("native_ssh_local_input_changed")
            return self.root + "/" + relative

    def receive_output(self, local: Path, identity: tuple[int, int]) -> None:
        """Publish only newly generated ordinary repository metadata into an empty local root.

        Args:
            local: Originally empty createrepo output directory selected by trusted code.
            identity: Original output-directory identity recorded before the remote command.
        """
        from scripts.completed_task_files import WindowsFiles

        relative = mapped_path(str(local), self.context["allowed_roots"])
        rows = self.control("files", paths=[relative])[relative]
        files = WindowsFiles()
        with files.ancestors(local), files.opened(local, directory=True, allow_child_publication=True):
            value = local.lstat()
            if (value.st_dev, value.st_ino) != identity:
                raise ValueError("native_ssh_output_identity_changed")
            if list(local.iterdir()):
                raise ValueError("native_ssh_output_not_empty")
            for row in sorted(rows, key=lambda item: (item["path"].count("/"), item["path"])):
                parts = row["path"].split("/")
                if any(part in ("", ".", "..") or "\\" in part or ":" in part for part in parts):
                    raise ValueError("native_ssh_output_path_invalid")
                target = local.joinpath(*parts)
                if row["kind"] == "directory":
                    target.mkdir()
                    continue
                data = io.BytesIO()
                self.sftp.getfo(self.root + "/" + relative + "/" + row["path"], data,
                                callback=lambda count, _total, size=row["size"]: self.progress(count, size))
                payload = data.getvalue()
                if len(payload) != row["size"] or hashlib.sha256(payload).hexdigest() != row["sha256"]:
                    raise ValueError("native_ssh_output_digest_changed")
                with files.ancestors(target), target.open("xb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())

    def progress(self, count: int, maximum: int) -> None:
        """Bound SFTP bytes as well as time even if a server reports inconsistent sizes.

        Args:
            count: Bytes received so far.
            maximum: Original bounded inventory size.
        """
        self.remaining()
        if count > maximum:
            raise ValueError("native_ssh_transfer_size_changed")

    def prepare(self, request: dict) -> tuple[dict, tuple[Path, tuple[int, int]] | None]:
        """Map public inputs while keeping RPM databases entirely inside this session.

        Args:
            request: Parent request with original Windows paths.
        """
        observation = self.control("verify")
        if abs(observation["observed_epoch"] - time.time()) > 5:
            raise ValueError("native_ssh_clock_skew")
        if self.catalog is not None and self.control("catalog")["sha256"] != self.catalog:
            raise ValueError("native_ssh_workspace_changed_between_commands")
        output = None
        arguments = []
        previous = ""
        for argument in request["arguments"]:
            if PureWindowsPath(argument).is_absolute():
                path = Path(argument)
                relative = mapped_path(argument, self.context["allowed_roots"])
                if previous == "--dbpath":
                    from scripts.completed_task_files import WindowsFiles

                    files = WindowsFiles()
                    with files.ancestors(path), files.opened(path, directory=True):
                        value = path.lstat()
                        identity = (value.st_dev, value.st_ino)
                        if relative in self.databases and self.databases[relative] != identity:
                            raise ValueError("native_ssh_database_identity_changed")
                    if list(path.iterdir()):
                        raise ValueError("native_ssh_database_must_be_isolated_and_empty")
                    arguments.append(self.directory(relative))
                    self.databases[relative] = identity
                elif previous == "--outputdir":
                    from scripts.completed_task_files import WindowsFiles

                    files = WindowsFiles()
                    with files.ancestors(path), files.opened(path, directory=True):
                        value = path.lstat()
                        identity = (value.st_dev, value.st_ino)
                    if list(path.iterdir()):
                        raise ValueError("native_ssh_output_not_empty")
                    arguments.append(self.directory(relative))
                    output = (path, identity)
                else:
                    arguments.append(self.transfer(path))
            else:
                if argument.startswith(("/", "\\")) or "\0" in argument:
                    raise ValueError("native_ssh_unmapped_absolute_argument")
                arguments.append(argument)
            previous = argument
        cwd = Path(request["cwd"])
        if cwd == Path(self.context["repository_root"]):
            remote_cwd = self.directory(mapped_path(str(cwd), self.context["allowed_roots"]))
        else:
            remote_cwd = self.transfer(cwd)
        return {**request, "arguments": arguments, "cwd": remote_cwd}, output

    def run(self, request: dict) -> None:
        """Relay the original/release/result barrier without manufacturing Linux completion.

        Args:
            request: One fixed native request bound to this phase's task and commit.
        """
        if (request.get("task_id") != self.context["task_id"]
                or request.get("source_commit") != self.context["source_commit"]
                or request.get("tool") not in {"rpm", "rpmkeys", "createrepo_c"}
                or not isinstance(request.get("arguments"), list)
                or len(request["arguments"]) > 2048
                or not all(isinstance(arg, str) and len(arg) <= 65536 for arg in request["arguments"])
                or not time.time() + 7 <= request["deadline_epoch"] <= self.context["deadline_epoch"]):
            raise ValueError("native_ssh_request_binding_invalid")
        self.deadline = request["deadline_epoch"]
        native, output = self.prepare(request)
        channel = self.transport.open_session(timeout=min(10, self.remaining()))
        channel.settimeout(self.remaining())
        self.clean = False
        try:
            channel.exec_command("/usr/bin/python3 -I -S -B " + shlex.quote(self.root + "/supervisor.py"))
            channel.sendall(json.dumps(native).encode() + b"\n")
            reader = channel.makefile("rb")
            raw = reader.readline(65537)
            if len(raw) > 65536:
                raise ValueError("native_ssh_original_limit")
            original = json.loads(raw)
            if original.get("kind") != "native-tool-original":
                raise ValueError("native_ssh_original_missing")
            emit(original)
            release = read_message()
            if release != {"release": request["request_id"]}:
                raise ValueError("native_ssh_release_invalid")
            channel.sendall(json.dumps(release).encode() + b"\n")
            raw = reader.readline(MAX_LINE + 1)
            if len(raw) > MAX_LINE:
                raise ValueError("native_ssh_result_limit")
            result = json.loads(raw)
            if (result.get("kind") != "native-tool-result" or result.get("whole_group_quiescent") is not True
                    or result.get("request_id") != original.get("request_id")
                    or result.get("pid") != original.get("pid")
                    or result.get("start_ticks") != original.get("start_ticks")):
                raise ValueError("native_ssh_quiescence_unproven")
            channel.shutdown_write()
            if channel.recv_exit_status() != 0:
                raise ValueError("native_ssh_supervisor_failed")
            self.clean = True
            if result["returncode"] == 0 and output is not None:
                self.receive_output(*output)
            self.catalog = self.control("catalog")["sha256"]
            emit(result)
        finally:
            channel.close()
            self.deadline = self.context["deadline_epoch"]


async def authenticate(context: dict, transport: Any, token: str, environment: str) -> None:
    """Retrieve the concealed selected password only inside this bounded child.

    Args:
        context: Validated public SSH selectors.
        transport: Transport whose Ed25519 key has already matched the console pin.
        token: Current-user DPAPI-unwrapped service-account token, never a command argument.
        environment: Exact pinned Atlaso Environment ID validated by the parent helper.
    """
    from onepassword import Client

    if hashlib.sha256(environment.encode()).hexdigest() != "fe14b62fb2d23460202299784cb1080b9e0fcf202ed5d75b4843202cd68bdf06":
        raise ValueError("native_ssh_environment_invalid")
    client = await asyncio.wait_for(Client.authenticate(auth=token, integration_name="Atlaso native RPM SSH",
                                                       integration_version="v1"), timeout=30)
    token = ""
    response = await asyncio.wait_for(client.environments.get_variables(environment), timeout=30)
    matches = [item for item in response.variables if item.name == context["ssh"]["password_variable"]]
    if len(matches) != 1 or not matches[0].masked or not matches[0].value:
        raise ValueError("native_ssh_password_contract_invalid")
    transport.auth_password(context["ssh"]["user"], matches[0].value)


def serve(context: dict, token: str, environment: str) -> None:
    """Authenticate once, then serve a phase until its owner requests proven cleanup.

    Args:
        context: Immutable source/task-bound refresh context.
        token: Service-account token removed from the environment before importing the SDK.
        environment: Pinned Atlaso Environment selector.
    """
    import paramiko

    from scripts.installation.refresh_plan import validate_native_ssh

    selection = validate_native_ssh(context["ssh"])
    connection = socket.create_connection((selection["host"], 22), timeout=15)
    transport = paramiko.Transport(connection)
    transport.get_security_options().key_types = ["ssh-ed25519"]
    transport.banner_timeout = transport.auth_timeout = 15
    session = None
    try:
        transport.start_client(timeout=15)
        if fingerprint(transport.get_remote_server_key()) != selection["host_key_sha256"]:
            raise ValueError("native_ssh_host_key_mismatch")
        asyncio.run(authenticate(context, transport, token, environment))
        token = ""
        transport.set_keepalive(15)
        ftp = paramiko.SFTPClient.from_transport(transport)
        ftp.get_channel().settimeout(30)
        session = Session(context, transport, ftp)
        session.original = session.control("create")
        emit({"kind": "native-ssh-original", **session.original})
        if abs(session.original["created_epoch"] - time.time()) > 5:
            raise ValueError("native_ssh_clock_skew")
        if read_message() != {"release_session": context["remote_id"]}:
            raise ValueError("native_ssh_session_release_invalid")
        ftp.putfo(io.BytesIO(session.supervisor_source), session.root + "/supervisor.py", confirm=True)
        observed = session.control("files", paths=["supervisor.py"])["supervisor.py"]
        if observed[0]["sha256"] != hashlib.sha256(session.supervisor_source).hexdigest():
            raise ValueError("native_ssh_supervisor_digest_mismatch")
        session.catalog = session.control("catalog")["sha256"]
        while True:
            request = read_message()
            if request == {"close": True}:
                if not session.clean:
                    raise ValueError("native_ssh_group_completion_missing")
                result = session.control("remove", expected_catalog=session.catalog)
                if result.get("remote_root_absent") is not True:
                    raise ValueError("native_ssh_workspace_remains")
                emit({"kind": "native-ssh-result", "task_id": context["task_id"],
                      "source_commit": context["source_commit"], "scope": context["remote_id"],
                      "whole_group_quiescent": True, "remote_root_absent": True})
                return
            session.run(request)
    finally:
        if session is not None:
            session.sftp.close()
        transport.close()


def main() -> int:
    """Enter the isolated dependency runtime without exposing credential failures."""
    token = os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", "")
    environment = os.environ.pop("ATLASO_NATIVE_ENVIRONMENT_ID", "")
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--dependency-path", required=True)
    args = parser.parse_args()
    sys.path[:0] = [args.dependency_path, str(Path(__file__).resolve().parents[1])]
    from scripts.completed_task_files import read_bounded_regular

    context = json.loads(read_bounded_regular(args.context, 65536))
    if not token or context["task_id"] != os.environ.get("CODEX_THREAD_ID"):
        raise ValueError("native_ssh_credential_or_task_missing")
    serve(context, token, environment)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:  # noqa: BLE001 - never serialize SDK, password or transport exception contents to the owner.
        emit({"kind": "native-ssh-failure", "whole_group_quiescent": False})
        raise SystemExit(2) from None

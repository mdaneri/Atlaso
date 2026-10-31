"""Exercise installer consent and failure paths without touching a block device."""

import hashlib
import importlib.util
import io
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_installer(monkeypatch, *, native_choices=False):
    """Load the native-console adapter on Windows with a noninteractive console.

Args:
    monkeypatch: Pytest fixture for replacing controlled dependencies.
    native_choices: Preserve the native storage-menu renderer for its isolated tests.
"""
    monkeypatch.setitem(sys.modules, "curses", SimpleNamespace())
    spec = importlib.util.spec_from_file_location("installation_adapter", Path("scripts/installation/installer.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not native_choices:
        monkeypatch.setattr(module, "storage_choice", lambda *_args: 0)
    return module


@pytest.mark.parametrize("autopartition", [True, False])
def test_named_service_storage_selects_only_explicit_disks(monkeypatch, autopartition):
    """Assign both named services without inferring disk roles from size or order.

    Args:
        monkeypatch: Isolated native choices and disk inventory.
        autopartition: Original Auto or Custom layout mode.
    """
    module = load_installer(monkeypatch)
    initial = {f"/dev/sd{letter}": {"size": size * 1024**3, "serial": letter}
               for letter, size in zip("abcd", (64, 20, 500, 500), strict=True)}
    config = {"disk": "/dev/sda", "arch": "x86_64", "bootmode": "efi", "autopartition": autopartition,
              "partitions": [{"mountpoint": "/", "size": 0, "filesystem": "ext4"}]}
    targets = iter(["/dev/sdd", "/dev/sdc"])

    def choose(_height, _width, title, mountpoint, choices):
        """Explicitly select two disks while checking the named public choices.

        Args:
            _height: Console rows.
            _width: Console columns.
            title: Service name.
            mountpoint: Fixed service mount path.
            choices: Tentative assignments offered by the installer.
        """
        assert (title, mountpoint) in module.SERVICE_STORAGE
        assert choices[0][1] == "keep"
        assert not any(action == "disk" and value == "/dev/sda" for _label, action, value in choices)
        if mountpoint.endswith("offline-depot"):
            assert not any(action == "disk" and value == "/dev/sdd" for _label, action, value in choices)
        target = next(targets)
        return next(i for i, (_label, action, value) in enumerate(choices) if action == "disk" and value == target)

    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "storage_choice", choose)
    assert module.assign_service_storage(25, 80, config, initial)
    assert config["autopartition"] is autopartition
    assert [(p["mountpoint"], p.get("disk", config["disk"])) for p in config["partitions"]] == [
        ("/", "/dev/sda"), ("/mnt/atlaso-vcf-backups", "/dev/sdd"), ("/mnt/atlaso-vcf-offline-depot", "/dev/sdc")]
    assert module.selected_disks(config) == ["/dev/sda", "/dev/sdc", "/dev/sdd"]
    consent = {path: initial[path] for path in module.selected_disks(config)}
    module.revalidate_disks(config, consent, initial)
    changed = {**initial, "/dev/sdd": {"size": initial["/dev/sdd"]["size"], "serial": "replacement"}}
    with pytest.raises(ValueError, match="identity"):
        module.revalidate_disks(config, consent, changed)


def test_service_storage_assigns_custom_partition_and_preserves_existing_role(monkeypatch):
    """Rename only a selected data mount and preserve another service's layout.

    Args:
        monkeypatch: Isolated disk inventory and native menu selections.
    """
    module = load_installer(monkeypatch)
    config = {"disk": "/dev/sda", "partitions": [
        {"mountpoint": "/", "size": 0, "filesystem": "ext4"},
        {"mountpoint": "/var", "disk": "/dev/sdb", "size": 4096, "filesystem": "ext4"},
        {"mountpoint": "/mnt/data", "disk": "/dev/sdb", "size": 8192, "filesystem": "xfs"},
        {"mountpoint": "/mnt/atlaso-vcf-offline-depot", "disk": "/dev/sdc", "size": 0, "filesystem": "ext4"},
    ]}
    initial = {f"/dev/sd{letter}": {"size": 64 * 1024**3} for letter in "abc"}

    def choose(_height, _width, _title, mountpoint, choices):
        """Choose the compatible custom data row, then keep the existing depot.

        Args:
            _height: Console rows.
            _width: Console columns.
            _title: Public service label.
            mountpoint: Fixed service mount.
            choices: Offered assignments.
        """
        if mountpoint.endswith("backups"):
            assert [value for _label, action, value in choices if action == "partition"] == [2]
            return 1
        assert choices[0][0] == "Keep existing partition on /dev/sdc"
        return 0

    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "storage_choice", choose)
    assert module.assign_service_storage(25, 80, config, initial)
    assert config["partitions"][1]["mountpoint"] == "/var"
    assert config["partitions"][2] == {"mountpoint": "/mnt/atlaso-vcf-backups", "disk": "/dev/sdb",
                                       "size": 8192, "filesystem": "xfs"}
    assert config["partitions"][3]["mountpoint"] == "/mnt/atlaso-vcf-offline-depot"


def test_service_storage_back_discards_tentative_assignments(monkeypatch):
    """Back through named roles without leaking tentative disk selections.

    Args:
        monkeypatch: Isolated inventory and native Back results.
    """
    module = load_installer(monkeypatch)
    config = {"disk": "/dev/sda", "partitions": [{"mountpoint": "/", "size": 0, "filesystem": "ext4"}]}
    original = module.copy.deepcopy(config)
    initial = {f"/dev/sd{letter}": {"size": 64 * 1024**3} for letter in "ab"}
    selections = iter([1, None, None])
    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "storage_choice", lambda *_args: next(selections))
    assert not module.assign_service_storage(25, 80, config, initial)
    assert config == original


def test_service_storage_reserves_native_efi_slot_and_accepts_swap(monkeypatch):
    """Keep new data filesystems inside the existing persisted-profile bound.

    Args:
        monkeypatch: Isolated installer loader.
    """
    module = load_installer(monkeypatch)
    config = {"disk": "/dev/sda", "partitions": [
        {"mountpoint": "/", "size": 4096, "filesystem": "ext4"},
        {"mountpoint": None, "size": 1024, "filesystem": "swap"},
        *({"mountpoint": f"/mnt/data-{i}", "size": 512, "filesystem": "ext4"} for i in range(30)),
    ]}
    eligible = {"/dev/sda": {"size": 64 * 1024**3}, "/dev/sdb": {"size": 500 * 1024**3}}
    choices = module.service_storage_choices(config, "/mnt/atlaso-vcf-backups", eligible)
    assert choices[0][1] == "keep"
    assert not any(action == "disk" for _label, action, _value in choices)
    assert len([action for _label, action, _value in choices if action == "partition"]) == 30
    config["partitions"].pop()
    assert any(action == "disk" and value == "/dev/sdb"
               for _label, action, value in module.service_storage_choices(config, "/mnt/atlaso-vcf-backups", eligible))


@pytest.mark.parametrize("back", [True, False])
def test_storage_menu_keeps_exact_actions_behind_bounded_native_labels(monkeypatch, back):
    """Exercise Photon-compatible native callbacks without a console or disk.

    Args:
        monkeypatch: Native Window/Menu doubles.
        back: Whether the native window returns Back.
    """
    module = load_installer(monkeypatch, native_choices=True)
    observed = {}

    class Window:
        """Retain one native panel for the public selection test."""
        def __init__(self, *args):
            """Capture native geometry and title.

            Args:
                *args: Native constructor parameters.
            """
            observed["window"] = args
        def addstr(self, *_args):
            """Accept public mount instructions.

            Args:
                *_args: Native text coordinates and content.
            """
        def set_action_panel(self, panel):
            """Bind the native menu.

            Args:
                panel: Native menu double.
            """
            self.panel = panel
        def do_action(self):
            """Return Back or the exact second native callback."""
            if back:
                return SimpleNamespace(success=False)
            _label, callback, value = self.panel[2][1]
            return callback(value)

    monkeypatch.setitem(sys.modules, "window", SimpleNamespace(Window=Window))
    monkeypatch.setitem(sys.modules, "menu", SimpleNamespace(Menu=lambda *args: args))
    monkeypatch.setitem(sys.modules, "actionresult", SimpleNamespace(
        ActionResult=lambda success, result: SimpleNamespace(success=success, result=result)))
    choices = [("Keep shared storage", "keep", None), ("Erase whole disk " + "x" * 100, "disk", "/dev/exact")]
    assert module.storage_choice(25, 80, "SFTP backup storage", "/mnt/atlaso-vcf-backups", choices) == (None if back else 1)
    assert observed["window"] == (18, 70, 25, 80, "SFTP backup storage", True)


@pytest.mark.parametrize("hardware,kind,accepted", [
    (False, "772", False), (False, "1", False), (True, "1", True), (True, "32", False),
])
def test_install_requires_hardware_ethernet_but_not_carrier(monkeypatch, tmp_path, hardware, kind, accepted):
    """Reject absent/software interfaces while admitting a disconnected real NIC.

    Args:
        monkeypatch: Controlled native module loader.
        tmp_path: Isolated sysfs fixture.
        hardware: Whether the interface is device-backed.
        kind: Kernel ARPHRD type.
        accepted: Whether installation may proceed.
    """
    module = load_installer(monkeypatch)
    interface = tmp_path / "eth0"
    interface.mkdir()
    (interface / "type").write_text(kind)
    (interface / "carrier").write_text("0")
    if hardware:
        (interface / "device").mkdir()
    if accepted:
        module.require_network_adapter(tmp_path)
    else:
        with pytest.raises(ValueError, match="No Ethernet adapter"):
            module.require_network_adapter(tmp_path)


def test_install_refuses_empty_or_unreadable_network_inventory(monkeypatch, tmp_path):
    """Never turn missing kernel evidence into permission to erase a disk.

    Args:
        monkeypatch: Controlled native module loader.
        tmp_path: Isolated empty sysfs fixture.
    """
    module = load_installer(monkeypatch)
    with pytest.raises(ValueError, match="No Ethernet adapter"):
        module.require_network_adapter(tmp_path)
    with pytest.raises(FileNotFoundError):
        module.require_network_adapter(tmp_path / "missing")


@pytest.mark.parametrize("fails", [False, True])
def test_progress_counts_completed_native_stages_only(monkeypatch, fails):
    """Preserve native mode/results and never advance a failed stage.

    Args:
        monkeypatch: Controlled native module loader.
        fails: Whether the package transaction fails.
    """
    module = load_installer(monkeypatch)
    events = []
    def operation(*args, **kwargs):
        """Model a native operation without touching disks.

        Args:
            *args: Forwarded native arguments.
            **kwargs: Forwarded native options.
        """
        events.append((args, kwargs))
        if fails:
            raise RuntimeError("native package failure")
        return "native result"
    engine = SimpleNamespace(**{name: operation for name, _ in module.INSTALLATION_STAGES})
    progress = SimpleNamespace(update_message=lambda text: events.append(text), increment=lambda: events.append("increment"))
    module.bind_installation_progress(engine, progress)
    if fails:
        with pytest.raises(RuntimeError, match="native package failure"):
            engine._install_packages("offline", verify=True)
        assert "increment" not in events
    else:
        assert engine._install_packages("offline", verify=True) == "native result"
        assert events[-1] == "increment"
    assert (("offline",), {"verify": True}) in events


@pytest.mark.parametrize("setting", ["", "ATLASO_DRY_RUN_SYSTEM_ADAPTERS=true\n", "ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false\nATLASO_DRY_RUN_SYSTEM_ADAPTERS=true\n"])
def test_installed_dry_run_refuses_completion_before_credentials(monkeypatch, tmp_path, setting):
    """An installed appliance must not silently retain simulated Apply behavior.

    Args:
        monkeypatch: Controlled native backend.
        tmp_path: Isolated target fixture.
        setting: Missing, simulated or ambiguous persisted configuration.
    """
    target = tmp_path / "target"
    env = target / "etc/atlaso/atlaso.env"
    env.parent.mkdir(parents=True)
    original = setting + 'ATLASO_BOOTSTRAP_ADMIN_PASSWORD="placeholder"\n'
    env.write_text(original)
    module = _install_fake_native_backend(monkeypatch, target, [])
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("credentials must remain unchanged"))
    with pytest.raises(ValueError, match="real system adapters"):
        module.install(tmp_path / "media", {"packages": ["linux"]}, {}, {}, ("Synthetic admin", "Synthetic root"))
    assert env.read_text() == original
    assert not (env.parent / "installation-profile").exists()


@pytest.mark.parametrize("fails", [False, True])
def test_native_output_does_not_propagate_to_progress_console(monkeypatch, tmp_path, fails):
    """Exercise real logging propagation, prints, and restoration on both outcomes.

    Args:
        monkeypatch: Isolated logger configuration.
        tmp_path: Native private-log fixture.
        fails: Whether the native operation fails inside the output boundary.
    """
    module = load_installer(monkeypatch)
    console, output = io.StringIO(), io.StringIO()
    logger = logging.getLogger("installer")
    parent = logging.Logger("installation-test-parent")
    parent.addHandler(logging.StreamHandler(console))
    existing = logging.StreamHandler(console)
    native_file = logging.FileHandler(tmp_path / "native.log")
    monkeypatch.setattr(logger, "parent", parent)
    monkeypatch.setattr(logger, "handlers", [existing, native_file])
    monkeypatch.setattr(logger, "propagate", True)
    monkeypatch.setattr(logger, "level", logging.INFO)
    descriptors = [module.os.fstat(fd) for fd in (1, 2)]
    original_stdout, original_stderr = sys.stdout, sys.stderr
    late = None
    try:
        try:
            with module.installation_output(output):
                logger.info("Skipping module for phase pre-install")
                print("native stdout")
                print("native stderr", file=sys.stderr)
                late = logging.StreamHandler()
                logger.addHandler(late)
                logger.info("Executing native stage")
                if fails:
                    raise RuntimeError("native failure")
        except RuntimeError:
            assert fails
        assert console.getvalue() == ""
        assert "Skipping module" in output.getvalue()
        assert "native stdout" in output.getvalue() and "native stderr" in output.getvalue()
        assert "Executing native stage" in output.getvalue()
        assert "Skipping module" in (tmp_path / "native.log").read_text()
        assert logger.propagate and existing.stream is console and late.stream is original_stderr
        assert sys.stdout is original_stdout and sys.stderr is original_stderr
        for fd, before in zip((1, 2), descriptors, strict=True):
            after = module.os.fstat(fd)
            assert (after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
    finally:
        native_file.close()


@pytest.mark.parametrize("fails", [False, True])
def test_install_console_closes_output_and_withholds_completion_on_failure(monkeypatch, tmp_path, fails):
    """Keep progress and private-output cleanup honest after a native failure.

    Args:
        monkeypatch: Isolated native control and installer doubles.
        tmp_path: Private log directory fixture.
        fails: Whether installation raises after a stage.
    """
    module = load_installer(monkeypatch)
    events = []
    streams = []
    window = SimpleNamespace(addstr=lambda *_args: None, refresh=lambda: None)

    class Progress:
        """Model the native control without terminals or timers."""
        def __init__(self, *_args):
            """Keep an isolated drawing surface.

            Args:
                *_args: Native control geometry.
            """
            self.window = window
        def update_num_items(self, count):
            """Record the total stage count.

            Args:
                count: Native progress denominator.
            """
            events.append(("total", count))
        def show(self):
            """Record visibility without creating a terminal."""
            events.append("show")
        def hide(self):
            """Record unconditional control cleanup."""
            events.append("hide")
        def increment(self):
            """Record successful completion accounting."""
            events.append("increment")
        def update_message(self, message):
            """Record non-secret stage text.

            Args:
                message: Displayed installation stage.
            """
            events.append(message)

    monkeypatch.setitem(sys.modules, "progressbar", SimpleNamespace(ProgressBar=Progress))
    monkeypatch.setitem(sys.modules, "window", SimpleNamespace(Window=lambda *_args: SimpleNamespace(show_window=lambda: None)))
    monkeypatch.setattr(module.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(module.os, "ttyname", lambda _fd: "/dev/ttyS0", raising=False)
    for name in ("init_pair", "curs_set"):
        setattr(module.curses, name, lambda *_args: None)
    for name in ("COLOR_WHITE", "COLOR_BLUE", "COLOR_BLACK", "COLOR_GREEN", "COLOR_RED"):
        setattr(module.curses, name, 0)
    module.curses.color_pair = lambda _pair: 0
    screen = SimpleNamespace(getmaxyx=lambda: (25, 80), bkgd=lambda *_args: None,
                             addnstr=lambda *_args: None, refresh=lambda: None)
    def install(*_args, **kwargs):
        """Simulate an unequal-duration stage and optional native failure.

        Args:
            *_args: Installation inputs, never logged.
            **kwargs: Native progress/output bindings.
        """
        streams.append(kwargs["output"])
        assert kwargs["log_path"] == tmp_path
        if fails:
            raise RuntimeError("native failure")
    monkeypatch.setattr(module, "install", install)
    if fails:
        with pytest.raises(RuntimeError, match="native failure"):
            module.install_console(screen, None, None, None, None, None)
        assert "increment" not in events
        assert "Installation completed" not in events
    else:
        module.install_console(screen, None, None, None, None, None)
        assert events[-3:] == ["Installation completed", "increment", "hide"]
    assert events[-1] == "hide"
    assert streams[0].closed


@pytest.mark.parametrize("mountpoint,expected", [
    ("/", None), ("/var/srv", None), ("/var/srv/app", None),
    ("/srv", "Use /var/srv"), ("/srv/app", "Use /var/srv/app"),
    ("/bin/app", "Use /usr/bin/app"), ("/var/run/app", "Use /run/app"),
    ("//srv", "canonical"), ("/srv/../var/srv", "canonical"), ("/var/srv\n", "No spaces"),
    ("/mnt/my data", "No spaces"), (r"/mnt/my\040data", "No spaces"), ("/mnt/my\u00a0data", "No spaces"),
    ("/var//srv", "canonical"), ("/var/srv/", "canonical"), ("relative", "canonical"),
    ("/proc", "reserved"), ("/proc/app", "reserved"), ("/sys", "reserved"),
    ("/dev/app", "reserved"), ("/run", "reserved"), ("/tmp/app", "reserved"),
])
def test_custom_mountpoint_rejects_native_aliases_before_consent(monkeypatch, mountpoint, expected):
    """Keep operator mount points canonical without rewriting a reviewed plan.

    Args:
        monkeypatch: Controlled native module loader.
        mountpoint: Proposed public Custom field.
        expected: Expected refusal substring, or acceptance for canonical paths.
    """
    module = load_installer(monkeypatch)
    aliases = {"/srv": "/var/srv", "/bin": "/usr/bin", "/var/run": "/run"}
    if expected:
        with pytest.raises(ValueError, match=expected):
            module.validate_custom_mountpoint(mountpoint, aliases)
    else:
        module.validate_custom_mountpoint(mountpoint, aliases)


def test_custom_mountpoint_refuses_native_alias_cycles(monkeypatch):
    """Fail before consent on a malformed native alias chain.

    Args:
        monkeypatch: Controlled native module loader.
    """
    module = load_installer(monkeypatch)
    with pytest.raises(ValueError, match="cycle"):
        module.validate_custom_mountpoint("/a", {"/a": "/b", "/b": "/a"})


@pytest.mark.parametrize("failure", ["", "changed", "missing", "duplicate", "malformed", "duplicate-path", "oversized", "timeout"])
def test_mount_alias_inventory_is_authenticated_and_bounded(monkeypatch, tmp_path, failure):
    """Query package headers only and reject missing, changed or malformed inputs.

    Args:
        monkeypatch: Native query replacement; no package scripts run.
        tmp_path: Synthetic authenticated media directory.
        failure: Guard whose refusal must precede native layout use.
    """
    module = load_installer(monkeypatch)
    directory = tmp_path / "rpms"
    directory.mkdir()
    package = directory / "filesystem-test.rpm"
    package.write_bytes(b"synthetic authenticated package")
    record = {"name": "filesystem", "file": package.name, "sha256": hashlib.sha256(package.read_bytes()).hexdigest()}
    identity = {"rpm_inventory": [record]}
    calls = []
    if failure == "changed":
        package.write_bytes(b"changed")
    elif failure == "missing":
        identity["rpm_inventory"] = []
    elif failure == "duplicate":
        identity["rpm_inventory"].append(record.copy())

    def query(command, **kwargs):
        """Return public RPM header rows without reading or executing an RPM.

        Args:
            command: Exact read-only query argument vector.
            **kwargs: Required subprocess deadline and output settings.
        """
        calls.append(command)
        assert command == ["rpm", "-qp", "--qf", "[%{FILENAMES}\t%{FILELINKTOS}\n]", str(package)]
        assert kwargs == {"check": True, "capture_output": True, "text": True, "timeout": 15}
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 15)
        output = "/srv\tvar/srv\n/var/run\t../run\n/var\t\n"
        if failure == "malformed":
            output = "/srv missing-tab\n"
        elif failure == "duplicate-path":
            output += "/srv\tvar/srv\n"
        elif failure == "oversized":
            output = "x" * 65537
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(module.subprocess, "run", query)
    if failure:
        expected = subprocess.TimeoutExpired if failure == "timeout" else ValueError
        with pytest.raises(expected):
            module.filesystem_mount_aliases(tmp_path, identity)
        if failure in {"changed", "missing", "duplicate"}:
            assert calls == []
    else:
        assert module.filesystem_mount_aliases(tmp_path, identity) == {"/srv": "/var/srv", "/var/run": "/run"}
        assert len(calls) == 1


def assert_native_confirmation_geometry(height, width, maxy, maxx, starty, message):
    """Check text and menu placement against Photon's pinned Window geometry.

    Args:
        height: Native ConfirmWindow height.
        width: Native ConfirmWindow width.
        maxy: Terminal height.
        maxx: Terminal width.
        starty: Native Menu start row.
        message: Complete text sent to ConfirmWindow.
    """
    line_count = len(message.splitlines())
    window_top = (maxy - height) // 2
    last_text_row = window_top + 2 + line_count - 1
    menu_last_row = starty
    assert height <= maxy
    assert width == maxx - 4
    assert height - 5 >= line_count
    assert starty == window_top + height - 4
    assert menu_last_row > last_text_row
    assert menu_last_row < window_top + height - 1
    assert maxx - 9 >= max(map(len, message.splitlines()))


@pytest.mark.parametrize("fails", [False, True])
def test_public_provisioning_checkpoint_precedes_child_and_preserves_failures(monkeypatch, tmp_path, fails):
    """Observe the actual provisioning entry without exposing private log output.

    Args:
        monkeypatch: Isolated native commands and progress observer.
        tmp_path: Task-owned target and admitted-input fixture.
        fails: Whether the shared provisioner fails after the checkpoint.
    """
    module = load_installer(monkeypatch)
    target, media = tmp_path / "target", tmp_path / "media"
    (target / "etc/atlaso").mkdir(parents=True)
    (media / "source").mkdir(parents=True)
    (media / "software").mkdir()
    (media / "software/release-manifest.json").write_text("{}")
    events = []
    output = io.StringIO()

    class Backend:
        """Invoke only the adapter's real shared-provisioning method."""
        def __init__(self, **_kwargs):
            """Bind the isolated target.

            Args:
                **_kwargs: Unused native constructor options.
            """
            self.photon_root = str(target)
            self.logger = SimpleNamespace(handlers=[])
        def configure(self, config):
            """Retain the native layout.

            Args:
                config: Tentative test configuration.
            """
            self.install_config = config
        def _unsafe_install(self):
            """Reach the real provisioning entry without native disk work."""
            self._provision_atlaso()
            events.append("success")
        def _unmount_all(self):
            """Record failure cleanup."""
            events.append("cleanup")

    def run(command, **kwargs):
        """Assert the public checkpoint precedes private child execution.

        Args:
            command: Public native command vector.
            **kwargs: Child options; environment values are discarded immediately.
        """
        kwargs.pop("env", None)
        if command[0] == "chroot":
            assert events[-1] == module.PROVISIONING_CHECKPOINT
            if kwargs.get("stdout") is not output or kwargs.get("stderr") is not output:
                raise AssertionError("provisioner output must stay on its private output stream")
            events.append("provisioner")
            if fails:
                raise RuntimeError("synthetic provisioning failure")
        return SimpleNamespace(returncode=0)

    monkeypatch.setitem(sys.modules, "installer", SimpleNamespace(Installer=Backend))
    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(module.Path, "symlink_to", lambda *_args: None)
    monkeypatch.setattr(module, "bind_installation_progress", lambda *_args: None)
    monkeypatch.setattr(module, "retain_development_inspection_inputs", lambda *_args: None)
    monkeypatch.setattr(module, "record_layout", lambda *_args: None)
    arguments = (media, {"packages": [], "source_commit": "a" * 40}, {"partitions": []}, {}, ("unused", "unused"))
    options = {"progress": SimpleNamespace(update_message=events.append), "output": output}
    if fails:
        with pytest.raises(RuntimeError, match="synthetic provisioning failure"):
            module.install(*arguments, **options)
        assert events == [module.PROVISIONING_CHECKPOINT, "provisioner", "cleanup"]
    else:
        module.install(*arguments, **options)
        assert events == [module.PROVISIONING_CHECKPOINT, "provisioner", "success"]


@pytest.mark.parametrize("boot_failure", [False, True])
def test_shared_provisioning_follows_native_grub_generation(monkeypatch, tmp_path, boot_failure):
    """Retain native finalization and generate boot files before shared provisioning.

    Args:
        monkeypatch: Scoped native backend replacement.
        tmp_path: Isolated target containing the generated boot configuration.
        boot_failure: Whether native bootloader generation fails before provisioning.
    """
    module = load_installer(monkeypatch)
    events = []
    grub = tmp_path / "grub.cfg"

    class Backend:
        def __init__(self, **kwargs):
            """Replace only shared provisioning with a checked ordering probe.

            Args:
                **kwargs: Native constructor settings supplied by the adapter.
            """
            self._provision_atlaso = self.checked_provisioning

        def checked_provisioning(self):
            assert grub.read_text() == "native generated configuration"
            events.append("provision")

        def configure(self, config):
            """Accept the adapter configuration without target mutation.

            Args:
                config: Native installation configuration.
            """

        def _finalize_system(self):
            events.append("native-finalize")

        def _setup_grub(self):
            events.append("native-grub")
            if boot_failure:
                raise RuntimeError("native bootloader failure")
            grub.write_text("native generated configuration")

        def _unsafe_install(self):
            self._finalize_system()
            self._setup_grub()
            events.append("native-fstab-and-postinstall")

        def _unmount_all(self):
            events.append("cleanup")

    monkeypatch.setitem(sys.modules, "installer", SimpleNamespace(Installer=Backend))
    if boot_failure:
        with pytest.raises(RuntimeError, match="native bootloader failure"):
            module.install(tmp_path, {"packages": ["linux"]}, {}, {}, ("unused", "unused"))
        assert events == ["native-finalize", "native-grub", "cleanup"]
    else:
        module.install(tmp_path, {"packages": ["linux"]}, {}, {}, ("unused", "unused"))
        assert events == ["native-finalize", "native-grub", "provision", "native-fstab-and-postinstall"]


def test_prompt_masks_secret_and_does_not_invoke_native_confirmation_lookup(monkeypatch):
    """Verify prompt masking without probing native confirmation state.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    module = load_installer(monkeypatch)
    calls = []

    class Reader:
        def __init__(self, *args):
            """Capture arguments passed to the fake native input reader.

            Args:
                *args: Args used by this test case.
            """
            calls.append(args)
            args[13]["value"] = "synthetic operator input"
            self.read_text = SimpleNamespace(textwin=SimpleNamespace())

        def get_user_string(self):
            return SimpleNamespace(success=True)

    monkeypatch.setitem(sys.modules, "windowstringreader", SimpleNamespace(WindowStringReader=Reader))
    assert module.prompt(25, 80, "Title", "First line\nSecond line", secret=True) == "synthetic operator input"
    assert calls[0][5] is None
    assert calls[0][6] == "*"
    assert calls[0][12] > 1


def test_rejected_secret_is_cleared_before_retry_without_revealing_input(monkeypatch):
    """A second attempt replaces a rejected secret instead of appending to it.

    Args:
        monkeypatch: Controlled native reader and screen dependencies.
    """
    module = load_installer(monkeypatch)
    events = []

    class Reader:
        def __init__(self, *args):
            """Retain the native validator and its memory-only input state.

            Args:
                *args: Native reader arguments.
            """
            self.args = args
            self.read_text = SimpleNamespace(textwin=SimpleNamespace(), init_text=lambda: events.append("cleared"))

        def get_user_string(self):
            """Exercise rejection, retry and exact whitespace comparison."""
            validate = self.args[8]
            assert validate("fixture-value") == (False, "Passwords do not match.")
            assert events == ["cleared"]
            assert validate(" fixture-value ") == (True, "")
            assert events == ["cleared"]
            self.args[13]["value"] = " fixture-value "
            return SimpleNamespace(success=True)

    monkeypatch.setitem(sys.modules, "windowstringreader", SimpleNamespace(WindowStringReader=Reader))
    result = module.prompt(25, 80, "Confirm", "Enter again", secret=True,
                           validator=lambda value: (True, "") if value == " fixture-value " else (False, "Passwords do not match."))
    assert result == " fixture-value "


@pytest.mark.parametrize("key,expected", [(8, 263), (127, 263), (13, 343), (263, 263), (65, 65)])
def test_concealed_input_accepts_terminal_backspace_codes(monkeypatch, key, expected):
    """Backspace variants reach the same native editing path; text is unchanged.

    Args:
        monkeypatch: Controlled curses constants.
        key: Incoming terminal key.
        expected: Normalized native key.
    """
    module = load_installer(monkeypatch)
    module.curses.KEY_BACKSPACE = 263
    module.curses.KEY_ENTER = 343
    window = SimpleNamespace(getch=lambda *_args: key, getmaxyx=lambda: (12, 70))
    adapter = module.ConsoleInputKeys(window)
    assert adapter.getch(2, 5) == expected
    assert adapter.getmaxyx() == (12, 70)


def test_password_confirmation_back_restarts_only_current_account(monkeypatch):
    """After mismatch and Back, confirm the replacement and keep policy checks.

    Args:
        monkeypatch: Controlled prompts without credentials or disk consumers.
    """
    module = load_installer(monkeypatch)
    titles = []

    def prompt(_maxy, _maxx, title, _message, *, secret, validator):
        """Drive a public fixture through mismatch, Back and replacement.

        Args:
            _maxy: Console height.
            _maxx: Console width.
            title: Account field title.
            _message: Operator guidance.
            secret: Required concealment.
            validator: Unchanged policy or exact-match validator.
        """
        titles.append(title)
        assert secret
        if len(titles) == 1:
            assert not validator("short")[0]
            return "Fixture-Password42!"
        if len(titles) == 2:
            assert not validator("Other-Password42!")[0]
            raise module.Cancelled()
        assert validator("Replacement-Password42!")[0]
        return "Replacement-Password42!"

    monkeypatch.setattr(module, "prompt", prompt)
    assert module.password_prompt(25, 80, "admin") == "Replacement-Password42!"
    assert titles == ["Set admin password", "Confirm admin password"] * 2
    monkeypatch.setattr(module, "prompt", lambda *_args, **_kwargs: (_ for _ in ()).throw(module.Cancelled()))
    with pytest.raises(module.Cancelled):
        module.password_prompt(25, 80, "root")


def test_root_password_back_discards_prior_admin_and_returns_to_admin(monkeypatch):
    """Back through accounts without returning an earlier password pair.

    Args:
        monkeypatch: Isolated account prompt responses.
    """
    module = load_installer(monkeypatch)
    names = []
    values = iter(["old-admin", module.Cancelled(), "new-admin", "new-root"])

    def password(_height, _width, username):
        """Return synthetic inputs and one first-field Back.

        Args:
            _height: Console height.
            _width: Console width.
            username: Account whose first field is shown.
        """
        names.append(username)
        value = next(values)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(module, "password_prompt", password)
    assert module.account_passwords(25, 80) == ("new-admin", "new-root")
    assert names == ["admin", "root", "admin", "root"]
    monkeypatch.setattr(module, "password_prompt", lambda *_args: (_ for _ in ()).throw(module.Cancelled()))
    assert module.account_passwords(25, 80) is None


@pytest.mark.parametrize("flow", ["custom-back", "admin-back", "admin-back-decline", "admin-back-disk-changed", "service-disks"])
def test_setup_back_navigation_preserves_prewrite_boundaries(monkeypatch, flow):
    """Exercise real wizard control flow with isolated native window doubles.

    Args:
        monkeypatch: Isolated native UI and inventory dependencies.
        flow: Navigation or refusal to exercise before returning installation inputs.
    """
    module = load_installer(monkeypatch)
    events = []
    review_lines = []
    configurations = []
    password_calls = []
    revalidations = []
    initial = {"/dev/sda": {"size": 64 * 1024**3, "serial": "target"}}
    if flow == "service-disks":
        initial.update({f"/dev/sd{letter}": {"size": 500 * 1024**3, "serial": letter} for letter in "bc"})

        def storage(_height, _width, _title, mountpoint, choices):
            """Bind both named roles to explicit data disks in the real wizard.

            Args:
                _height: Console rows.
                _width: Console columns.
                _title: Service title.
                mountpoint: Fixed service mount.
                choices: Exact offered assignments.
            """
            target = "/dev/sdb" if mountpoint.endswith("backups") else "/dev/sdc"
            return next(i for i, (_label, action, value) in enumerate(choices) if action == "disk" and value == target)

        monkeypatch.setattr(module, "storage_choice", storage)

    class SelectDisk:
        """Model explicit disk/layout selection only."""
        def __init__(self, _height, _width, config):
            """Retain each fresh configuration.

            Args:
                _height: Console rows.
                _width: Console columns.
                config: Native selection configuration.
            """
            assert "partitions" not in config
            self.config = config
            configurations.append(config)

        def display(self):
            """Choose Custom once or the supported Auto target."""
            self.config.update(disk="/dev/sda", autopartition=not (flow == "custom-back" and len(configurations) == 1))
            events.append("select")
            return SimpleNamespace(success=True)

    class CustomPartition:
        """Model an abandoned native Custom plan."""
        def __init__(self, _height, _width, config):
            """Retain a plan that must never reach disk consent.

            Args:
                _height: Console rows.
                _width: Console columns.
                config: Native Custom configuration.
            """
            self.config = config

        def display(self):
            """Return Back with deliberately unusable abandoned rows."""
            self.config["partitions"] = [{"disk": "/dev/abandoned", "mountpoint": "/old"}]
            events.append("custom-back")
            return SimpleNamespace(success=False)

    monkeypatch.setitem(sys.modules, "selectdisk", SimpleNamespace(SelectDisk=SelectDisk))
    monkeypatch.setitem(sys.modules, "custompartition", SimpleNamespace(CustomPartition=CustomPartition))
    monkeypatch.setitem(sys.modules, "partitionpane", SimpleNamespace(PartitionPane=type("Pane", (), {})))
    monkeypatch.setitem(sys.modules, "device", SimpleNamespace(Device=type("Device", (), {})))
    for name in ["COLOR_WHITE", "COLOR_BLUE", "COLOR_BLACK", "COLOR_GREEN", "COLOR_RED"]:
        setattr(module.curses, name, 0)
    for name in ["init_pair", "curs_set"]:
        setattr(module.curses, name, lambda *_args: None)
    module.curses.color_pair = lambda _index: 0
    screen = SimpleNamespace(getmaxyx=lambda: (25, 80), bkgd=lambda *_args: None)
    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "show_layout_review_pages", lambda *_args, **_kwargs:
                        (events.append("review-page"), review_lines.extend(_args[2])))

    def revalidate(config, consent, current):
        """Refuse changed evidence on return instead of retaining prior Yes.

        Args:
            config: Current plan.
            consent: Original identities.
            current: Read-only current inventory.
        """
        assert current == initial
        assert consent == {path: current[path] for path in module.selected_disks(config)}
        assert all(p.get("disk", "/dev/sda") in initial for p in config["partitions"])
        revalidations.append(True)
        if flow == "admin-back-disk-changed" and len(revalidations) == 3:
            raise ValueError("disk changed before renewed review")

    def confirm(*_args):
        """Record each new destructive decision.

        Args:
            *_args: Complete reviewed native confirmation.
        """
        events.append("confirm")
        if flow == "service-disks":
            reviewed = "\n".join([*review_lines, _args[2]])
            for path in initial:
                assert path in reviewed
            for _label, mountpoint in module.SERVICE_STORAGE:
                assert mountpoint in reviewed
        return not (flow == "admin-back-decline" and events.count("confirm") == 2)

    def password(_height, _width, username):
        """Go Back once, then provide fresh synthetic inputs.

        Args:
            _height: Console rows.
            _width: Console columns.
            username: Current local account.
        """
        password_calls.append(username)
        if flow.startswith("admin-back") and len(password_calls) == 1:
            raise module.Cancelled()
        return "fresh-" + username

    monkeypatch.setattr(module, "revalidate_disks", revalidate)
    monkeypatch.setattr(module, "confirm_installation", confirm)
    monkeypatch.setattr(module, "password_prompt", password)
    if flow == "admin-back-decline":
        with pytest.raises(module.Cancelled):
            module.configure_console(screen, initial, {})
        assert password_calls == ["admin"]
        assert events.count("confirm") == 2
    elif flow == "admin-back-disk-changed":
        with pytest.raises(ValueError, match="disk changed"):
            module.configure_console(screen, initial, {})
        assert password_calls == ["admin"]
        assert events.count("confirm") == 1
    else:
        config, consent, passwords = module.configure_console(screen, initial, {})
        assert passwords == ("fresh-admin", "fresh-root") and consent == initial
        assert config["partitions"][0] == {"mountpoint": "/", "size": 0, "filesystem": "ext4"}
        assert len(config["partitions"]) == (3 if flow == "service-disks" else 1)
        assert not any("password" in key for key in config)
        assert len(configurations) == (2 if flow == "custom-back" else 1)
        assert events.count("confirm") == (2 if flow == "admin-back" else 1)


@pytest.mark.parametrize("line_count", [1, 4, 5, 15])
def test_prompt_layout_fits_pinned_native_validation_error_row(monkeypatch, line_count):
    """Keep prompt text and ReadText's validation row inside Photon's text area.

    Args:
        monkeypatch: Pytest fixture for replacing the native reader.
        line_count: Number of unwrapped prompt lines to lay out at 80x25.
    """
    module = load_installer(monkeypatch)
    message = "\n".join(f"Prompt line {index}" for index in range(line_count))

    class NativeReaderDouble:
        def __init__(self, *args):
            """Enforce the pinned Window and ReadText row geometry.

            Args:
                *args: Positional WindowStringReader arguments from the adapter.
            """
            maxy, maxx, height, width = args[:4]
            display_lines = str(args[11]).splitlines()
            inputy = args[12]
            content_height = height - 5
            assert maxy == 25
            assert maxx == 80
            assert height <= maxy
            assert len(display_lines) == line_count
            # Photon Window creates textwin at (height - 5, width - 5).
            # ReadText.init_text writes both the input row and row y + 2.
            assert width - 5 > 0
            assert 0 <= inputy < content_height
            assert 0 <= inputy + 2 < content_height
            args[13]["value"] = "accepted"

        def get_user_string(self):
            return SimpleNamespace(success=True)

    monkeypatch.setitem(sys.modules, "windowstringreader", SimpleNamespace(WindowStringReader=NativeReaderDouble))
    assert module.prompt(25, 80, "Review", message) == "accepted"


def test_prompt_rejects_more_than_native_review_page_before_reader_creation(monkeypatch):
    """Reject a prompt beyond the native 80x25 text page before constructing UI.

    Args:
        monkeypatch: Fixture for detecting any unexpected native reader creation.
    """
    module = load_installer(monkeypatch)

    def unexpected_reader(*_args):
        """Reject construction after the adapter should have refused the page.

        Args:
            *_args: Native reader arguments that must never be used.
        """
        pytest.fail("out-of-page prompt must be rejected before creating the native reader")

    monkeypatch.setitem(sys.modules, "windowstringreader", SimpleNamespace(WindowStringReader=unexpected_reader))
    message = "\n".join(f"Prompt line {index}" for index in range(16))
    with pytest.raises(ValueError, match="console page size"):
        module.prompt(25, 80, "Review", message)


def test_long_layout_uses_complete_native_information_pages(monkeypatch):
    """Preserve every planned custom partition across native review pages.

    Args:
        monkeypatch: Pytest fixture for replacing the native confirmation window.
    """
    module = load_installer(monkeypatch)
    pages = []

    class ConfirmWindow:
        def __init__(self, height, _width, maxy, maxx, starty, message, info=False):
            """Capture each displayed page without involving curses.

            Args:
                height: Dialog height.
                _width: Dialog width.
                maxy: Terminal height.
                maxx: Terminal width.
                starty: Menu start row.
                message: Complete page text.
                info: Whether the dialog is informational.
            """
            assert_native_confirmation_geometry(height, _width, maxy, maxx, starty, message)
            pages.append((message, info))

        def do_action(self):
            """Accept the informational page."""
            return SimpleNamespace(success=True, result={"yes": True})

    monkeypatch.setitem(sys.modules, "confirmwindow", SimpleNamespace(ConfirmWindow=ConfirmWindow))
    lines = [f"/dev/sda planned partition {index:02d} /mount/{index:02d} ext4 1024 MiB" for index in range(40)]

    module.show_layout_review_pages(25, 80, lines)

    assert len(pages) > 1
    assert all(info for _message, info in pages)
    rendered = "\n".join(message for message, _info in pages)
    for line in lines:
        assert line in rendered


def test_cancelled_native_layout_page_aborts_review(monkeypatch):
    """Do not proceed to credentials when a Photon information page fails.

    Args:
        monkeypatch: Pytest fixture for replacing the native confirmation window.
    """
    module = load_installer(monkeypatch)

    class ConfirmWindow:
        def __init__(self, _height, _width, _maxy, _maxx, _starty, _message, info=False):
            """Accept only the native info-page constructor contract.

            Args:
                _height: Dialog height.
                _width: Dialog width.
                _maxy: Terminal height.
                _maxx: Terminal width.
                _starty: Menu start row.
                _message: Complete page text.
                info: Whether this is an informational page.
            """
            assert info

        def do_action(self):
            """Report native dismissal as an unsuccessful action."""
            return SimpleNamespace(success=False, result=None)

    monkeypatch.setitem(sys.modules, "confirmwindow", SimpleNamespace(ConfirmWindow=ConfirmWindow))

    with pytest.raises(module.Cancelled):
        module.show_layout_review_pages(25, 80, [f"/dev/sda partition {index}" for index in range(20)])


def test_environment_value_round_trips_posix_shell_metacharacters(monkeypatch, tmp_path):
    """Round-trip shell metacharacters through the environment helper.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    module = load_installer(monkeypatch)
    shell = Path(shutil.which("sh") or r"C:\Program Files\Git\usr\bin\sh.exe")
    if not shell.is_file():
        pytest.skip("POSIX sh is unavailable")

    value = ' leading "quotes" \\ paths $HOME $(touch marker) ' + chr(96) + 'touch marker' + chr(96) + ' ; trailing '
    environment_file = tmp_path / "atlaso.env"
    environment_file.write_text(
        f"ATLASO_BOOTSTRAP_ADMIN_PASSWORD={module.environment_value(value)}\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(shell),
            "-c",
            '. "$1"; printf "%s" "$ATLASO_BOOTSTRAP_ADMIN_PASSWORD"',
            "installation-environment-roundtrip",
            str(environment_file),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    assert result.stdout == value.encode("utf-8")
    assert not (tmp_path / "marker").exists()


def _install_fake_native_backend(monkeypatch, target, events, *, fail_at=None):
    """Install a native-backend double that drives the adapter's completion callback.

Args:
    monkeypatch: Pytest fixture for replacing controlled dependencies.
    target: Destination root or target under test.
    events: Recorded backend events used to verify operation order.
    fail_at: Backend stage that should raise an error.
"""
    module = load_installer(monkeypatch)
    boot = target / "boot"
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "vmlinuz-test").write_bytes(b"native kernel")
    (boot / "initrd.img-test").write_bytes(b"native initrd")
    monkeypatch.setattr(module.subprocess, "check_output", lambda *args, **kwargs: "photon_linux=vmlinuz-test\nphoton_initrd=initrd.img-test\n")

    class Backend:
        def __init__(self, **_kwargs):
            """Capture native backend constructor settings without target mutation.

            Args:
                **_kwargs: Additional keyword arguments supplied to the test double.
            """
            self.photon_root = str(target)

        def configure(self, config):
            """Record configuration passed to the fake native backend.

            Args:
                config: Installer configuration passed to the fake backend.
            """
            self.install_config = config

        def _clear_vgs(self):
            events.append("host-wide-vg-clear")

        def _unsafe_install(self):
            self._clear_vgs()
            for stage in ("post-install-root-default", "grub", "fstab"):
                events.append(stage)
                if stage == fail_at:
                    raise RuntimeError(f"synthetic failure at {stage}")
            self.atlaso_provisioned = True
            self._deactivate_network_in_chroot()
            events.append("install-complete")

        def _unmount_all(self):
            events.append("unmount")

    monkeypatch.setitem(sys.modules, "installer", SimpleNamespace(Installer=Backend))
    return module


def test_native_completion_callback_applies_chosen_credentials_only_after_boot_setup(monkeypatch, tmp_path):
    """Apply credentials only after native boot setup completes.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    target = tmp_path / "target"
    atlaso = target / "etc/atlaso"
    atlaso.mkdir(parents=True)
    env_path = atlaso / "atlaso.env"
    env_path.write_text('ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false\nATLASO_BOOTSTRAP_ADMIN_PASSWORD="generated-placeholder"\n', encoding="utf-8")
    events = []
    module = _install_fake_native_backend(monkeypatch, target, events)
    chpasswd = []

    def run(command, *, input, **kwargs):
        """Record the password command without running a subprocess.

        Args:
            command: Subprocess argument vector received by the test double.
            input: Standard input supplied to the mocked subprocess.
            **kwargs: Additional subprocess options received by the test double.
        """
        events.append("chpasswd")
        chpasswd.append((command, input, kwargs))

    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(module.os, "sync", lambda: None, raising=False)

    module.install(
        tmp_path / "media",
        {"packages": ["linux"]},
        {"arch": "x86_64", "bootmode": "efi", "partitions": []},
        {},
        ("Synthetic admin $value", "Synthetic root value"),
    )

    assert events == [
        "post-install-root-default",
        "grub",
        "fstab",
        "chpasswd",
        "install-complete",
    ]
    assert "host-wide-vg-clear" not in events
    assert env_path.read_text(encoding="utf-8") == (
        "ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false\nATLASO_BOOTSTRAP_ADMIN_PASSWORD="
        + module.environment_value("Synthetic admin $value")
        + "\n"
    )
    assert (atlaso / "installation-profile").read_text(encoding="utf-8") == module.PROFILE
    assert len(chpasswd) == 1
    command, input_value, kwargs = chpasswd[0]
    assert command == ["chroot", str(target), "chpasswd"]
    assert input_value == "admin:Synthetic admin $value\nroot:Synthetic root value\n"
    assert kwargs == {
        "text": True,
        "check": True,
        "stdout": module.subprocess.DEVNULL,
        "stderr": module.subprocess.DEVNULL,
    }
    assert all("Synthetic" not in argument for argument in command)


@pytest.mark.parametrize("failure_stage", ["post-install-root-default", "grub", "fstab"])
def test_native_failure_before_completion_callback_preserves_no_profile(
    monkeypatch, tmp_path, failure_stage
):
    """Preserve the target when native setup fails before completion.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
        failure_stage: Native installation stage where the test injects failure.
    """
    target = tmp_path / "target"
    atlaso = target / "etc/atlaso"
    atlaso.mkdir(parents=True)
    env_path = atlaso / "atlaso.env"
    original = 'ATLASO_BOOTSTRAP_ADMIN_PASSWORD="generated-placeholder"\n'
    env_path.write_text(original, encoding="utf-8")
    events = []
    module = _install_fake_native_backend(monkeypatch, target, events, fail_at=failure_stage)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("credentials must not run before native completion"),
    )

    with pytest.raises(RuntimeError, match="synthetic failure"):
        module.install(
            tmp_path / "media",
            {"packages": ["linux"]},
            {"arch": "x86_64", "bootmode": "efi", "partitions": []},
            {},
            ("Synthetic admin", "Synthetic root"),
        )

    assert "host-wide-vg-clear" not in events
    assert not (atlaso / "installation-profile").exists()
    assert env_path.read_text(encoding="utf-8") == original


def test_cancelled_prompt_returns_no_consent(monkeypatch):
    """Return no consent when the native prompt is cancelled.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    module = load_installer(monkeypatch)
    reader = SimpleNamespace(get_user_string=lambda: SimpleNamespace(success=False))
    monkeypatch.setitem(sys.modules, "windowstringreader", SimpleNamespace(WindowStringReader=lambda *args: reader))
    with pytest.raises(module.Cancelled):
        module.prompt(25, 80, "Review", "Confirm disk")


@pytest.mark.parametrize("size_gib", [4, 63, 64, 128])
def test_disk_review_cancellation_returns_before_passwords_or_install(monkeypatch, size_gib):
    """Stop before password handling when disk review is cancelled.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        size_gib: Selected disk capacity, including the minimum boundary.
    """
    module = load_installer(monkeypatch)
    calls = []

    class Screen:
        def getmaxyx(self):
            return 25, 80

        def bkgd(self, *_args):
            """Accept a native background-paint call without changing state.

            Args:
                *_args: Additional positional arguments supplied to the test double.
            """
            pass

    class SelectDisk:
        def __init__(self, _height, _width, config):
            """Retain the configuration passed to the fake selection window.

            Args:
                _height: Console height supplied to the fake UI callback.
                _width: Console width supplied to the fake UI callback.
                config: Installer configuration passed to the fake backend.
            """
            self.config = config

        def display(self):
            self.config.update({"disk": "/dev/nvme0n1", "autopartition": True})
            return SimpleNamespace(success=True)

    class CustomPartition:
        pass

    class Device:
        refresh_devices = None
        refresh_devices_bytes = None

    class PartitionPane:
        pass

    for name, value in (
        ("custompartition", SimpleNamespace(CustomPartition=CustomPartition, PartitionPane=PartitionPane)),
        ("device", SimpleNamespace(Device=Device)),
        ("partitionpane", SimpleNamespace(PartitionPane=PartitionPane)),
        ("selectdisk", SimpleNamespace(SelectDisk=SelectDisk)),
    ):
        monkeypatch.setitem(sys.modules, name, value)
    initial = {"/dev/nvme0n1": {"size": size_gib * 1024**3, "model": "Test NVMe", "serial": "serial-root"}}
    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "selected_disks", lambda _config: ["/dev/nvme0n1"])
    monkeypatch.setattr(module, "revalidate_disks", lambda *_args: calls.append("revalidate"))

    confirmation = {}

    class ConfirmWindow:
        def __init__(self, height, width, maxy, maxx, starty, message, info=False):
            """Record the complete destructive confirmation.

            Args:
                height: Native dialog height.
                width: Native dialog width.
                maxy: Terminal height.
                maxx: Terminal width.
                starty: Menu start row.
                message: Complete confirmation message.
                info: Whether the dialog is informational.
            """
            assert_native_confirmation_geometry(height, width, maxy, maxx, starty, message)
            confirmation["message"] = message
            confirmation["info"] = info
            self.menu = SimpleNamespace(position=0)

        def do_action(self):
            """Cancel an informational refusal or decline destructive confirmation."""
            confirmation["default"] = self.menu.position
            return SimpleNamespace(success=not confirmation["info"], result={"yes": False})

    monkeypatch.setitem(sys.modules, "confirmwindow", SimpleNamespace(ConfirmWindow=ConfirmWindow))

    def prompt(_height, _width, title, _message, *, secret=False, validator=None):
        """Capture prompt arguments for the fake native reader.

        Args:
            _height: Console height supplied to the fake UI callback.
            _width: Console width supplied to the fake UI callback.
            title: Prompt title shown by the console adapter.
            _message: Prompt text passed to the fake UI callback.
            secret: Whether the fake prompt should conceal its input.
            validator: Validation callback passed to the prompt.
        """
        calls.append((title, secret))
        pytest.fail("password prompt must not follow cancelled destructive review")

    monkeypatch.setattr(module, "prompt", prompt)
    for name, value in (
        ("COLOR_WHITE", 1),
        ("COLOR_BLUE", 2),
        ("COLOR_BLACK", 3),
        ("COLOR_GREEN", 4),
        ("COLOR_RED", 5),
    ):
        monkeypatch.setattr(module.curses, name, value, raising=False)
    monkeypatch.setattr(module.curses, "init_pair", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "curs_set", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "color_pair", lambda *_args: 0, raising=False)

    if size_gib < 64:
        with pytest.raises(module.Cancelled):
            module.configure_console(Screen(), initial, {"/srv": "/var/srv"})
        assert calls == ["revalidate"]
        assert confirmation["info"] is True
        assert "default installation requires a disk of at least 64 GiB" in confirmation["message"]
        assert f"Selected /dev/nvme0n1 has {size_gib * 1024**3} bytes." in confirmation["message"]
        assert "Press Enter to choose another disk, or Esc to cancel." in confirmation["message"]
    else:
        with pytest.raises(module.Cancelled):
            module.configure_console(Screen(), initial, {"/srv": "/var/srv"})
        assert calls == ["revalidate", "revalidate"]
        assert confirmation["default"] == 1
        assert "Erase selected disks?" in confirmation["message"]
        assert f"/dev/nvme0n1: Test NVMe {size_gib} GiB" in confirmation["message"]
        assert "Serial/WWN: serial-root" in confirmation["message"]
        assert "/boot/efi vfat 10 MiB (Photon UEFI default)" in confirmation["message"]
        assert "ALL EXISTING DATA ON SELECTED DISKS WILL BE LOST." in confirmation["message"]


def test_small_default_disk_refusal_returns_to_native_disk_selection(monkeypatch):
    """Allow choosing a different disk after a native capacity refusal.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    module = load_installer(monkeypatch)
    selected = []
    messages = []

    class Screen:
        def getmaxyx(self):
            return 25, 80

        def bkgd(self, *_args):
            """Accept the standard Photon background setup.

            Args:
                *_args: Background arguments supplied by the installer.
            """

    class SelectDisk:
        def __init__(self, _height, _width, config):
            """Capture the selection configuration.

            Args:
                _height: Terminal height supplied by the installer.
                _width: Terminal width supplied by the installer.
                config: Mutable native installer configuration.
            """
            self.config = config

        def display(self):
            path = ("/dev/sdb", "/dev/nvme0n1")[len(selected)]
            selected.append(path)
            self.config.update({"disk": path, "autopartition": True})
            return SimpleNamespace(success=True)

    class ConfirmWindow:
        def __init__(self, height, width, maxy, maxx, starty, message, info=False):
            """Capture and validate a native Photon confirmation window.

            Args:
                height: Dialog height.
                width: Dialog width.
                maxy: Terminal height.
                maxx: Terminal width.
                starty: Native menu start row.
                message: Text presented by the dialog.
                info: Whether the dialog is informational.
            """
            assert_native_confirmation_geometry(height, width, maxy, maxx, starty, message)
            messages.append((message, info))
            self.menu = SimpleNamespace(position=0)

        def do_action(self):
            if messages[-1][1]:
                return SimpleNamespace(success=True, result={})
            return SimpleNamespace(success=True, result={"yes": False})

    class CustomPartition:
        pass

    class Device:
        refresh_devices = None
        refresh_devices_bytes = None

    class PartitionPane:
        pass

    monkeypatch.setitem(sys.modules, "custompartition", SimpleNamespace(
        CustomPartition=CustomPartition, PartitionPane=PartitionPane,
    ))
    monkeypatch.setitem(sys.modules, "device", SimpleNamespace(Device=Device))
    monkeypatch.setitem(sys.modules, "partitionpane", SimpleNamespace(PartitionPane=PartitionPane))
    monkeypatch.setitem(sys.modules, "selectdisk", SimpleNamespace(SelectDisk=SelectDisk))
    monkeypatch.setitem(sys.modules, "confirmwindow", SimpleNamespace(ConfirmWindow=ConfirmWindow))
    initial = {
        "/dev/sdb": {"size": 4 * 1024**3, "model": "Small test disk", "serial": "serial-small"},
        "/dev/nvme0n1": {"size": 128 * 1024**3, "model": "NVMe", "serial": "serial-root"},
    }
    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "selected_disks", lambda config: [config["disk"]])
    revalidated = []
    monkeypatch.setattr(module, "revalidate_disks", lambda _config, consent, _current: revalidated.append(tuple(consent)))
    monkeypatch.setattr(module.curses, "init_pair", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "curs_set", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "color_pair", lambda *_args: 0, raising=False)
    monkeypatch.setattr(module.curses, "COLOR_WHITE", 1, raising=False)
    monkeypatch.setattr(module.curses, "COLOR_BLUE", 2, raising=False)
    monkeypatch.setattr(module.curses, "COLOR_BLACK", 3, raising=False)
    monkeypatch.setattr(module.curses, "COLOR_GREEN", 4, raising=False)
    monkeypatch.setattr(module.curses, "COLOR_RED", 5, raising=False)
    monkeypatch.setattr(module, "prompt", lambda *_args, **_kwargs: pytest.fail("credentials must follow capacity admission"))

    with pytest.raises(module.Cancelled):
        module.configure_console(Screen(), initial, {"/srv": "/var/srv"})

    assert selected == ["/dev/sdb", "/dev/nvme0n1"]
    assert len(revalidated) == 3
    assert messages[0][1] is True
    assert "Selected /dev/sdb has 4294967296 bytes." in messages[0][0]
    assert messages[1][1] is False


def test_custom_multi_disk_adapter_displays_selected_disk_and_maps_each_partition(monkeypatch):
    """Map each selected disk through the native adapter.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    module = load_installer(monkeypatch)
    interactions = []

    class Screen:
        def getmaxyx(self):
            return 30, 100

        def bkgd(self, *_args):
            """Accept a native background-paint call without changing state.

            Args:
                *_args: Additional positional arguments supplied to the test double.
            """
            pass

    class Device:
        def __init__(self, _model, path, _size):
            """Retain the selected disk path in the native UI double.

            Args:
                _model: Model string supplied to the fake disk record.
                path: Path to the fixture or file being tested.
                _size: Display size supplied to the fake disk record.
            """
            self.path = path

    class SelectDisk:
        selected = iter(("/dev/nvme0n1", "/dev/nvme0n1", "/dev/nvme0n1", "/dev/sdb"))

        def __init__(self, _height, _width, selection):
            """Retain the disk selection passed to the fake native selector.

            Args:
                _height: Console height supplied to the fake UI callback.
                _width: Console width supplied to the fake UI callback.
                selection: Mutable disk selection returned by the fake selector.
            """
            self.selection = selection

        def display(self):
            self.selection["disk"] = next(self.selected)
            return SimpleNamespace(success=True)

    class PartitionPane:
        def __init__(self):
            self.config = {
                "partitionsnumber": 3,
                "0partition_disk": "/dev/nvme0n1",
                "1partition_disk": "/dev/nvme0n1",
                "2partition_disk": "/dev/sdb",
            }
            self.text_items = [(None, 12)]
            self.lines = ["header", "root partition", "var partition", "backup partition"]

        def partition(self):
            return None

    class CustomPartition:
        def __init__(self, _height, _width, config):
            """Retain the configuration passed to the fake partition form.

            Args:
                _height: Console height supplied to the fake UI callback.
                _width: Console width supplied to the fake UI callback.
                config: Installer configuration passed to the fake backend.
            """
            self.config = config
            self.disk_to_index = {"/dev/nvme0n1": 0, "/dev/sdb": 1}
            self.devices = [Device("NVMe", "/dev/nvme0n1", "128 GiB"), Device("SATA", "/dev/sdb", "256 GiB")]
            self.device_index = 0
            self.cp_config = {"partitionsnumber": 0}
            self.install_config = {
                "partitions": [
                    {"mountpoint": "/", "filesystem": "ext4", "size": 0},
                    {"mountpoint": "/var/lib/atlaso", "filesystem": "ext4", "size": 4096},
                    {"mountpoint": "/mnt/atlaso-vcf-backups", "filesystem": "xfs", "size": 8192},
                ]
            }

        def initialize_devices(self):
            return None

        def create_function(self):
            return SimpleNamespace(success=True)

        def validate_partition(self, _values):
            """Accept partition validation in the isolated UI double.

            Args:
                _values: Partition fields passed to the fake validator.
            """
            return True, ""

        def next(self):
            return SimpleNamespace(success=True)

        def display(self):
            for filesystem in ("xfs", "btrfs", "vfat"):
                assert self.validate_partition(("", filesystem, "/boot", "512")) == (
                    False, "The Photon EFI loader requires ext4 for /boot.",
                )
            assert self.validate_partition(("", "vfat", "/", "0")) == (
                False, "The root filesystem must be ext4, xfs, or btrfs.",
            )
            assert self.validate_partition(("", "ext4", "/srv", "0")) == (
                False, "Use /var/srv; /srv is a symlink.",
            )
            assert self.cp_config["partitionsnumber"] == 0
            assert self.partition_disks == {}
            self.create_function()
            self.cp_config.update({"partitionsnumber": 0, "0partition_info0": "existing"})
            self.validate_partition(("", "ext4", "/", "0"))
            self.create_function()
            self.cp_config.update({"partitionsnumber": 1, "1partition_info0": "existing"})
            self.validate_partition(("", "ext4", "/var/lib/atlaso", "4096"))
            self.create_function()
            self.cp_config.update({"partitionsnumber": 2, "2partition_info0": "existing"})
            self.validate_partition(("", "xfs", "/mnt/atlaso-vcf-backups", "8192"))
            result = self.next()
            self.config["partitions"] = self.install_config["partitions"]
            interactions.append(self.install_config["partitions"])
            return result

    custompartition_module = SimpleNamespace(CustomPartition=CustomPartition, PartitionPane=PartitionPane)
    monkeypatch.setitem(sys.modules, "custompartition", custompartition_module)
    monkeypatch.setitem(sys.modules, "device", SimpleNamespace(Device=Device))
    monkeypatch.setitem(sys.modules, "partitionpane", SimpleNamespace(PartitionPane=PartitionPane))
    monkeypatch.setitem(sys.modules, "selectdisk", SimpleNamespace(SelectDisk=SelectDisk))
    initial = {
        "/dev/nvme0n1": {"size": 128 * 1024**3, "model": "NVMe", "serial": "serial-root"},
        "/dev/sdb": {"size": 256 * 1024**3, "model": "SATA", "serial": "serial-backup"},
    }
    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "selected_disks", lambda _config: ["/dev/nvme0n1", "/dev/sdb"])
    monkeypatch.setattr(module, "revalidate_disks", lambda *_args: None)

    confirmations = []
    password_errors = []

    class ConfirmWindow:
        def __init__(self, height, width, maxy, maxx, starty, message, info=False):
            """Capture the full summary shown for both selected disks.

            Args:
                height: Native dialog height.
                width: Native dialog width.
                maxy: Terminal height.
                maxx: Terminal width.
                starty: Menu start row.
                message: Full confirmation content.
                info: Whether this is an informational page.
            """
            assert_native_confirmation_geometry(height, width, maxy, maxx, starty, message)
            confirmations.append({"message": message, "info": info})
            self.menu = SimpleNamespace(position=0)

        def do_action(self):
            """Accept the dialog after capturing its default choice."""
            confirmations[-1]["default"] = self.menu.position
            return SimpleNamespace(success=True, result={"yes": True})

    monkeypatch.setitem(sys.modules, "confirmwindow", SimpleNamespace(ConfirmWindow=ConfirmWindow))

    def prompt(_height, _width, title, message, *, secret=False, validator=None):
        """Capture prompt layout and validation arguments for the fake native UI.

        Args:
            _height: Console height supplied to the fake UI callback.
            _width: Console width supplied to the fake UI callback.
            title: Prompt title shown by the console adapter.
            message: Expected validation message or prompt text.
            secret: Whether the fake prompt should conceal its input.
            validator: Validation callback passed to the prompt.
        """
        if title.startswith("Set "):
            value = "Good-Password42!"
            assert validator(value)[0]
            return value
        if secret and validator:
            accepted, error = validator("Other-Password42!")
            assert not accepted
            password_errors.append(error)
            assert validator("Good-Password42!")[0]
            return "Good-Password42!"
        return "test-password"

    monkeypatch.setattr(module, "prompt", prompt)
    for name, value in (
        ("COLOR_WHITE", 1),
        ("COLOR_BLUE", 2),
        ("COLOR_BLACK", 3),
        ("COLOR_GREEN", 4),
        ("COLOR_RED", 5),
    ):
        monkeypatch.setattr(module.curses, name, value, raising=False)
    monkeypatch.setattr(module.curses, "init_pair", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "curs_set", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "color_pair", lambda *_args: 0, raising=False)

    config, consent, _credentials = module.configure_console(Screen(), initial, {"/srv": "/var/srv"})

    assert interactions == [[
        {"mountpoint": "/", "filesystem": "ext4", "size": 0, "disk": "/dev/nvme0n1"},
        {"mountpoint": "/var/lib/atlaso", "filesystem": "ext4", "size": 4096, "disk": "/dev/nvme0n1"},
        {"mountpoint": "/mnt/atlaso-vcf-backups", "filesystem": "xfs", "size": 8192, "disk": "/dev/sdb"},
    ]]
    assert consent == initial
    assert config["partitions"] == interactions[0]
    assert len(confirmations) == 1
    confirmation = confirmations[0]
    assert confirmation["info"] is False
    assert confirmation["default"] == 1
    assert "Erase selected disks?" in confirmation["message"]
    assert "/dev/nvme0n1: NVMe 128 GiB" in confirmation["message"]
    assert "Serial/WWN: serial-root" in confirmation["message"]
    assert "/dev/sdb: SATA 256 GiB" in confirmation["message"]
    assert "Serial/WWN: serial-backup" in confirmation["message"]
    assert "/mnt/atlaso-vcf-backups xfs 8192 MiB" in confirmation["message"]
    assert password_errors == ["Passwords do not match.", "Passwords do not match."]
    pane = custompartition_module.PartitionPane()
    pane.partition()
    assert pane.lines[1].startswith("/dev/nvme0n1")
    assert pane.lines[2].startswith("/dev/nvme0n1")
    assert pane.lines[3].startswith("/dev/sdb")


def test_large_custom_disk_review_pages_identities_and_layout_before_cancellable_confirmation(monkeypatch):
    """Review every selected identity and layout before a bounded No-default confirmation.

    Args:
        monkeypatch: Fixture for replacing Photon controls and disk access.
    """
    module = load_installer(monkeypatch)
    paths = [f"/dev/sd{letter}" for letter in "abcdefg"]
    initial = {
        path: {"size": 128 * 1024**3, "model": f"Model {index}", "serial": f"serial-{index}"}
        for index, path in enumerate(paths, start=1)
    }
    mountpoints = ["/", *(f"/mnt/atlaso-volume-{index}" for index in range(1, len(paths)))]
    partitions = [
        {"mountpoint": mountpoint, "filesystem": "ext4", "size": 1024, "disk": path}
        for path, mountpoint in zip(paths, mountpoints, strict=True)
    ]

    class Screen:
        def getmaxyx(self):
            return 25, 80

        def bkgd(self, *_args):
            """Accept a native background-paint call without changing state.

            Args:
                *_args: Additional positional arguments passed to the test double.
            """
            pass

    class SelectDisk:
        def __init__(self, _height, _width, config):
            """Retain the configuration passed to the fake disk selector.

            Args:
                _height: Console height passed to the fake UI callback.
                _width: Console width passed to the fake UI callback.
                config: Installation configuration supplied by the adapter.
            """
            self.config = config

        def display(self):
            self.config.update({"disk": paths[0], "autopartition": False})
            return SimpleNamespace(success=True)

    class CustomPartition:
        def __init__(self, _height, _width, config):
            """Retain the configuration passed to the fake capacity dialog.

            Args:
                _height: Console height passed to the fake UI callback.
                _width: Console width passed to the fake UI callback.
                config: Installation configuration supplied by the adapter.
            """
            self.config = config
            self.install_config = {"partitions": partitions}

        def display(self):
            self.partition_disks = {index: path for index, path in enumerate(paths)}
            result = self.next()
            self.config.update(self.install_config)
            return result

        def next(self):
            return SimpleNamespace(success=True)

    class ConfirmWindow:
        def __init__(self, height, width, maxy, maxx, starty, message, info=False):
            """Capture the native confirmation geometry and message.

            Args:
                height: Dialog height supplied to the fake confirmation window.
                width: Dialog width supplied to the fake confirmation window.
                maxy: Terminal height supplied to the fake confirmation window.
                maxx: Terminal width supplied to the fake confirmation window.
                starty: Menu start row supplied to the fake confirmation window.
                message: Confirmation text supplied by the installer.
                info: Whether the confirmation window is informational.
            """
            assert_native_confirmation_geometry(height, width, maxy, maxx, starty, message)
            dialogs.append({"message": message, "info": info})
            self.menu = SimpleNamespace(position=0)

        def do_action(self):
            dialogs[-1]["default"] = self.menu.position
            return SimpleNamespace(success=True, result={"yes": False})

    dialogs = []
    custompartition = SimpleNamespace(CustomPartition=CustomPartition, PartitionPane=object)
    monkeypatch.setitem(sys.modules, "custompartition", custompartition)
    monkeypatch.setitem(sys.modules, "device", SimpleNamespace(Device=type("Device", (), {})))
    monkeypatch.setitem(sys.modules, "partitionpane", SimpleNamespace(PartitionPane=object))
    monkeypatch.setitem(sys.modules, "selectdisk", SimpleNamespace(SelectDisk=SelectDisk))
    monkeypatch.setitem(sys.modules, "confirmwindow", SimpleNamespace(ConfirmWindow=ConfirmWindow))
    monkeypatch.setattr(module, "disk_inventory", lambda: initial)
    monkeypatch.setattr(module, "selected_disks", lambda _config: paths)
    monkeypatch.setattr(module, "revalidate_disks", lambda *_args: None)
    monkeypatch.setattr(module, "prompt", lambda *_args, **_kwargs: pytest.fail("credentials must follow consent"))
    writes = []
    monkeypatch.setattr(module, "install", lambda *_args: writes.append("install"))
    for name, value in (
        ("COLOR_WHITE", 1),
        ("COLOR_BLUE", 2),
        ("COLOR_BLACK", 3),
        ("COLOR_GREEN", 4),
        ("COLOR_RED", 5),
    ):
        monkeypatch.setattr(module.curses, name, value, raising=False)
    monkeypatch.setattr(module.curses, "init_pair", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "curs_set", lambda *_args: None, raising=False)
    monkeypatch.setattr(module.curses, "color_pair", lambda *_args: 0, raising=False)

    with pytest.raises(module.Cancelled):
        module.configure_console(Screen(), initial, {"/srv": "/var/srv"})

    information = [dialog["message"] for dialog in dialogs if dialog["info"]]
    assert len(information) >= 4
    rendered_review = "\n".join(information)
    for index, path in enumerate(paths, start=1):
        assert f"{path}: Model {index} 128 GiB" in rendered_review
        assert f"Serial/WWN: serial-{index}" in rendered_review
        assert f"{path} planned layout:" in rendered_review
        assert mountpoints[index - 1] in rendered_review
    destructive = [dialog for dialog in dialogs if not dialog["info"]]
    assert len(destructive) == 1
    assert destructive[0]["default"] == 1
    assert "ALL EXISTING DATA ON SELECTED DISKS WILL BE LOST." in destructive[0]["message"]
    assert "Select Yes to continue or No to cancel." in destructive[0]["message"]
    assert len(destructive[0]["message"].splitlines()) + 7 <= 25
    assert writes == []


def test_changed_disk_prevents_native_partition_call(monkeypatch, tmp_path):
    """Avoid partitioning after the selected disk changes.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    module = load_installer(monkeypatch)
    mutations = []

    class Backend:
        def __init__(self, **kwargs):
            """Accept backend construction without changing installation state.

            Args:
                **kwargs: Additional subprocess options received by the test double.
            """
            pass

        def configure(self, value):
            """Record the configuration passed to the fake backend.

            Args:
                value: Value supplied to the test case.
            """
            self.install_config = value

        def _unsafe_install(self):
            self._partition_disks()

        def _partition_disks(self):
            mutations.append("partition")

        def _unmount_all(self):
            mutations.append("unmount")

    monkeypatch.setitem(sys.modules, "installer", SimpleNamespace(Installer=Backend))
    monkeypatch.setattr(module, "disk_inventory", lambda: {})
    monkeypatch.setattr(module, "require_network_adapter", lambda: None)
    config = {"disk": "/dev/sda", "arch": "x86_64", "bootmode": "efi", "partitions": [{"mountpoint": "/", "filesystem": "ext4", "size": 0}]}
    with pytest.raises(ValueError, match="changed"):
        module.install(tmp_path, {"packages": ["linux"]}, config, {"/dev/sda": {"size": 64 * 1024**3}}, ("unused", "unused"))
    assert mutations == ["unmount"]
    assert not any("password" in name for name in config)


def test_custom_boot_only_disk_has_capacity_before_native_efi_insertion(monkeypatch, tmp_path):
    """Check boot-only disk capacity before native EFI insertion.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    module = load_installer(monkeypatch)
    sizes = []

    class Backend:
        def __init__(self, **_kwargs):
            """Accept backend construction without changing installation state.

            Args:
                **_kwargs: Additional keyword arguments supplied to the test double.
            """
            pass

        def configure(self, config):
            """Record configuration before returning simulated disk sizes.

            Args:
                config: Installer configuration passed to the fake backend.
            """
            self.install_config = config
            self._get_disk_sizes()
            sizes.append(self.disk_sizes)

        def _get_disk_sizes(self):
            self.disk_sizes = {"/dev/sdb": 128 * 1024**3}

        def _unsafe_install(self):
            pass

    monkeypatch.setitem(sys.modules, "installer", SimpleNamespace(Installer=Backend))
    module.install(
        tmp_path, {"packages": ["linux"]},
        {"disk": "/dev/sda", "partitions": [{"disk": "/dev/sdb", "mountpoint": "/", "filesystem": "ext4", "size": 0}]},
        {"/dev/sda": {"size": 64 * 1024**3}}, ("unused", "unused"),
    )
    assert sizes == [{"/dev/sda": 64 * 1024**3, "/dev/sdb": 128 * 1024**3}]


@pytest.mark.parametrize("failure", ["native", "docker"])
def test_native_failure_cannot_continue_or_use_network_fallback(monkeypatch, tmp_path, failure):
    """Stop failed native provisioning without a network fallback.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
        failure: Failure mode to exercise.
    """
    module = load_installer(monkeypatch)
    events = []

    class Backend:
        def __init__(self, **kwargs):
            """Accept backend construction without changing installation state.

            Args:
                **kwargs: Additional subprocess options received by the test double.
            """
            pass

        def configure(self, value):
            """Record the configuration passed to the fake backend.

            Args:
                value: Value supplied to the test case.
            """
            self.install_config = value

        def _unsafe_install(self):
            if failure == "native":
                self.exit_gracefully()
            else:
                self._run_tdnf_in_docker("never executed")
            events.append("incorrect success")

        def _unmount_all(self):
            events.append("unmount")

    monkeypatch.setitem(sys.modules, "installer", SimpleNamespace(Installer=Backend))
    with pytest.raises(RuntimeError):
        module.install(tmp_path, {"packages": ["linux"]}, {}, {}, ("unused", "unused"))
    assert events == ["unmount"]


def test_iso_identity_initialization_preserves_chosen_credentials(monkeypatch):
    """Preserve selected credentials during ISO identity initialization.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    spec = importlib.util.spec_from_file_location("iso_identity", Path("scripts/appliance/atlaso-initialize-machine-identity.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("ATLASO_STORAGE_PROFILE", "installation")
    values = []
    commands = []
    identities = []
    monkeypatch.setattr(module, "_password", lambda: pytest.fail("must preserve installer passwords"))
    monkeypatch.setattr(module, "_replace_environment", lambda value: values.append(value))
    monkeypatch.setattr(module, "_regenerate_host_identity", lambda: identities.append("fresh"))
    monkeypatch.setattr(module.subprocess, "run", lambda command, **kwargs: commands.append(command))
    module.initialize("baremetal")
    assert set(values[0]) == {"ATLASO_SECRET_KEY", "ATLASO_SECRETS_KEY"}
    assert identities == ["fresh"]
    assert commands == [["python3", "/opt/atlaso/scripts/installation/layout.py", "verify"]]


def test_bad_installation_receipt_blocks_identity_changes(monkeypatch):
    """Reject identity changes when installation receipt validation fails.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    spec = importlib.util.spec_from_file_location("iso_identity_invalid", Path("scripts/appliance/atlaso-initialize-machine-identity.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("ATLASO_STORAGE_PROFILE", "installation")

    def fail(command, **kwargs):
        """Simulate password-command failure before identity changes.

        Args:
            command: Subprocess argument vector received by the test double.
            **kwargs: Additional subprocess options received by the test double.
        """
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(module.subprocess, "run", fail)
    monkeypatch.setattr(module, "_replace_environment", lambda value: pytest.fail("unverified identity mutation"))
    with pytest.raises(subprocess.CalledProcessError):
        module.initialize("baremetal")


@pytest.mark.parametrize("identity, admitted, expected", [
    ({"signing_key_id": "atlaso-release-2026-01"}, "atlaso-release-2026-01", "production"),
    ({"signing_key_id": "atlaso-installation-development-public-test", "development": {"non_production": True}}, "atlaso-installation-development-public-test", "enabled"),
    ({"signing_key_id": "atlaso-release-2026-01", "development": {"non_production": True}}, "atlaso-installation-development-public-test", "refused"),
    ({"signing_key_id": "atlaso-installation-development-public-test", "development": {"non_production": 1}}, "atlaso-installation-development-public-test", "refused"),
    ({"signing_key_id": "atlaso-installation-development-public-test", "development": {"non_production": True}}, "atlaso-release-2026-01", "refused"),
])
def test_installed_serial_login_requires_development_trust(monkeypatch, tmp_path, identity, admitted, expected):
    """Keep standard serial login confined to admitted VMware development media.

    Args:
        monkeypatch: Controlled trust and subprocess replacements.
        tmp_path: Synthetic installed root, never a live system.
        identity: Signature-verified payload identity to exercise.
        admitted: Initrd trust selected after marker and VMware checks.
        expected: Production omission, development enablement, or refusal.
    """
    module = load_installer(monkeypatch)
    commands = []
    monkeypatch.setattr(module, "installer_key_id", lambda: admitted)
    monkeypatch.setattr(module.subprocess, "run", lambda command, **kwargs: commands.append(command))
    if expected == "refused":
        with pytest.raises(ValueError, match="admitted development"):
            module.configure_development_serial_login(tmp_path, identity)
    else:
        module.configure_development_serial_login(tmp_path, identity)
    assert commands == ([
        ["chroot", str(tmp_path), "/opt/atlaso/bin/atlaso-install-boot-branding",
         "/opt/atlaso/image/common/boot/grub/theme.txt", "/opt/atlaso/image/common/boot/grub/atlaso.png",
         "--development-serial-console"],
        ["chroot", str(tmp_path), "systemctl", "enable", "serial-getty@ttyS0.service"],
    ] if expected == "enabled" else [])


def _inspection_identity(module, software):
    """Build the verified media fields consumed by the retention helper.

    Args:
        module: Loaded installer adapter.
        software: Public source software directory for the installation fixture.
    """
    files = module.inventory(software)
    return {
        "signing_key_id": module.DEVELOPMENT_KEY_ID,
        "development": {
            "schema": 1,
            "software_source_commit": "a" * 40,
            "non_production": True,
        },
        "files": [
            {
                "path": "software/" + item["path"],
                "size": item["size"],
                "sha256": item["sha256"],
            }
            for item in files
        ],
    }


def test_development_inspection_inputs_survive_photon_tmp_unmount(monkeypatch, tmp_path):
    """Keep the exact authenticated public software tree for read-only VM checks.

    Args:
        monkeypatch: Controlled source helper module loader.
        tmp_path: Synthetic installed root and media directory.
    """
    module = load_installer(monkeypatch)
    media = tmp_path / "media"
    source = media / "software"
    source.mkdir(parents=True)
    (source / "release-manifest.json").write_bytes(b"signed public manifest")
    (source / "packages").mkdir()
    (source / "packages/atlaso.whl").write_bytes(b"public application wheel")
    target = tmp_path / "target"
    state = target / "var/lib/atlaso"
    state.mkdir(parents=True)
    tmpfs = target / "tmp/atlaso-software"
    shutil.copytree(source, tmpfs)

    module.retain_development_inspection_inputs(media, target, _inspection_identity(module, source))

    retained = state / "installation-inspection/software"
    shutil.rmtree(target / "tmp")
    assert (retained / "release-manifest.json").read_bytes() == b"signed public manifest"
    assert (retained / "packages/atlaso.whl").read_bytes() == b"public application wheel"
    assert module.inventory(retained) == module.inventory(source)


def test_production_install_does_not_create_inspection_copy(monkeypatch, tmp_path):
    """Leave production disk state unchanged for the development-only helper.

    Args:
        monkeypatch: Controlled source helper module loader.
        tmp_path: Synthetic target root used to verify no mutation.
    """
    module = load_installer(monkeypatch)
    target = tmp_path / "target"
    identity = {"signing_key_id": "atlaso-release-2026-01"}

    module.retain_development_inspection_inputs(tmp_path / "missing-media", target, identity)

    assert not target.exists()


@pytest.mark.parametrize("corruption", ["marker", "digest"])
def test_retained_inspection_refuses_changed_authority_or_software(monkeypatch, tmp_path, corruption):
    """Refuse invalid development authority or changed bytes before target writes.

    Args:
        monkeypatch: Isolated native installer import fixture.
        tmp_path: Task-owned media and destination fixture.
        corruption: Independently changed marker or authenticated content digest.
    """
    module = load_installer(monkeypatch)
    media = tmp_path / "media"
    source = media / "software"
    source.mkdir(parents=True)
    manifest = source / "release-manifest.json"
    manifest.write_bytes(b"authenticated public software")
    identity = _inspection_identity(module, source)
    if corruption == "marker":
        identity["development"]["non_production"] = False
    else:
        manifest.write_bytes(b"changed public software")
    target = tmp_path / "must-remain-absent"
    with pytest.raises(ValueError):
        module.retain_development_inspection_inputs(media, target, identity)
    assert not target.exists()


def test_existing_inspection_destination_is_preserved(monkeypatch, tmp_path):
    """Refuse an existing inspection tree without replacing its files.

    Args:
        monkeypatch: Controlled source helper module loader.
        tmp_path: Synthetic media and target roots.
    """
    module = load_installer(monkeypatch)
    media = tmp_path / "media"
    source = media / "software"
    source.mkdir(parents=True)
    (source / "release-manifest.json").write_bytes(b"authenticated public manifest")
    state = tmp_path / "target/var/lib/atlaso"
    destination = state / "installation-inspection/software"
    destination.mkdir(parents=True)
    (destination / "operator-file").write_bytes(b"preserve")

    with pytest.raises(FileExistsError, match="already exist"):
        module.retain_development_inspection_inputs(media, state.parents[2], _inspection_identity(module, source))

    assert (destination / "operator-file").read_bytes() == b"preserve"


@pytest.mark.parametrize("failure", [None, "missing-initrd", "empty-initrd", "missing-selection", "duplicate-selection", "escaping-selection"])
def test_installed_boot_artifacts_require_native_kernel_and_initrd(monkeypatch, tmp_path, failure):
    """Refuse incomplete native boot setup before credentials or completion.

    Args:
        monkeypatch: Controlled native metadata command replacement.
        tmp_path: Synthetic installed filesystem, never a block device.
        failure: Missing, empty, ambiguous, or unsafe native artifact to exercise.
    """
    module = load_installer(monkeypatch)
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / "vmlinuz-test").write_bytes(b"native kernel")
    (boot / "initrd.img-test").write_bytes(b"native initrd")
    metadata = "photon_linux=vmlinuz-test\nphoton_initrd=initrd.img-test\n"
    if failure == "missing-initrd":
        (boot / "initrd.img-test").unlink()
    elif failure == "empty-initrd":
        (boot / "initrd.img-test").write_bytes(b"")
    elif failure == "missing-selection":
        metadata = "photon_linux=vmlinuz-test\n"
    elif failure == "duplicate-selection":
        metadata += "photon_initrd=initrd.img-test\n"
    elif failure == "escaping-selection":
        metadata = "photon_linux=vmlinuz-test\nphoton_initrd=../outside\n"

    def native_metadata(command, **kwargs):
        """Emulate only the installed GRUB environment read.

        Args:
            command: Native metadata command argument vector.
            **kwargs: Bounded subprocess settings under test.
        """
        assert command == ["chroot", str(tmp_path), "/usr/bin/grub2-editenv", "/boot/photon.cfg", "list"]
        assert kwargs == {"text": True, "stderr": subprocess.DEVNULL, "timeout": 30}
        return metadata

    monkeypatch.setattr(module.subprocess, "check_output", native_metadata)
    if failure:
        with pytest.raises(RuntimeError, match="installed Photon"):
            module.verify_installed_boot_artifacts(tmp_path)
    else:
        module.verify_installed_boot_artifacts(tmp_path)


def test_missing_native_initrd_blocks_chosen_credentials_and_completion(monkeypatch, tmp_path):
    """An incomplete native boot environment must fail before account updates.

    Args:
        monkeypatch: Controlled native backend and credential-command replacements.
        tmp_path: Synthetic installed system root.
    """
    target = tmp_path / "target"
    atlaso = target / "etc/atlaso"
    atlaso.mkdir(parents=True)
    env_path = atlaso / "atlaso.env"
    original = 'ATLASO_BOOTSTRAP_ADMIN_PASSWORD="generated-placeholder"\n'
    env_path.write_text(original, encoding="utf-8")
    events = []
    module = _install_fake_native_backend(monkeypatch, target, events)
    (target / "boot/initrd.img-test").unlink()
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: pytest.fail("credentials must not be applied"))
    with pytest.raises(RuntimeError, match="kernel or initrd image is missing"):
        module.install(tmp_path / "media", {"packages": ["linux"]}, {"partitions": []}, {}, ("fixture admin", "fixture root"))
    assert env_path.read_text(encoding="utf-8") == original
    assert not (atlaso / "installation-profile").exists()
    assert events == ["post-install-root-default", "grub", "fstab", "unmount"]

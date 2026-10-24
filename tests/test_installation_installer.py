"""Exercise installer consent and failure paths without touching a block device."""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def load_installer(monkeypatch):
    """Load the native-console adapter on Windows with a noninteractive console.

Args:
    monkeypatch: Pytest fixture for replacing controlled dependencies.
"""
    monkeypatch.setitem(sys.modules, "curses", SimpleNamespace())
    spec = importlib.util.spec_from_file_location("installation_adapter", Path("scripts/installation/installer.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    module = load_installer(monkeypatch)
    calls = []

    class Reader:
        def __init__(self, *args):
            """
            Args:
                *args: Args used by this test case.
            """
            calls.append(args)
            args[13]["value"] = "synthetic operator input"

        def get_user_string(self):
            return SimpleNamespace(success=True)

    monkeypatch.setitem(sys.modules, "windowstringreader", SimpleNamespace(WindowStringReader=Reader))
    assert module.prompt(25, 80, "Title", "First line\nSecond line", secret=True) == "synthetic operator input"
    assert calls[0][5] is None
    assert calls[0][6] == "*"
    assert calls[0][12] > 1


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


def test_environment_value_round_trips_posix_shell_metacharacters(monkeypatch, tmp_path):
    """
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

    class Backend:
        def __init__(self, **_kwargs):
            """
            Args:
                **_kwargs: Additional keyword arguments supplied to the test double.
            """
            self.photon_root = str(target)

        def configure(self, config):
            """
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
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    target = tmp_path / "target"
    atlaso = target / "etc/atlaso"
    atlaso.mkdir(parents=True)
    env_path = atlaso / "atlaso.env"
    env_path.write_text('ATLASO_BOOTSTRAP_ADMIN_PASSWORD="generated-placeholder"\n', encoding="utf-8")
    events = []
    module = _install_fake_native_backend(monkeypatch, target, events)
    chpasswd = []

    def run(command, *, input, **kwargs):
        """
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
        "ATLASO_BOOTSTRAP_ADMIN_PASSWORD="
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
    """
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
    """
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
    """
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
            """
            Args:
                *_args: Additional positional arguments supplied to the test double.
            """
            pass

    class SelectDisk:
        def __init__(self, _height, _width, config):
            """
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

    def prompt(_height, _width, title, _message, *, secret=False, validator=None):
        """
        Args:
            _height: Console height supplied to the fake UI callback.
            _width: Console width supplied to the fake UI callback.
            title: Prompt title shown by the console adapter.
            _message: Prompt text passed to the fake UI callback.
            secret: Whether the fake prompt should conceal its input.
            validator: Validation callback passed to the prompt.
        """
        calls.append((title, secret))
        if title == "Review planned partitions":
            return "NEXT"
        if title == "Review Atlaso installation disk":
            return "CANCEL"
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
        with pytest.raises(ValueError, match=rf"selected /dev/nvme0n1 has {size_gib * 1024**3} bytes$"):
            module.configure_console(Screen(), initial)
        assert calls == ["revalidate"]
    else:
        with pytest.raises(module.Cancelled):
            module.configure_console(Screen(), initial)
        assert calls == ["revalidate", ("Review planned partitions", False), ("Review Atlaso installation disk", False)]


def test_custom_multi_disk_adapter_displays_selected_disk_and_maps_each_partition(monkeypatch):
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    module = load_installer(monkeypatch)
    interactions = []

    class Screen:
        def getmaxyx(self):
            return 30, 100

        def bkgd(self, *_args):
            """
            Args:
                *_args: Additional positional arguments supplied to the test double.
            """
            pass

    class Device:
        def __init__(self, _model, path, _size):
            """
            Args:
                _model: Model string supplied to the fake disk record.
                path: Path to the fixture or file being tested.
                _size: Display size supplied to the fake disk record.
            """
            self.path = path

    class SelectDisk:
        selected = iter(("/dev/nvme0n1", "/dev/nvme0n1", "/dev/nvme0n1", "/dev/sdb"))

        def __init__(self, _height, _width, selection):
            """
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
            """
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
            """
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
    def prompt(_height, _width, title, message, *, secret=False, validator=None):
        """
        Args:
            _height: Console height supplied to the fake UI callback.
            _width: Console width supplied to the fake UI callback.
            title: Prompt title shown by the console adapter.
            message: Expected validation message or prompt text.
            secret: Whether the fake prompt should conceal its input.
            validator: Validation callback passed to the prompt.
        """
        if title == "Review planned partitions":
            return "NEXT"
        if title == "Review Atlaso installation disk":
            return f"ERASE {message.split(':', 1)[0]}"
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

    config, consent, _credentials = module.configure_console(Screen(), initial)

    assert interactions == [[
        {"mountpoint": "/", "filesystem": "ext4", "size": 0, "disk": "/dev/nvme0n1"},
        {"mountpoint": "/var/lib/atlaso", "filesystem": "ext4", "size": 4096, "disk": "/dev/nvme0n1"},
        {"mountpoint": "/mnt/atlaso-vcf-backups", "filesystem": "xfs", "size": 8192, "disk": "/dev/sdb"},
    ]]
    assert consent == initial
    assert config["partitions"] == interactions[0]
    pane = custompartition_module.PartitionPane()
    pane.partition()
    assert pane.lines[1].startswith("/dev/nvme0n1")
    assert pane.lines[2].startswith("/dev/nvme0n1")
    assert pane.lines[3].startswith("/dev/sdb")


def test_changed_disk_prevents_native_partition_call(monkeypatch, tmp_path):
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    module = load_installer(monkeypatch)
    mutations = []

    class Backend:
        def __init__(self, **kwargs):
            """
            Args:
                **kwargs: Additional subprocess options received by the test double.
            """
            pass

        def configure(self, value):
            """
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
    config = {"disk": "/dev/sda", "arch": "x86_64", "bootmode": "efi", "partitions": [{"mountpoint": "/", "filesystem": "ext4", "size": 0}]}
    with pytest.raises(ValueError, match="changed"):
        module.install(tmp_path, {"packages": ["linux"]}, config, {"/dev/sda": {"size": 64 * 1024**3}}, ("unused", "unused"))
    assert mutations == ["unmount"]
    assert not any("password" in name for name in config)


def test_custom_boot_only_disk_has_capacity_before_native_efi_insertion(monkeypatch, tmp_path):
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
    """
    module = load_installer(monkeypatch)
    sizes = []

    class Backend:
        def __init__(self, **_kwargs):
            """
            Args:
                **_kwargs: Additional keyword arguments supplied to the test double.
            """
            pass

        def configure(self, config):
            """
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
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Temporary directory for this test's filesystem fixtures.
        failure: Failure mode to exercise.
    """
    module = load_installer(monkeypatch)
    events = []

    class Backend:
        def __init__(self, **kwargs):
            """
            Args:
                **kwargs: Additional subprocess options received by the test double.
            """
            pass

        def configure(self, value):
            """
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
    """
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
    """
    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    spec = importlib.util.spec_from_file_location("iso_identity_invalid", Path("scripts/appliance/atlaso-initialize-machine-identity.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("ATLASO_STORAGE_PROFILE", "installation")

    def fail(command, **kwargs):
        """
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
    assert commands == ([["chroot", str(tmp_path), "systemctl", "enable", "serial-getty@ttyS0.service"]] if expected == "enabled" else [])

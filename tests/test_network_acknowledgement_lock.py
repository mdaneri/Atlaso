"""Exercise bounded Network Apply and acknowledgement lock admission."""

from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import pytest

from tests.test_appliance_helper import load_helper_module


@pytest.mark.parametrize("release_after", [0, 2, None])
def test_acknowledgement_waits_only_until_lock_or_deadline(monkeypatch, release_after):
    """Wait for actual acquisition, refusing a lock held past the bounded deadline.

    Args:
        monkeypatch: Replace only the OS lock and clock, including on Windows.
        release_after: Number of busy attempts before release, or never release.
    """
    helper = load_helper_module()
    now = [0.0]
    attempts = []

    def flock(descriptor, operation):
        """Model another owner without granting the caller its critical section.

        Args:
            descriptor: Already admitted native lock-file descriptor.
            operation: Exclusive nonblocking acquisition flags.
        """
        assert (descriptor, operation) == (17, 3)
        attempts.append(now[0])
        if release_after is None or len(attempts) <= release_after:
            raise BlockingIOError

    monkeypatch.setattr(helper, "fcntl", SimpleNamespace(flock=flock, LOCK_EX=1, LOCK_NB=2))
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helper.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    if release_after is None:
        with pytest.raises(ValueError, match="still owned by a live helper"):
            helper._acquire_network_transaction_lock(17, wait_seconds=0.2)
        assert now[0] == pytest.approx(0.2)
    else:
        helper._acquire_network_transaction_lock(17, wait_seconds=0.2)
        assert len(attempts) == release_after + 1
        assert now[0] < 0.2


@pytest.mark.parametrize("action,wait_seconds", [("apply", 30), ("recover", 0), ("acknowledge", 10)])
def test_network_mutations_execute_only_after_lock_admission(monkeypatch, action, wait_seconds):
    """Allow bounded Apply and acknowledgement waits while keeping recovery fail-fast.

    Args:
        monkeypatch: Observe the lock boundary without invoking any native mutation.
        action: Real public helper operation.
        wait_seconds: Exact permitted lock wait for that operation.
    """
    helper = load_helper_module()
    events = []

    @contextmanager
    def lock(*, wait_seconds=0):
        """Expose admission before and release after the operation.

        Args:
            wait_seconds: Bounded acquisition policy selected by the dispatcher.
        """
        events.append(("acquired", wait_seconds))
        yield
        events.append(("released", wait_seconds))

    def handle(actual_action, args, **_kwargs):
        """Verify exact task arguments are still inside the admitted boundary.

        Args:
            actual_action: Operation passed unchanged to the locked handler.
            args: Exact caller-owned task identifier.
            **_kwargs: Existing protected handoff options.
        """
        assert events == [("acquired", wait_seconds)]
        assert (actual_action, args) == (action, ["job-owned"])
        events.append(("handled", actual_action))
        return 0

    monkeypatch.setattr(helper, "_network_transaction_lock", lock)
    monkeypatch.setattr(helper, "_handle_network_locked", handle)
    assert helper._handle_network(action, ["job-owned"]) == 0
    assert events == [("acquired", wait_seconds), ("handled", action), ("released", wait_seconds)]


@pytest.mark.parametrize("paired", [False, True])
@pytest.mark.parametrize("observer_releases", [False, True])
def test_apply_waits_for_observer_before_mutation(monkeypatch, paired, observer_releases):
    """Exercise ordinary and paired Apply while the observer still owns the native lock.

    Args:
        monkeypatch: Replace the OS lock, clock, and mutation, retaining real helper admission.
        paired: Enter Network through paired Traffic Publishing instead of direct dispatch.
        observer_releases: Release after slow native collection or remain busy past the deadline.
    """
    helper = load_helper_module()
    now = [0.0]
    mutations = []

    def flock(_descriptor, _operation):
        """Model a slow observer or a still-active owner at expiry.

        Args:
            _descriptor: Synthetic admitted lock descriptor.
            _operation: Nonblocking native exclusive-lock request.
        """
        if not observer_releases or now[0] < 13:
            raise BlockingIOError

    @contextmanager
    def lock(*, wait_seconds=0):
        """Use the real timed admission loop without touching the host lock file.

        Args:
            wait_seconds: Acquisition limit chosen by the real dispatcher.
        """
        helper._acquire_network_transaction_lock(17, wait_seconds=wait_seconds)
        yield

    def handle(action, args, **_kwargs):
        """Record a mutation only after lock admission.

        Args:
            action: Actual Network operation selected by the dispatcher.
            args: Original staged configuration path.
            **_kwargs: Existing handoff options.
        """
        mutations.append((action, args, now[0]))
        return 0

    monkeypatch.setattr(helper, "fcntl", SimpleNamespace(flock=flock, LOCK_EX=1, LOCK_NB=2))
    monkeypatch.setattr(helper.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(helper.time, "sleep", lambda delay: now.__setitem__(0, now[0] + delay))
    monkeypatch.setattr(helper, "_network_transaction_lock", lock)
    monkeypatch.setattr(helper, "_handle_network_locked", handle)
    monkeypatch.setattr(helper, "_publishing_network_stage", lambda _content: nullcontext("owned.conf"))

    if not paired:
        assert helper._handle_network("apply", ["owned.conf"]) == (0 if observer_releases else 2)
    elif observer_releases:
        helper._publishing_apply_network("synthetic staged Network configuration")
    else:
        with pytest.raises(ValueError, match="Network apply failed during paired publication"):
            helper._publishing_apply_network("synthetic staged Network configuration")

    if observer_releases:
        assert mutations == [("apply", ["owned.conf"], pytest.approx(13, abs=0.05))]
    else:
        assert mutations == []
        assert now[0] == pytest.approx(30)


def test_lock_errors_are_not_retried_as_contention(monkeypatch):
    """Propagate an unsafe/invalid descriptor rather than treating it as busy.

    Args:
        monkeypatch: Inject an OS error unrelated to another live owner.
    """
    helper = load_helper_module()

    def denied(*_args):
        """Represent a failed lock operation without retry authority.

        Args:
            *_args: Ignored lock descriptor and operation flags.
        """
        raise PermissionError("lock descriptor refused")

    monkeypatch.setattr(helper, "fcntl", SimpleNamespace(flock=denied, LOCK_EX=1, LOCK_NB=2))
    with pytest.raises(PermissionError, match="descriptor refused"):
        helper._acquire_network_transaction_lock(17, wait_seconds=10)


def test_acknowledgement_waits_for_independent_native_owner(tmp_path, monkeypatch):
    """Acquire the real POSIX lock only after a separate process releases it.

    Args:
        tmp_path: Originally owned pytest output directory.
        monkeypatch: Preserve native file checks while mapping test ownership to root.
    """
    import subprocess
    import sys
    import threading

    helper = load_helper_module()
    if helper.fcntl is None:
        pytest.skip("Independent POSIX flock is verified by canonical Linux CI")
    root = tmp_path / "transaction"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(helper, "NETWORK_TRANSACTION_DIR", root)
    original_fstat = helper.os.fstat

    def root_metadata(descriptor):
        """Substitute UID without weakening file type, mode or link-count checks.

        Args:
            descriptor: Native lock-file or directory descriptor.
        """
        value = original_fstat(descriptor)
        return SimpleNamespace(st_uid=0, st_mode=value.st_mode, st_nlink=value.st_nlink)

    monkeypatch.setattr(helper.os, "fstat", root_metadata)
    script = (
        "import fcntl,os,sys;"
        "f=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);"
        "fcntl.flock(f,fcntl.LOCK_EX);print('locked',flush=True);"
        "sys.stdin.readline();os.close(f)"
    )
    with subprocess.Popen([sys.executable, "-c", script, str(root / ".lock")],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as owner:
        assert owner.stdout.readline().strip() == "locked"

        def release():
            """Release the independent owner without changing its lock file."""
            owner.stdin.write("release\n")
            owner.stdin.flush()

        timer = threading.Timer(0.1, release)
        timer.start()
        try:
            assert helper._handle_network("acknowledge", ["job-owned"]) == 0
        finally:
            timer.join(timeout=3)
            if owner.poll() is None:
                owner.stdin.close()
            owner.wait(timeout=3)
    assert not (root / "state.json").exists()

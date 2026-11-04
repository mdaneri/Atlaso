"""Keep changed DHCP addresses from blocking the backend needed for publication."""

import configparser
import runpy
import shlex
import subprocess

import pytest


def completed_bootstrap(monkeypatch, *, proof=True, contract=True):
    """Load completed bootstrap with the native stale-listener failure.

    Args:
        monkeypatch: Replace native operations without changing real services.
        proof: Whether encrypted development-root proof succeeds.
        contract: Whether the completed nginx include contract is intact.
    """
    main = runpy.run_path("scripts/appliance/atlaso-bootstrap-https")["main"]
    namespace = main.__globals__
    commands = []
    monkeypatch.setitem(namespace, "first_boot_https_artifacts_are_complete", lambda: True)
    monkeypatch.setitem(namespace, "first_boot_https_contract_is_complete", lambda: contract)
    monkeypatch.setitem(namespace, "ensure_nginx_main_config_includes_atlaso", lambda: None)
    monkeypatch.setattr(namespace["shutil"], "which", lambda _: "/usr/sbin/nginx")
    monkeypatch.setitem(namespace, "publish_first_boot_stage", lambda _: None)
    monkeypatch.setitem(namespace, "publish_development_root_ca_import_proof", lambda: proof)

    def unavailable_listener(command):
        """Model the actual completed peer's missing former DHCP address.

        Args:
            command: Native validation command under test.
        """
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 1, "", "bind() to 192.168.167.181:80 failed (99: Cannot assign requested address)",
        )

    monkeypatch.setitem(namespace, "run", unavailable_listener)
    return main, commands


def test_systemd_completed_boot_can_start_backend_after_dhcp_address_disappears(monkeypatch):
    """Exercise the installed unit's actual admission mode, with no nginx bypass.

    Args:
        monkeypatch: Isolate completed state and the unavailable native address.
    """
    unit = configparser.ConfigParser(interpolation=None, strict=False)
    unit.read("image/common/systemd/atlaso-bootstrap-https.service")
    arguments = shlex.split(unit["Service"]["ExecStart"])
    main, commands = completed_bootstrap(monkeypatch)
    boot_admission = "--completed-boot-admission" in arguments
    result = main(completed_boot_admission=True) if boot_admission else main()
    assert result == 0, "A stale nginx bind must not block the observer's required backend"
    assert boot_admission
    assert commands == [], "nginx.service and the atomic publisher retain native listener validation"


def test_direct_completed_bootstrap_keeps_native_validation(monkeypatch):
    """A direct invocation must retain its existing native readiness result.

    Args:
        monkeypatch: Replace completed state and native validation.
    """
    main, commands = completed_bootstrap(monkeypatch)
    assert main() == 1
    assert commands == [["/usr/sbin/nginx", "-t"]]


@pytest.mark.parametrize("failure", ["contract", "encrypted-root-proof", "missing-nginx"])
def test_completed_boot_admission_keeps_artifact_and_trust_refusals(monkeypatch, failure):
    """Backend admission cannot replace completed artifacts or root proof.

    Args:
        monkeypatch: Replace native and completed-state dependencies.
        failure: One prerequisite that remains mandatory during boot.
    """
    main, _ = completed_bootstrap(
        monkeypatch, proof=failure != "encrypted-root-proof", contract=failure != "contract",
    )
    if failure == "missing-nginx":
        monkeypatch.setattr(main.__globals__["shutil"], "which", lambda _: None)
    assert main(completed_boot_admission=True) == 2


def test_boot_admission_does_not_skip_initial_bootstrap(monkeypatch):
    """An incomplete appliance still enters the original full bootstrap path.

    Args:
        monkeypatch: Stop at the first full-bootstrap preparation operation.
    """
    main, _ = completed_bootstrap(monkeypatch)
    monkeypatch.setitem(main.__globals__, "first_boot_https_artifacts_are_complete", lambda: False)

    def full_bootstrap_required():
        """Stop before any real initialization, proving the full path is reached."""
        raise RuntimeError("full bootstrap is required")

    monkeypatch.setitem(main.__globals__, "_ui_functions", full_bootstrap_required)
    with pytest.raises(RuntimeError, match="full bootstrap is required"):
        main(completed_boot_admission=True)


def test_completed_network_recovery_keeps_its_original_path(monkeypatch):
    """A bound Network recovery takes precedence over completed boot admission.

    Args:
        monkeypatch: Replace the existing guarded recovery entry point.
    """
    main, commands = completed_bootstrap(monkeypatch)
    jobs = []
    monkeypatch.setitem(main.__globals__, "refresh_completed_management_certificate", lambda job: jobs.append(job) or 2)
    assert main("job_existing_network", completed_boot_admission=True) == 2
    assert jobs == ["job_existing_network"]
    assert commands == []

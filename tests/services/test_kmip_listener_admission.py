"""Test applied KMIP listener address ownership admission."""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from atlaso.app.adapters.system import AdapterResult
from atlaso.app.services import kmip_listener_admission as admission
from atlaso.app.services.networking import HostPhysicalInterface

NETWORK_PREVIEW = """[physical_interfaces]
interface=eth1
  mac=00:11:22:33:44:55
  role=access
  mode=access
  ipv4_method=static
  ip_cidr=192.168.1.254/24
  ipv6_enabled=true
  ipv6_cidr=2001:db8::254/64
  admin_state=up

interface=eth2
  mac=00:11:22:33:44:66
  role=management
  mode=access
  ipv4_method=static
  ip_cidr=192.168.1.10/24
  ipv6_enabled=false
  admin_state=up

[vlan_interfaces]
"""


def _physical(name: str = "eth1", mac: str = "00:11:22:33:44:55", *, ipv4="192.168.1.254/24",
              ipv6="2001:db8::254/64", dhcp=None, up=True) -> HostPhysicalInterface:
    """Build synthetic native address evidence for one interface.

    Args:
        name: Synthetic native interface name.
        mac: Synthetic hardware address pinned by applied network state.
        ipv4: Current IPv4 address and prefix, if any.
        ipv6: Current IPv6 address and prefix, if any.
        dhcp: IPv4 address carrying explicit native dynamic-source evidence.
        up: Whether native evidence reports administrative and operational up state.
    """
    return HostPhysicalInterface(
        name=name,
        mac_address=mac,
        driver=None,
        speed=None,
        host_ip_cidr=ipv4,
        host_mtu=1500,
        host_admin_state="up" if up else "down",
        oper_state="up" if up else "down",
        host_ipv6_cidr=ipv6,
        host_dhcp_ip_cidr=dhcp,
        host_ip_cidrs=(ipv4,) if ipv4 else (),
        host_ipv6_cidrs=(ipv6,) if ipv6 else (),
    )


class _Db:
    """Supply only the successful baseline setting consumed by the service."""

    def __init__(self, baselines: dict | None) -> None:
        """Wrap synthetic successful-Apply baselines as a Setting row.

        Args:
            baselines: Synthetic baseline data, or ``None`` to represent absence.
        """
        self.setting = SimpleNamespace(value=json.dumps(baselines)) if baselines is not None else None

    def execute(self, _statement):
        """Return the synthetic Setting row selected by the service.

        Args:
            _statement: SQLAlchemy query, unused by this narrow test double.
        """
        return SimpleNamespace(scalar_one_or_none=lambda: self.setting)


def _baselines(*, addresses=("192.168.1.254",), sources=None, port=5696,
               network=NETWORK_PREVIEW) -> dict:
    """Return synthetic successful Apply evidence with exact listener owners.

    Args:
        addresses: IP addresses in the captured applied KMIP listener configuration.
        sources: Captured address-to-interface map, defaulting to ``eth1`` ownership.
        port: Port in the captured applied KMIP listener configuration.
        network: Captured applied Network interface configuration.
    """
    return {
        "kms": {
            "config_preview": json.dumps({
                "enabled": True,
                "listen": {"addresses": list(addresses), "port": port},
            }),
            "applied_listener_sources": sources if sources is not None else {
                value: "eth1" for value in addresses
            },
        },
        "network": {"config_preview": network},
    }


def _observe(monkeypatch, hosts=None):
    """Replace physical interface discovery with chosen synthetic observations.

    Args:
        monkeypatch: Pytest fixture for replacing the native observation function.
        hosts: Synthetic observed interfaces, or the default ``eth1`` observation.
    """
    monkeypatch.setattr(admission, "discover_host_physical_interfaces", lambda **_kwargs: list(hosts or [_physical()]))


@pytest.fixture(autouse=True)
def synthetic_deployed_listener(monkeypatch):
    """Provide synthetic deployed listener evidence; no native deployment is implied.

    Args:
        monkeypatch: Pytest fixture for replacing the privileged helper result.
    """
    monkeypatch.setattr(admission.SystemAdapter, "kms_listener_status", lambda *_args, **_kwargs: AdapterResult(command=[], dry_run=False, stdout=json.dumps({
        "enabled": True, "listen": {"addresses": ["192.168.1.254"], "port": 5696},
    })))


def test_admits_exact_applied_ip_on_fresh_pinned_up_interface(monkeypatch):
    """An applied address and matching current MAC/address observation prove IP ownership.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic native observations.
    """
    _observe(monkeypatch)

    assert admission.applied_kmip_listener_addresses(_Db(_baselines()), port=5696) == frozenset({"192.168.1.254"})


def test_admits_applied_static_ipv6_listener(monkeypatch):
    """IPv6 admission retains the exact applied address and native observation.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic native observations.
    """
    _observe(monkeypatch)
    monkeypatch.setattr(admission.SystemAdapter, "kms_listener_status", lambda *_args, **_kwargs: AdapterResult(command=[], dry_run=False, stdout=json.dumps({
        "enabled": True, "listen": {"addresses": ["2001:db8::254"], "port": 5696},
    })))

    assert admission.applied_kmip_listener_addresses(
        _Db(_baselines(addresses=("2001:db8::254",))), port=5696,
    ) == frozenset({"2001:db8::254"})


@pytest.mark.parametrize("baselines,port,hosts", [
    (None, 5696, [_physical()]),
    (_baselines(port=5695), 5696, [_physical()]),
    (_baselines(sources={}), 5696, [_physical()]),
    (_baselines(sources={"192.168.1.254": "eth9"}), 5696, [_physical()]),
    (_baselines(), 5696, [_physical(mac="00:11:22:33:44:99")]),
    (_baselines(), 5696, [_physical(up=False)]),
    (_baselines(sources={"192.168.1.254": "eth2"}), 5696, [_physical("eth2", "00:11:22:33:44:66")]),
])
def test_rejects_missing_stale_unapplied_or_unrelated_ownership(monkeypatch, baselines, port, hosts):
    """Labels, another interface, old addresses, or missing source metadata prove nothing.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic native observations.
        baselines: Synthetic captured Apply evidence for this rejection case.
        port: Configured KMIP port supplied to the address-admission check.
        hosts: Synthetic native observations for this rejection case.
    """
    _observe(monkeypatch, hosts)

    assert admission.applied_kmip_listener_addresses(_Db(baselines), port=port) == frozenset()


def test_rejects_address_without_successful_network_baseline(monkeypatch):
    """A successful KMS snapshot cannot admit an address without applied Network ownership.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic native observations.
    """
    _observe(monkeypatch)
    baseline = _baselines()
    baseline.pop("network")

    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset()


@pytest.mark.parametrize("legacy_static_cidr", [False, True])
def test_dhcp_admission_requires_native_dynamic_address(monkeypatch, legacy_static_cidr):
    """A lingering static address cannot impersonate the successful DHCP listener lease.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic native observations.
        legacy_static_cidr: Whether the applied Network snapshot retains a previous static CIDR.
    """
    preview = NETWORK_PREVIEW.replace("ipv4_method=static", "ipv4_method=dhcp")
    if not legacy_static_cidr:
        preview = preview.replace("ip_cidr=192.168.1.254/24", "ip_cidr=")
    baseline = _baselines(network=preview)
    _observe(monkeypatch, [_physical(ipv4="192.168.1.254/24", dhcp=None)])

    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset()

    _observe(monkeypatch, [_physical(ipv4="192.168.1.254/24", dhcp="192.168.1.254/24")])
    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset({"192.168.1.254"})


def test_automatic_ipv6_requires_current_dynamic_source_evidence(monkeypatch):
    """A lingering static IPv6 address cannot substitute for the applied automatic address.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic native observations.
    """
    address = "2001:db8::254"
    baseline = _baselines(addresses=(address,), network=NETWORK_PREVIEW.replace("ipv6_cidr=2001:db8::254/64", "ipv6_cidr="))
    monkeypatch.setattr(admission.SystemAdapter, "kms_listener_status", lambda *_args, **_kwargs: AdapterResult(
        command=[], dry_run=False, stdout=json.dumps({"enabled": True, "listen": {"addresses": [address], "port": 5696}}),
    ))
    _observe(monkeypatch)
    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset()
    _observe(monkeypatch, [replace(_physical(), host_dynamic_ipv6_cidrs=("2001:db8::254/64",))])
    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset({address})


@pytest.mark.parametrize("dry_run,returncode", [(True, 0), (False, 2)])
def test_missing_real_deployed_listener_proof_fails_closed(monkeypatch, dry_run, returncode):
    """Dry-run or unavailable helper evidence never authorizes an IP.

    Args:
        monkeypatch: Pytest fixture for replacing the privileged helper result.
        dry_run: Whether the synthetic helper reports that it only ran a preview.
        returncode: Synthetic privileged-helper exit code.
    """
    _observe(monkeypatch)
    monkeypatch.setattr(admission.SystemAdapter, "kms_listener_status", lambda *_args, **_kwargs: AdapterResult(
        command=[], dry_run=dry_run, returncode=returncode, stdout='{"enabled":true}',
    ))
    assert admission.applied_kmip_listener_addresses(_Db(_baselines()), port=5696) == frozenset()


def test_vlan_admission_delegates_to_exact_native_vlan_verification(monkeypatch):
    """An applied VLAN listener requires parent, tag, link, and address checks.

    Args:
        monkeypatch: Pytest fixture for injecting synthetic interface and VLAN observations.
    """
    address = "192.168.1.254"
    preview = NETWORK_PREVIEW + """vlan=eth1.50
  parent=eth1
  parent_mac=00:11:22:33:44:55
  vlan_id=50
  role=access
  ip_cidr=192.168.1.254/24
  ipv6_cidr=
"""
    baseline = _baselines(addresses=(address,), sources={address: "eth1.50"}, network=preview)
    _observe(monkeypatch)
    calls = []
    monkeypatch.setattr(admission, "verify_native_management_vlans", lambda paths, **kwargs: calls.append(paths) or True)

    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset({address})
    assert calls[0][0]["name"] == "eth1.50"
    assert calls[0][0]["parent"] == "eth1"

    monkeypatch.setattr(admission, "verify_native_management_vlans", lambda *_args, **_kwargs: False)
    assert admission.applied_kmip_listener_addresses(_Db(baseline), port=5696) == frozenset()


def test_unavailable_native_observation_fails_closed(monkeypatch):
    """An observation failure does not fall back to saved desired or cached state.

    Args:
        monkeypatch: Pytest fixture for simulating unavailable native observation.
    """
    monkeypatch.setattr(admission, "discover_host_physical_interfaces", lambda **_kwargs: (_ for _ in ()).throw(OSError()))

    assert admission.applied_kmip_listener_addresses(_Db(_baselines()), port=5696) == frozenset()


@pytest.mark.parametrize("runtime", ["{}", "null", "invalid", json.dumps({
    "enabled": False, "listen": {"addresses": ["192.168.1.254"], "port": 5696},
}), json.dumps({"enabled": True, "listen": {"addresses": ["192.168.1.253"], "port": 5696}})])
def test_missing_disabled_or_different_deployed_listener_rejects_ip(monkeypatch, runtime):
    """A dry-run or stale baseline cannot stand in for deployed configuration.

    Args:
        monkeypatch: Pytest fixture for replacing privileged listener evidence.
        runtime: Synthetic deployed listener response to validate or reject.
    """
    _observe(monkeypatch)
    monkeypatch.setattr(admission.SystemAdapter, "kms_listener_status", lambda *_args, **_kwargs: AdapterResult(command=[], dry_run=False, stdout=runtime))
    assert admission.applied_kmip_listener_addresses(_Db(_baselines()), port=5696) == frozenset()

"""Cover dynamic service listeners in Network handoffs without DNS ownership."""

import json
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select

from tests.routers.ui.helpers import login
from tests.routers.ui.test_generated_dns_apply import _prepare_service_address_baseline


def _prepare_service_baselines(db, ui, active_services, *, dns_enabled, dynamic_ipv4=False, dynamic_ipv6=True):
    """Capture applied listener configs, then build candidate Network intent.

    Args:
        db: Active seeded test database session.
        ui: Appliance UI module that owns Apply unit and baseline helpers.
        active_services: Listener service IDs to leave enabled in the applied snapshots.
        dns_enabled: Whether desired DNS remains enabled after baseline capture.
        dynamic_ipv4: Whether candidate Network uses DHCPv4 on the listener interface.
        dynamic_ipv6: Whether candidate Network uses SLAAC on the listener interface.

    Returns:
        The candidate access interface and Apply units keyed by unit ID.
    """
    _management, access = _prepare_service_address_baseline(db, ui)
    from atlaso.app.models import (
        DnsRecord,
        DnsSettings,
        KmsSettings,
        LdapSettings,
        NtpSettings,
        VcfOfflineDepotSettings,
    )

    ntp = db.scalar(select(NtpSettings))
    ldap = db.scalar(select(LdapSettings))
    kms = db.scalar(select(KmsSettings))
    depot = db.scalar(select(VcfOfflineDepotSettings))
    for service, settings in (("ntpd", ntp), ("ldap", ldap), ("kms", kms), ("vcf_offline_depot", depot)):
        settings.enabled = service in active_services
        settings.listen_interface = access.name
        settings.listen_address = "192.0.2.10\n2001:db8::10"

    captured = ui.appliance_apply_units(db)
    ui.update_appliance_apply_baselines(db, captured, {unit["id"] for unit in captured})

    dns = db.scalar(select(DnsSettings))
    dns.enabled = dns_enabled
    db.execute(delete(DnsRecord))
    baselines = ui.load_appliance_apply_baselines(db)
    baselines["dnsmasq"]["dns_enabled"] = dns_enabled
    baselines["dnsmasq"]["service_dns_records"] = []
    ui.save_appliance_apply_baselines(db, baselines)

    access.ipv4_method = "dhcp" if dynamic_ipv4 else "static"
    access.ip_cidr = None if dynamic_ipv4 else "192.0.2.10/24"
    access.ipv6_enabled = True
    access.ipv6_cidr = None if dynamic_ipv6 else "2001:db8::10/64"
    access.host_ip_cidr = "192.0.2.10/24"
    access.host_ipv6_cidr = "2001:db8::10/64"
    access.mtu = 1400
    db.flush()
    units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
    return access, units


@pytest.mark.parametrize("dns_enabled", [False, True], ids=["dns-disabled", "dns-enabled-empty-ownership"])
def test_dynamic_service_listener_moves_do_not_require_dns_ownership(client, dns_enabled):
    """Capture every active dynamic listener from applied service baselines alone.

    Args:
        client: Isolated authenticated application client.
        dns_enabled: Keep DNS disabled or enabled with an empty owned-record inventory.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    services = {"ntpd", "ldap", "kms", "vcf_offline_depot"}
    with SessionLocal() as db:
        access, units = _prepare_service_baselines(
            db, ui, services, dns_enabled=dns_enabled, dynamic_ipv4=False,
        )

        assert units["network"]["changed"] is True
        assert units["network"]["validation_errors"] == []
        assert ui.load_appliance_apply_baselines(db)["dnsmasq"]["service_dns_records"] == []
        moves = ui.network_dynamic_service_listener_moves(db, units)

        assert {move["service"] for move in moves} == services
        assert all(move["interface"] == access.name for move in moves)
        assert all(move["old_address"] == move["new_address"] for move in moves)
        assert {move["old_address"] for move in moves} == {"2001:db8::10"}


def test_static_candidate_does_not_create_dynamic_service_listener_moves(client):
    """Leave static service listeners outside the dynamic Network handoff.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        _access, units = _prepare_service_baselines(
            db, ui, {"ntpd"}, dns_enabled=False, dynamic_ipv4=False, dynamic_ipv6=False,
        )

        assert units["network"]["changed"] is True
        assert ui.network_dynamic_service_listener_moves(db, units) == []


def test_management_handoff_captures_and_persists_service_moves_without_dns(client, monkeypatch, tmp_path):
    """Verify a no-DNS handoff carries listener moves and advances its applied baseline.

    Args:
        client: Isolated authenticated application client.
        monkeypatch: Substitute native discovery, staging, and helper execution.
        tmp_path: Temporary root for the staged handoff manifest.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        access, units = _prepare_service_baselines(db, ui, {"ntpd"}, dns_enabled=False, dynamic_ipv4=False)
        units["public_services"]["context"]["public_service_entries"] = []
        submitted_move = {
            "service": "ntpd",
            "interface": access.name,
            "old_address": "2001:db8::10",
            "new_address": "2001:db8::10",
        }
        observed_move = {**submitted_move, "new_address": "2001:db8::21"}
        staged: dict[str, str] = {}

        def stage_config(target, content):
            """Record staged configuration without writing appliance paths.

            Args:
                target: Canonical staging path selected by Apply.
                content: Configuration or manifest text staged for the handoff.

            Returns:
                The unchanged staging path.
            """
            staged[str(target)] = content
            return str(target)

        class Adapter:
            """Return helper evidence for one confirmed SLAAC listener move."""

            dry_run = False

            def validate_management_handoff(self, _path):
                """Accept the staged manifest for the test handoff.

                Args:
                    _path: Staged manifest path validated by the helper.
                """
                return AdapterResult(command=["validate"], dry_run=False, returncode=0)

            def apply_management_handoff(self, path):
                """Return the manifest moves with the helper-confirmed address.

                Args:
                    path: Staged manifest path applied by the helper.
                """
                manifest = json.loads(staged[str(path)])
                assert manifest["listener_address_moves"] == [submitted_move]
                return AdapterResult(
                    command=["apply"],
                    dry_run=False,
                    returncode=0,
                    stdout=json.dumps({
                        "management_handoff": "applied",
                        "listener_address_moves": [observed_move],
                        "service_address_observation": {
                            "complete": True,
                            "links": [{
                                "name": access.name,
                                "configured": True,
                                "address_inventory_complete": True,
                                "addresses": [{
                                    "address": observed_move["new_address"],
                                    "cidr": "2001:db8::21/64",
                                    "scope": "global",
                                    "state": "assigned",
                                }],
                            }],
                        },
                    }),
                )

                def recover_management_handoff(self):
                    """Confirm there is no interrupted handoff to recover."""
                    return AdapterResult(command=["recover"], dry_run=False, returncode=0, stdout=json.dumps({"management_handoff": "no interrupted transaction"}))

        monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
        monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(tmp_path / "handoff.json"))
        monkeypatch.setattr(ui, "stage_appliance_apply_config", stage_config)
        monkeypatch.setattr(ui, "network_config_with_removed_vlans", lambda preview, _removed: preview)
        monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
        monkeypatch.setattr(
            ui,
            "discover_host_physical_interfaces",
            lambda: [SimpleNamespace(
                name=access.name,
                mac_address=access.mac_address,
                host_ipv6_cidr="2001:db8::21/64",
            )],
        )

        group, _results = ui.execute_management_handoff(
            units,
            job_id="job_dynamic_listener_no_dns",
            adapter=Adapter(),
            db=db,
            include_dnsmasq=False,
        )

        manifest = json.loads(staged[str(ui.MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH)])
        assert manifest["dnsmasq_config_path"] == ""
        assert manifest["listener_address_moves"] == [submitted_move]
        assert group["success"] is True, group["management_handoff"]
        assert group["listener_baselines"]["ntpd"]["config_preview"].count("2001:db8::21") == 2

        baselines = ui.load_appliance_apply_baselines(db)
        baselines.update(group["listener_baselines"])
        ui.save_appliance_apply_baselines(db, baselines)
        assert "2001:db8::21" in ui.load_appliance_apply_baselines(db)["ntpd"]["config_preview"]


def test_public_only_dynamic_readback_persists_host_address_and_baseline(client, monkeypatch, tmp_path):
    """Persist a public-only SLAAC observation and projected socket baseline without DNS.

    Args:
        client: Isolated authenticated application client.
        monkeypatch: Substitute native discovery, staging, and helper execution.
        tmp_path: Temporary root for the staged handoff manifest.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        access, units = _prepare_service_baselines(db, ui, set(), dns_enabled=False, dynamic_ipv4=False)
        public = units["public_services"]
        binding = next(
            entry for entry in public["context"]["public_service_entries"]
            if entry["interface"] == access.name and ":" in entry["address"]
        )
        old_address = binding["address"]
        submitted = public["raw_config_preview"]
        assert f"listen [{old_address}]:" in submitted
        submitted_move = {
            "interface": access.name, "old_address": old_address, "new_address": old_address,
        }
        observed_move = {**submitted_move, "new_address": "2001:db8::21"}
        staged: dict[str, str] = {}

        def stage_config(target, content):
            """Capture staging requests for the mocked helper.

            Args:
                target: Canonical destination path chosen for the staged config.
                content: Config or manifest text supplied to the staging helper.

            Returns:
                The unchanged destination path.
            """
            staged[str(target)] = content
            return str(target)

        class Adapter:
            """Return a successful public-listener handoff observation."""

            dry_run = False

            def validate_management_handoff(self, path):
                """Accept the staged transaction manifest.

                Args:
                    path: Manifest path selected for validation.
                """
                return AdapterResult(command=["validate"], dry_run=False, returncode=0)

            def apply_management_handoff(self, path):
                """Confirm the socket move and assigned SLAAC address.

                Args:
                    path: Manifest path selected for application.
                """
                manifest = json.loads(staged[str(path)])
                assert manifest["public_dynamic_bindings"] == [
                    {"interface": access.name, "old_address": old_address}
                ]
                return AdapterResult(
                    command=["apply"], dry_run=False, returncode=0,
                    stdout=json.dumps({
                        "management_handoff": "applied",
                        "listener_address_moves": [],
                        "public_service_address_moves": [observed_move],
                        "service_address_observation": {
                            "complete": True,
                            "links": [{
                                "name": access.name,
                                "configured": True,
                                "address_inventory_complete": True,
                                "addresses": [{
                                    "address": "2001:db8::21", "cidr": "2001:db8::21/64",
                                    "scope": "global", "state": "assigned",
                                }],
                            }],
                        },
                    }),
                )

            def recover_management_handoff(self):
                """Confirm no interrupted transaction remains after a successful apply."""
                return AdapterResult(
                    command=["recover"], dry_run=False, returncode=0,
                    stdout=json.dumps({"management_handoff": "no interrupted transaction"}),
                )

        monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
        monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(tmp_path / "handoff.json"))
        monkeypatch.setattr(ui, "stage_appliance_apply_config", stage_config)
        monkeypatch.setattr(ui, "network_config_with_removed_vlans", lambda preview, _removed: preview)
        monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
        monkeypatch.setattr(
            ui,
            "discover_host_physical_interfaces",
            lambda: [SimpleNamespace(
                name=access.name, mac_address=access.mac_address, host_ipv6_cidr="2001:db8::21/64",
            )],
        )

        group, _results = ui.execute_management_handoff(
            units, job_id="job_public_listener_no_dns", adapter=Adapter(), db=db, include_dnsmasq=False,
        )

        assert group["success"] is True, group["management_handoff"]
        projected = ui.projected_public_service_config(submitted, [observed_move])
        assert public["raw_config_preview"] == projected
        assert "listen [2001:db8::21]:" in public["raw_config_preview"]
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == access.name))
        assert interface.host_ipv6_cidr == "2001:db8::21/64"

        ui.update_appliance_apply_baselines(db, [public], {"public_services"})
        refreshed = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}["public_services"]
        assert refreshed["changed"] is False
        baseline_config = ui.load_appliance_apply_baselines(db)["public_services"]["config_preview"]
        assert baseline_config == projected.rstrip("\n")
        assert refreshed["config_preview"] == baseline_config


def test_kms_listener_source_survives_renewal_and_pending_interface_edit(client):
    """Use the successfully applied KMS interface after startup renews SLAAC.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import KmsSettings, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        access, _units = _prepare_service_baselines(
            db, ui, {"kms"}, dns_enabled=False, dynamic_ipv4=False, dynamic_ipv6=True,
        )
        baselines = ui.load_appliance_apply_baselines(db)
        assert baselines["kms"]["applied_listener_sources"]["2001:db8::10"] == access.name
        baselines["kms"]["applied_listener_sources"]["2001:db8::10"] = "renamed-access"
        baselines["network"]["physical_interface_aliases"] = {"renamed-access": access.name}
        ui.save_appliance_apply_baselines(db, baselines)
        management = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.role == "management")
        )
        assert management is not None

        # Startup observed a new SLAAC address after the prior KMS Apply. The
        # operator also has a different, still-pending KMS interface selection.
        access.host_ipv6_cidr = "2001:db8::21/64"
        db.scalar(select(KmsSettings)).listen_interface = management.name
        db.flush()
        assert all("2001:db8::10" not in option["addresses"] for option in ui.service_bind_options(db))
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}

        moves = ui.network_dynamic_service_listener_moves(db, units)
        kms_move = next(move for move in moves if move["service"] == "kms")
        assert kms_move == {
            "service": "kms", "interface": access.name,
            "old_address": "2001:db8::10", "new_address": "2001:db8::10",
        }
        assert units["network"]["validation_errors"] == []
        assert units["kms"]["changed"] is True
        projected = ui.projected_handoff_listener_baselines(
            {"kms": baselines["kms"]}, units,
            [{**kms_move, "new_address": "2001:db8::21"}],
        )["kms"]
        assert projected["applied_listener_sources"] == {
            "192.0.2.10": access.name, "2001:db8::21": access.name,
        }
        assert "2001:db8::21" in projected["config_preview"]


def test_legacy_kms_dynamic_listener_without_dns_source_fails_closed(client):
    """Block Network Apply when a legacy KMS dynamic binding has no proven source.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        _access, units = _prepare_service_baselines(
            db, ui, {"kms"}, dns_enabled=False, dynamic_ipv4=False, dynamic_ipv6=True,
        )
        baselines = ui.load_appliance_apply_baselines(db)
        # Model an older applied DHCP/SLAAC Network snapshot without the KMS
        # source metadata introduced by newer successful KMS Applies.
        baselines["network"]["config_preview"] = units["network"]["config_preview"]
        baselines["kms"].pop("applied_listener_interface", None)
        baselines["kms"].pop("applied_listener_sources", None)
        baselines["dnsmasq"]["service_dns_records"] = []
        ui.save_appliance_apply_baselines(db, baselines)

        reviewed = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert reviewed["network"]["validation_errors"] == [
            "The applied KMS listener source cannot be proven from this legacy baseline. Apply vSphere Key Providers first, then review Network again."
        ]


def test_kms_applied_source_map_keeps_multiple_interface_bindings(client):
    """Retain per-address source ownership when KMS listens on multiple interfaces.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import KmsSettings, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        access, _units = _prepare_service_baselines(
            db, ui, {"kms"}, dns_enabled=False, dynamic_ipv4=False, dynamic_ipv6=True,
        )
        secondary = PhysicalInterface(
            name="eth10", mac_address="02:00:00:00:00:20", role="access", mode="access",
            admin_state="up", oper_state="up", ipv4_method="static", ip_cidr="203.0.113.10/24",
        )
        db.add(secondary)
        db.flush()
        options = {row["name"]: row["addresses"] for row in ui.service_bind_options(db)}
        selected = [access.name, secondary.name]
        addresses = list(dict.fromkeys([*options[access.name], *options[secondary.name]]))
        kms_settings = db.scalar(select(KmsSettings))
        kms_settings.listen_interface = "\n".join(selected)
        kms_settings.listen_address = "\n".join(addresses)
        db.flush()

        captured = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        ui.update_appliance_apply_baselines(db, [captured["kms"]], {"kms"})
        baseline_sources = ui.load_appliance_apply_baselines(db)["kms"]["applied_listener_sources"]
        assert baseline_sources["2001:db8::10"] == access.name
        assert baseline_sources["203.0.113.10"] == secondary.name

        access.host_ipv6_cidr = "2001:db8::21/64"
        db.flush()
        candidate = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        kms_moves = [move for move in ui.network_dynamic_service_listener_moves(db, candidate)
                     if move["service"] == "kms"]
        assert kms_moves == [{
            "service": "kms", "interface": access.name,
            "old_address": "2001:db8::10", "new_address": "2001:db8::10",
        }]


@pytest.mark.parametrize("service", ["ntpd", "ldap", "vcf_offline_depot"])
def test_dynamic_listener_sources_survive_renewal_alias_and_pending_interface(client, service):
    """Use captured per-address source ownership after renewals and pending edits.

    Args:
        client: Isolated authenticated application client.
        service: Listener service whose applied source is renewed.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        LdapSettings,
        NtpSettings,
        PhysicalInterface,
        VcfOfflineDepotSettings,
    )

    login(client)
    with SessionLocal() as db:
        access, _units = _prepare_service_baselines(
            db, ui, {service}, dns_enabled=False, dynamic_ipv4=False, dynamic_ipv6=True,
        )
        secondary = PhysicalInterface(
            name="eth10", mac_address="02:00:00:00:00:20", role="access", mode="access",
            admin_state="up", oper_state="up", ipv4_method="static", ip_cidr="203.0.113.10/24",
            ipv6_enabled=True, ipv6_cidr="2001:db8:2::10/64",
        )
        db.add(secondary)
        db.flush()
        options = {row["name"]: row["addresses"] for row in ui.service_bind_options(db)}
        selected = [access.name, secondary.name]
        addresses = list(dict.fromkeys([*options[access.name], *options[secondary.name]]))
        settings = db.scalar(select({
            "ntpd": NtpSettings, "ldap": LdapSettings, "vcf_offline_depot": VcfOfflineDepotSettings,
        }[service]))
        settings.listen_interface = "\n".join(selected)
        settings.listen_address = "\n".join(addresses)
        db.flush()

        applied_units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        ui.update_appliance_apply_baselines(db, [applied_units[service]], {service})
        baselines = ui.load_appliance_apply_baselines(db)
        sources = baselines[service]["applied_listener_sources"]
        assert sources["2001:db8::10"] == access.name
        assert sources["203.0.113.10"] == secondary.name
        assert sources["2001:db8:2::10"] == secondary.name

        # Startup renamed the source, then discovered a fresh SLAAC address.
        # A pending service interface edit must not take ownership of the move.
        baselines[service]["applied_listener_sources"]["2001:db8::10"] = "renamed-access"
        baselines["network"]["physical_interface_aliases"] = {"renamed-access": access.name}
        ui.save_appliance_apply_baselines(db, baselines)
        access.host_ipv6_cidr = "2001:db8::21/64"
        settings.listen_interface = secondary.name
        db.flush()
        candidate = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}

        moves = [move for move in ui.network_dynamic_service_listener_moves(db, candidate)
                 if move["service"] == service]
        assert moves == [{
            "service": service, "interface": access.name,
            "old_address": "2001:db8::10", "new_address": "2001:db8::10",
        }]
        projected = ui.projected_handoff_listener_baselines(
            {service: baselines[service]}, candidate,
            [{**moves[0], "new_address": "2001:db8::21"}],
        )[service]
        assert "2001:db8::21" in projected["config_preview"]
        assert "203.0.113.10" in projected["config_preview"]
        assert "2001:db8:2::10" in projected["config_preview"]
        assert projected["applied_listener_sources"]["2001:db8::21"] == access.name
        assert projected["applied_listener_sources"]["203.0.113.10"] == secondary.name


@pytest.mark.parametrize("desired_change", ["disable_ca", "remove_source_binding"])
def test_applied_dynamic_public_listener_still_requires_network_review(
    client, monkeypatch, desired_change,
):
    """Protect an applied dynamic Public Services socket after desired removal.

    Args:
        client: Authenticated application test client.
        monkeypatch: Replace protected unit rendering and background execution.
        desired_change: Disable CA or move its binding off the applied interface.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings, Job, JobStatus, PhysicalInterface
    from tests.routers.ui.test_dynamic_public_handoff_admission import (
        _mark_pending_protected_units,
        _prepare_dynamic_public_baseline,
    )

    login(client)
    with SessionLocal() as db:
        access = _prepare_dynamic_public_baseline(db, ui, dns_enabled=False, access_dynamic=True)
        access.mtu = 1400
        ca = db.scalar(select(CaSettings))
        if desired_change == "disable_ca":
            ca.enabled = False
        else:
            secondary = PhysicalInterface(
                name="eth10", mac_address="02:00:00:00:00:20", role="access", mode="access",
                admin_state="up", oper_state="up", ipv4_method="static", ip_cidr="203.0.113.10/24",
            )
            db.add(secondary)
            db.flush()
            ca.listen_interface = secondary.name
            ca.listen_address = "203.0.113.10"
        db.commit()

        with SessionLocal() as read_db:
            applied_public = ui.load_appliance_apply_baselines(read_db)["public_services"]["config_preview"]
            units = {unit["id"]: unit for unit in ui.appliance_apply_units(read_db)}
            dns_baseline = ui.load_appliance_apply_baselines(read_db)["dnsmasq"]
            assert dns_baseline["dns_enabled"] is False
            assert ui.network_generated_dns_unit(read_db, units) is None
            assert "listen [2001:db8::10]:443" in applied_public
            assert "listen [2001:db8::10]:443" not in units["public_services"]["raw_config_preview"]
            assert units["network"]["changed"] is True
            assert ui.network_dynamic_public_bindings(units) == []
            assert ui.network_listener_handoff_required(read_db, units) is True

    _mark_pending_protected_units(monkeypatch, ui)
    review_response = client.get("/appliance-apply/review")
    assert review_response.status_code == 200, review_response.text
    review = review_response.json()
    reviewed = {unit["id"]: unit for unit in review["units"]}
    assert reviewed["network"]["valid"] is True
    assert {"ca", "public_services"} <= {
        unit_id for unit_id, unit in reviewed.items() if unit.get("requires_network_selection")
    }
    required = {
        unit_id for unit_id, unit in reviewed.items() if unit.get("requires_network_selection")
    }

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    rejected = client.post(
        "/appliance-apply", data={"csrf": csrf, "selected_units": ["network"]},
        headers={"Accept": "application/json"},
    )
    assert rejected.status_code == 422, rejected.text
    assert "Unchecked changes cannot be applied" in rejected.json()["detail"]
    with SessionLocal() as db:
        assert db.scalar(select(Job).where(Job.status == JobStatus.PENDING.value)) is None

    submitted = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network", *sorted(required)]},
        headers={"Accept": "application/json"},
    )
    assert submitted.status_code == 202, submitted.text
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, submitted.json()["job_id"]).result or "{}")
        assert payload["management_handoff"] is True
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= set(payload["selected_units"])
        assert "dnsmasq" not in payload["selected_units"]
        captured = {unit["unit_id"] for unit in payload["captured_units"]}
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= captured
        assert "dnsmasq" not in captured


def test_removed_applied_static_public_listener_does_not_force_dynamic_handoff(client):
    """Do not add the dynamic listener handoff for an applied static socket.

    Args:
        client: Authenticated application test client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings
    from tests.routers.ui.test_dynamic_public_handoff_admission import (
        _prepare_dynamic_public_baseline,
    )

    login(client)
    with SessionLocal() as db:
        _access = _prepare_dynamic_public_baseline(
            db, ui, dns_enabled=False, access_dynamic=False,
        )
        db.scalar(select(CaSettings)).enabled = False
        _access.mtu = 1400
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}

        assert units["network"]["changed"] is True
        assert "listen [2001:db8::10]:443" not in units["public_services"]["raw_config_preview"]
        assert ui.network_dynamic_public_bindings(units) == []
        assert ui.network_applied_dynamic_public_listener_required(db, units) is False
        assert ui.network_listener_handoff_required(db, units) is False

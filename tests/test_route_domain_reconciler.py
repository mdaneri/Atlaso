"""Verify identity-bound dynamic routing rules and partial-failure recovery."""

import errno
import json
import struct
from contextlib import nullcontext

import pytest

from atlaso import route_domains as domains


def interface(name="eth0", mac="02:00:00:00:00:01", table=100):
    """Return a single applied interface identity.

    Args:
        name: Exact native attribute or interface name.
        mac: Expected native interface MAC identity.
        table: Owned management or lab routing table number.
    """
    return {"name": name, "mac": mac, "table": table}


def intent(*rows, held_addresses=None):
    """Validate an ordinary or protected-handoff intent fixture.

    Args:
        held_addresses: Previous management sources retained until handoff retirement.
        *rows: Interface records included in the applied intent fixture.
    """
    return domains.parse_intent({"schema": 1, "interfaces": list(rows), "held_addresses": held_addresses or []})


def link(row, *addresses):
    """Return native iproute2 interface and assigned-address observations.

    Args:
        row: Interface ownership record.
        *addresses: Assigned addresses included in the native link fixture.
    """
    return {"ifname": row["name"], "address": row["mac"], "addr_info": [
        {"local": address, "scope": "global", "valid_life_time": 3600} if isinstance(address, str) else address
        for address in addresses
    ]}


@pytest.mark.parametrize("source", ["192.0.2.10", "2001:db8::10"])
def test_transition_seeds_live_management_lookup_before_global_guard(monkeypatch, source):
    """An old source without a legacy prefix selector keeps its working path."""
    management = interface()
    inventory = [link(management, source)]
    events: list[tuple[str, object]] = []
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_native", lambda args: inventory if args == ["address", "show"] else [])
    monkeypatch.setattr(domains, "run_ip", lambda command: events.append(("rule", command)) or "")
    monkeypatch.setattr(domains, "_set_guard_locked", lambda family, enable:
                        events.append(("guard", (family, enable))))

    domains.transition_guard(True, [{"name": "eth0", "table": 100}])

    assert [event[0] for event in events] == ["rule", "rule", "guard", "guard"]
    assert events[0][1][-2:] == ["table", "100"]
    assert events[1][1][-1] == "unreachable"


def test_transition_refuses_ambiguous_live_management_source_before_guard(monkeypatch):
    """A duplicate address is not evidence of one management source owner."""
    management = interface()
    inventory = [link(management, "192.0.2.10"),
                 link(interface("eth1", "02:00:00:00:00:02", 200), "192.0.2.10")]
    commands = []
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_native", lambda args: inventory if args == ["address", "show"] else [])
    monkeypatch.setattr(domains, "run_ip", lambda command: commands.append(command) or "")

    with pytest.raises(domains.ReconcileError, match="ambiguous previous management source"):
        domains.transition_guard(True, [{"name": "eth0", "table": 100}])
    assert commands == []


def test_transition_start_seeds_persisted_identity_before_guard(monkeypatch):
    """The service's boot entry point also preserves already assigned sources."""
    management = interface()
    events = []
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_intent", lambda: intent(management))
    monkeypatch.setattr(domains, "read_native", lambda args:
                        [link(management, "192.0.2.10")] if args == ["address", "show"] else [])
    monkeypatch.setattr(domains, "run_ip", lambda command: events.append("rule") or "")
    monkeypatch.setattr(domains, "_set_guard_locked", lambda _family, _enable: events.append("guard"))

    domains.transition_guard(True)

    assert events == ["rule", "rule", "guard", "guard"]


def test_removed_vlan_already_absent_needs_no_source_hold():
    """A removed parent may already have taken its applied VLAN link away."""
    management = interface()
    removed = interface("eth0.20", "02:00:00:00:00:02", 200)
    applied = intent(management, removed)

    assert domains.removed_interface_holds(applied, [link(management, "192.0.2.10")], {removed["name"]}) == []


def test_removed_vlan_still_requires_other_and_present_link_identity():
    """Only the selected absent link is exempt from source identity proof."""
    management = interface()
    removed = interface("eth0.20", "02:00:00:00:00:02", 200)
    applied = intent(management, removed)

    with pytest.raises(domains.ReconcileError, match="old source identity unavailable"):
        domains.removed_interface_holds(applied, [link(removed, "192.0.2.20")], {removed["name"]})
    mismatch = link(removed, "192.0.2.20")
    mismatch["address"] = "02:00:00:00:00:03"
    with pytest.raises(domains.ReconcileError, match="old source identity unavailable"):
        domains.removed_interface_holds(applied, [link(management, "192.0.2.10"), mismatch], {removed["name"]})


def native_rule(rule):
    """Encode the exact iproute2 JSON shape, including omitted host prefix lengths.

    Args:
        rule: Exact source lookup or unreachable guard.
    """
    result = {"priority": rule.priority, "src": rule.source, "iif": "lo", "protocol": "2"}
    result.update({"table": str(rule.table)} if rule.table is not None else {"action": "unreachable"})
    return result


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("foreign", [False, True])
def test_preflight_reads_only_rules_without_intent(monkeypatch, family, foreign):
    """Canonical occupied-window admission is read-only and needs no prior intent.

    Args:
        monkeypatch: Reversible native boundary replacements.
        family: Family containing the observed source rule.
        foreign: Whether an unowned occupant must reject admission.
    """
    source = "192.0.2.10" if family == 4 else "2001:db8::10"
    row = native_rule(domains.Rule(5000, source, 100))
    if foreign:
        row["protocol"] = "99"
    reads = []

    def observe(arguments):
        """Return fixed rule observations, rejecting any other native operation.

        Args:
            arguments: Requested native read command.
        """
        assert arguments in [[f"-{version}", "rule", "show"] for version in (4, 6)]
        reads.append(arguments)
        return [row] if arguments[0] == f"-{family}" else []

    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_native", observe)
    monkeypatch.setattr(domains, "read_intent", lambda: pytest.fail("preflight read intent"))
    monkeypatch.setattr(domains, "apply_rules", lambda *_args: pytest.fail("preflight mutated rules"))
    if foreign:
        with pytest.raises(domains.ReconcileError, match="ownership conflict"):
            domains.preflight()
    else:
        domains.preflight()
        assert len(reads) == 2


def capture_commands(monkeypatch, fail_at=None):
    """Capture native mutations and optionally inject a bounded command failure.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        fail_at: Command ordinal at which the stub injects failure.
    """
    commands = []

    def execute(arguments):
        """Record the command before simulating its native result.

        Args:
            arguments: Native command argument vector.
        """
        commands.append(arguments)
        if fail_at == len(commands):
            raise domains.ReconcileError("injected native failure")
        return ""

    monkeypatch.setattr(domains, "run_ip", execute)
    return commands


def test_overlapping_domains_keep_distinct_exact_dual_stack_sources():
    """The same prefixes never collapse management and lab interface ownership."""
    management, lab = interface(), interface("eth1", "02:00:00:00:00:02", 200)
    sources, incomplete = domains.source_tables(intent(management, lab), [
        link(management, "192.0.2.10", "2001:db8::10"), link(lab, "192.0.2.20", "2001:db8::20"),
    ])
    assert not incomplete
    assert sources == {"192.0.2.10": 100, "2001:db8::10": 100, "192.0.2.20": 200, "2001:db8::20": 200}
    rules = domains.plan_rules(sources, set())
    assert len(rules) == 8
    for rule in rules:
        assert domains.PRIORITY_START <= rule.priority < domains.PRIORITY_END
        assert domains.Rule(rule.slot + 1, rule.source, None) in rules
        command = domains.rule_command("add", rule)
        assert command[command.index("iif") + 1] == "lo"
        assert command[command.index("from") + 1].endswith("/32" if rule.family == 4 else "/128")


@pytest.mark.parametrize("entry", [
    {"local": "192.0.2.10", "tentative": True},
    {"local": "192.0.2.10", "dadfailed": True},
    {"local": "2001:db8::10", "flags": ["tentative"]},
    {"local": "2001:db8::10", "flags": ["dadfailed"]},
    {"local": "2001:db8::10", "valid_life_time": 0},
    {"local": "fe80::10"}, {"local": "169.254.1.2"}, {"local": "127.0.0.1"},
    {"local": "::1"}, {"local": "0.0.0.0"}, {"local": "ff02::1"}, {"local": "224.0.0.1"},
])
def test_unassigned_failed_and_special_sources_never_acquire_lookup_rules(entry):
    """Tentative, failed DAD, expired, and non-unicast sources are ineligible.

    Args:
        entry: Native address record whose eligibility is tested.
    """
    row = interface()
    assert domains.source_tables(intent(row), [link(row, entry)]) == ({}, False)


def test_deprecated_and_privacy_addresses_keep_reply_routes_until_removed():
    """Deprecated SLAAC addresses remain assigned and usable by existing sockets."""
    row = interface("eth1", "02:00:00:00:00:02", 200)
    entries = [{"local": "fd00::123", "deprecated": True, "preferred_life_time": 0},
               {"local": "2001:db8::456", "temporary": True}]
    assert domains.source_tables(intent(row), [link(row, *entries)]) == ({"fd00::123": 200, "2001:db8::456": 200}, False)


@pytest.mark.parametrize("inventory", [[], [link(interface(mac="02:00:00:00:00:99"), "192.0.2.10")]])
def test_missing_or_replaced_interface_never_inherits_applied_ownership(inventory):
    """An interface name alone does not authorize a replacement NIC's addresses.

    Args:
        inventory: Native link and assigned-address inventory.
    """
    assert domains.source_tables(intent(interface()), inventory) == ({}, True)


def test_shared_source_is_guarded_without_arbitrary_table(monkeypatch):
    """A new duplicate removes an existing lookup only after its guard is ready.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    management, lab = interface(), interface("eth1", "02:00:00:00:00:02", 200)
    sources, _ = domains.source_tables(intent(management, lab), [link(management, "192.0.2.10"), link(lab, "192.0.2.10")])
    assert sources == {"192.0.2.10": None}
    old = {domains.Rule(5000, "192.0.2.10", 100)}
    desired = domains.plan_rules(sources, old)
    assert desired == {domains.Rule(5001, "192.0.2.10", None)}
    commands = capture_commands(monkeypatch)
    domains.apply_rules(desired, old)
    assert commands == [domains.rule_command("add", next(iter(desired))), domains.rule_command("del", next(iter(old)))]


def test_renewal_and_slaac_expiry_install_new_pairs_before_retiring_old(monkeypatch):
    """Renewal keeps unrelated stable priorities while safely replacing expired sources.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    old = domains.plan_rules({"192.0.2.10": 100, "2001:db8::10": 200, "2001:db8::20": 200}, set())
    desired = domains.plan_rules({"192.0.2.11": 100, "2001:db8::20": 200}, old)
    assert {rule for rule in old if rule.source == "2001:db8::20"} <= desired
    commands = capture_commands(monkeypatch)
    domains.apply_rules(desired, old)
    adds = [index for index, command in enumerate(commands) if command[3] == "add"]
    deletes = [index for index, command in enumerate(commands) if command[3] == "del"]
    assert max(adds) < min(deletes)
    assert all(command[-1] == "unreachable" for command in commands[-2:])


def test_handoff_hold_overrides_new_interface_domain_until_retirement(monkeypatch):
    """An old management source remains in table100 beside a new lab source.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    row = interface(table=200)
    hold = {**row, "address": "192.0.2.10", "table": 100}
    inventory = [link(row, "192.0.2.10", "192.0.2.11")]
    sources, _ = domains.source_tables(intent(row, held_addresses=[hold]), inventory)
    assert sources == {"192.0.2.10": 100, "192.0.2.11": 200}
    old = domains.plan_rules(sources, set())
    final_sources, _ = domains.source_tables(intent(row), inventory)
    desired = domains.plan_rules(final_sources, old)
    commands = capture_commands(monkeypatch)
    domains.apply_rules(desired, old)
    assert len(commands) == 2
    assert commands[0][3] == "del" and commands[0][-1] == "100"
    assert commands[1][3] == "add" and commands[1][-1] == "200"
    assert domains.Rule(next(rule.slot for rule in old if rule.source == "192.0.2.10") + 1, "192.0.2.10", None) in desired


def test_hold_can_retain_source_on_old_interface_omitted_from_final_intent():
    """Interface replacement can retain one old source without adopting other IPs."""
    row = interface()
    hold = {**row, "address": "192.0.2.10"}
    assert domains.source_tables(intent(held_addresses=[hold]), [link(row, "192.0.2.10", "192.0.2.11")]) == ({"192.0.2.10": 100}, False)


@pytest.mark.parametrize("change", [
    {"protocol": "static"}, {"iif": "eth0"}, {"fwmark": "0x1"}, {"srclen": 24},
    {"table": "254"}, {"priority": 5001}, {"action": "blackhole"},
])
def test_rule_ownership_refuses_foreign_or_noncanonical_records(change):
    """Never delete a range occupant or tagged rule with unproven selectors.

    Args:
        change: Noncanonical rule field overrides that must be rejected.
    """
    row = native_rule(domains.Rule(5000, "192.0.2.10", 100))
    row.update(change)
    with pytest.raises(domains.ReconcileError):
        domains.owned_rules([row], 4)


def test_round_trip_owned_rules_and_preserve_unrelated_priorities():
    """Numeric protocol tagging and exact selectors admit only our own rules."""
    rules = {domains.Rule(5000, "192.0.2.10", 100), domains.Rule(5001, "192.0.2.10", None)}
    rows = [native_rule(rule) for rule in rules]
    rows += [{"priority": 0, "src": "all", "table": "local", "protocol": "kernel"},
             {"priority": 2000, "src": "192.0.2.0", "srclen": 24, "table": "200"},
             {"priority": 32766, "src": "all", "table": "254", "protocol": "2"}]
    assert domains.owned_rules(rows, 4) == rules


@pytest.mark.parametrize("action", ["7", "unreachable"])
def test_photon_unreachable_action_allows_repeat_reconciliation_and_rollback(monkeypatch, action):
    """Admit the captured numeric guard so repeat Apply and rollback can converge.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        action: Native policy action under test or requested rule operation.
    """
    row = {"priority": 5571, "src": "192.168.167.172", "iif": "lo", "action": action, "protocol": "2"}
    lookup = domains.Rule(5570, "192.168.167.172", 100)
    guard = domains.Rule(5571, "192.168.167.172", None)
    existing = domains.owned_rules([native_rule(lookup), row], 4)
    assert existing == {lookup, guard}
    commands = capture_commands(monkeypatch)
    domains.apply_rules(domains.plan_rules({lookup.source: 100}, existing), existing)
    assert commands == []
    domains.apply_rules(set(), existing)
    assert commands == [domains.rule_command("del", lookup), domains.rule_command("del", guard)]


@pytest.mark.parametrize("action", ["6", "8", "07", "blackhole", "prohibit", 7, True, None])
def test_unreachable_numeric_action_does_not_admit_other_native_shapes(action):
    """Only named unreachable or its canonical numeric string owns a guard.

    Args:
        action: Native policy action under test or requested rule operation.
    """
    row = {"priority": 5571, "src": "192.168.167.172", "iif": "lo", "action": action, "protocol": "2"}
    with pytest.raises(domains.ReconcileError, match="policy action"):
        domains.owned_rules([row], 4)


def test_duplicate_native_priority_and_slot_ownership_are_rejected():
    """Ambiguous partial state must never be repaired using broad deletion."""
    row = native_rule(domains.Rule(5000, "192.0.2.10", 100))
    with pytest.raises(domains.ReconcileError):
        domains.owned_rules([row, row], 4)
    with pytest.raises(domains.ReconcileError):
        domains.plan_rules({}, {domains.Rule(5000, "192.0.2.10", 100), domains.Rule(5001, "192.0.2.11", None)})


def test_capacity_failure_does_not_retire_stale_rules_to_make_space(monkeypatch):
    """Fail before mutation when add-before-retire cannot fit in the owned range.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    monkeypatch.setattr(domains, "PRIORITY_END", 5004)
    old = {domains.Rule(5000, "192.0.2.1", 100), domains.Rule(5002, "192.0.2.2", 100)}
    with pytest.raises(domains.ReconcileError, match="capacity"):
        domains.plan_rules({"192.0.2.3": 100}, old)


@pytest.mark.parametrize("fail_at", [1, 2])
def test_partial_add_failure_never_retires_old_working_source(monkeypatch, fail_at):
    """Failed guards or lookups preserve the existing source path for recovery.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        fail_at: Command ordinal at which the stub injects failure.
    """
    old = domains.plan_rules({"192.0.2.10": 100}, set())
    desired = domains.plan_rules({"192.0.2.11": 100}, old)
    commands = capture_commands(monkeypatch, fail_at)
    with pytest.raises(domains.ReconcileError, match="injected"):
        domains.apply_rules(desired, old)
    assert all(command[3] == "add" for command in commands)


def test_empty_intent_retires_lookup_before_its_guard(monkeypatch):
    """Rollback to a pre-feature snapshot can remove only owned rule pairs.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    old = {domains.Rule(5000, "192.0.2.10", 100), domains.Rule(5001, "192.0.2.10", None)}
    commands = capture_commands(monkeypatch)
    domains.apply_rules(set(), old)
    assert commands == [domains.rule_command("del", domains.Rule(5000, "192.0.2.10", 100)),
                        domains.rule_command("del", domains.Rule(5001, "192.0.2.10", None))]


@pytest.mark.parametrize("failure_step", range(1, 5))
def test_partial_renewal_mutation_is_recoverable_from_native_snapshot(monkeypatch, failure_step):
    """Every interrupted renewal step converges without duplicate or broad rules.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        failure_step: Mutation ordinal at which simulated interruption occurs.
    """
    native = domains.plan_rules({"192.0.2.10": 100}, set())
    desired_sources = {"192.0.2.11": 100}
    desired = domains.plan_rules(desired_sources, native)
    calls = 0

    def execute(arguments):
        """Emulate kernel rule updates and one injected command failure.

        Args:
            arguments: Native command argument vector.
        """
        nonlocal calls
        calls += 1
        if calls == failure_step:
            raise domains.ReconcileError("interrupted")
        rule = domains.Rule(int(arguments[5]), arguments[7].split("/")[0],
                            None if arguments[-1] == "unreachable" else int(arguments[-1]))
        if arguments[3] == "add":
            assert rule not in native
            native.add(rule)
        else:
            assert rule in native
            native.remove(rule)
        return ""

    monkeypatch.setattr(domains, "run_ip", execute)
    with pytest.raises(domains.ReconcileError, match="interrupted"):
        domains.apply_rules(desired, set(native))
    domains.apply_rules(domains.plan_rules(desired_sources, native), set(native))
    assert {rule.source for rule in native} == {"192.0.2.11"}
    assert len(native) == 2


def test_failed_table_change_leaves_unreachable_guard_active(monkeypatch):
    """Changing ownership may fail closed but cannot fall into the other table.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    existing = {domains.Rule(5000, "192.0.2.10", 100), domains.Rule(5001, "192.0.2.10", None)}
    desired = domains.plan_rules({"192.0.2.10": 200}, existing)
    commands = capture_commands(monkeypatch, fail_at=2)
    with pytest.raises(domains.ReconcileError):
        domains.apply_rules(desired, existing)
    assert commands[0] == domains.rule_command("del", domains.Rule(5000, "192.0.2.10", 100))
    assert commands[1] == domains.rule_command("add", domains.Rule(5000, "192.0.2.10", 200))


def test_missing_intent_is_empty_for_prefeature_rollback(monkeypatch):
    """A missing fixed intent file means no applied source-rule ownership.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    def missing(*_args):
        """Model an older snapshot without the routing-domain feature.

        Args:
            *_args: Unused positional arguments required by the mocked native interface.
        """
        raise FileNotFoundError

    monkeypatch.setattr(domains.os, "open", missing)
    monkeypatch.setattr(domains.os, "O_NOFOLLOW", 0, raising=False)
    assert domains.read_intent() == domains.Intent(())


@pytest.mark.parametrize("value", [
    {"schema": True, "interfaces": []}, {"schema": 1, "interfaces": [], "extra": 1},
    {"schema": 1, "interfaces": [interface(table=True)]},
    {"schema": 1, "interfaces": [interface(name="eth0;id")]},
    {"schema": 1, "interfaces": [interface(mac="ff:ff:ff:ff:ff:ff")]},
    {"schema": 1, "interfaces": [interface(), interface()]},
])
def test_malformed_intent_cannot_authorize_commands(value):
    """Schema, identity, and shell-safe interface admission remain strict.

    Args:
        value: Untrusted value being validated.
    """
    with pytest.raises(domains.ReconcileError):
        domains.parse_intent(value)


@pytest.mark.parametrize("kind", [2, 4, 16, 17, 20, 21])
def test_link_address_and_overflow_events_trigger_full_snapshot(kind):
    """Initial and recovery planning uses complete snapshots instead of event deltas.

    Args:
        kind: Netlink message type encoded in the test datagram.
    """
    assert domains.event_requires_rescan(struct.pack("=IHHII", 16, kind, 0, 0, 0))


def test_truncation_malformed_event_and_unrelated_message_handling():
    """Any possible event loss requires a rescan; unrelated messages do not."""
    assert domains.event_requires_rescan(b"short")
    assert domains.event_requires_rescan(struct.pack("=IHHII", 16, 3, 0, 0, 0), True)
    assert not domains.event_requires_rescan(struct.pack("=IHHII", 16, 3, 0, 0, 0))


def test_reconcile_reads_new_intent_each_time_and_never_uses_desired_db(monkeypatch):
    """A periodic rescan consumes freshly published applied identity bindings.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    row = interface()
    states = iter([intent(row), intent()])
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_intent", lambda: next(states))
    monkeypatch.setattr(domains, "read_native", lambda args: [link(row, "192.0.2.10")] if args == ["address", "show"] else [])
    monkeypatch.setattr(domains, "run_ip", lambda _command: "")
    calls = []
    monkeypatch.setattr(domains, "apply_rules", lambda desired, existing: calls.append((desired, existing)))
    domains.reconcile()
    domains.reconcile()
    assert len(calls[0][0]) == 2
    assert calls[1] == (set(), set())


def test_new_dynamic_address_is_observed_only_behind_terminal_guards(monkeypatch):
    """A newly usable lease cannot escape through main before exact rules exist.

    Args:
        monkeypatch: Pytest fixture replacing external dependencies.
    """
    row = interface()
    guards = {4: False, 6: False}
    events = []
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_intent", lambda: intent(row))

    def read_native(args):
        """Return controlled native observations for this test.

        Args:
            args: Native observation arguments.
        """
        if args == ["address", "show"]:
            assert all(guards.values())
            events.append("address-observed")
            return [link(row, "192.0.2.20")]
        family = int(args[0][1:])
        return ([{"priority": domains.TRANSITION_PRIORITY, "src": "all", "srclen": 0, "iif": "lo",
                  "action": "unreachable", "protocol": "2"}] if guards[family] else [])

    def run_ip(command):
        """Record the policy-rule command without host mutation.

        Args:
            command: Native command being recorded.
        """
        family = int(command[1][1:])
        guards[family] = True
        events.append(f"guard-{family}")
        return ""

    monkeypatch.setattr(domains, "read_native", read_native)
    monkeypatch.setattr(domains, "run_ip", run_ip)
    monkeypatch.setattr(domains, "apply_rules", lambda desired, existing: events.append("exact-rules"))
    domains.reconcile()
    assert events == [*["guard-4"] * 5, *["guard-6"] * 5, "address-observed", "exact-rules"]
    assert guards == {4: True, 6: True}


def test_missing_identity_quarantines_old_source_instead_of_opening_main_fallback(monkeypatch):
    """Replacement NIC with an old source cannot inherit or bypass domain rules.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    row = interface()
    replaced = interface(mac="02:00:00:00:00:99")
    old = {domains.Rule(5000, "192.0.2.10", 100), domains.Rule(5001, "192.0.2.10", None)}
    monkeypatch.setattr(domains, "reconciliation_lock", nullcontext)
    monkeypatch.setattr(domains, "read_intent", lambda: intent(row))
    monkeypatch.setattr(domains, "read_native", lambda args: [link(replaced, "192.0.2.10")]
                        if args == ["address", "show"] else [native_rule(rule) for rule in old] if args[0] == "-4" else [])
    commands = capture_commands(monkeypatch)
    with pytest.raises(domains.ReconcileError, match="identity unavailable"):
        domains.reconcile()
    assert [(command[1], command[3], command[command.index("priority") + 1]) for command in commands[:10]] == [
        (family, "add", str(priority)) for family in ("-4", "-6")
        for priority in (6004, 6000, 6001, 6002, 6003)]
    assert commands[10:] == [domains.rule_command("del", domains.Rule(5000, "192.0.2.10", 100))]


def test_native_rule_dump_requests_numeric_and_detailed_kernel_protocol(monkeypatch):
    """Kernel-protocol ownership is visible only with detailed iproute2 dumps.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    commands = []
    monkeypatch.setattr(domains, "run_ip", lambda arguments: commands.append(arguments) or "[]")
    assert domains.read_native(["-4", "rule", "show"]) == []
    assert commands == [[domains.IP_COMMAND, "-N", "-j", "-details", "-4", "rule", "show"]]


def test_native_json_failure_is_sanitized(monkeypatch):
    """Malformed command output is not included in privileged service errors.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    monkeypatch.setattr(domains, "run_ip", lambda _args: "untrusted native output")
    with pytest.raises(domains.ReconcileError, match="invalid native policy JSON"):
        domains.read_native(["address", "show"])


@pytest.mark.parametrize("failure", ["overflow", "timeout", "exit"])
def test_native_command_limits_kill_or_reap_child_without_exposing_output(monkeypatch, failure):
    """A stalled or noisy ip process cannot run indefinitely or leak its output.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
        failure: Injected subprocess failure mode.
    """
    class Output:
        """Provide the native stdout descriptor expected by bounded reads."""

        def fileno(self):
            return 7

    class Process:
        """Expose the Popen lifecycle without starting a host subprocess."""

        stdout = Output()
        killed = False
        stopped = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Implement the exit test stub.

            Args:
                *_args: Unused positional arguments required by the mocked native interface.
            """
            return False

        def poll(self):
            return 1 if self.stopped else None

        def kill(self):
            self.killed = True

        def wait(self, **_kwargs):
            """Implement the wait test stub.

            Args:
                **_kwargs: Unused keyword arguments required by the mocked subprocess interface.
            """
            self.stopped = True
            return 1 if failure == "exit" else 0

    process = Process()
    monkeypatch.setattr(domains.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(domains.select, "select", lambda *_args: ([], [], []) if failure == "timeout" else ([True], [], []))
    monkeypatch.setattr(domains.os, "read", lambda *_args: b"untrusted-native-output" if failure == "overflow" else b"")
    monkeypatch.setattr(domains, "MAX_JSON_BYTES", 8)
    with pytest.raises(domains.ReconcileError) as caught:
        domains.run_ip([domains.IP_COMMAND, "-j", "address", "show"])
    assert "untrusted" not in str(caught.value)
    assert process.stopped
    assert process.killed == (failure != "exit")


def test_monitor_rescans_receive_overflow_without_waiting_period(monkeypatch):
    """ENOBUFS cannot leave a missed lease change stale until another event.

    Args:
        monkeypatch: Pytest fixture replacing native operations with controlled observations.
    """
    class StopMonitor(Exception):
        """End the controlled monitor after its overflow recovery snapshot."""

    class FakeSocket:
        """Model a subscribed netlink descriptor that reports receive overflow."""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Implement the exit test stub.

            Args:
                *_args: Unused positional arguments required by the mocked native interface.
            """
            return False

        def setsockopt(self, *_args):
            """Implement the setsockopt test stub.

            Args:
                *_args: Unused positional arguments required by the mocked native interface.
            """
            pass

        def bind(self, *_args):
            """Implement the bind test stub.

            Args:
                *_args: Unused positional arguments required by the mocked native interface.
            """
            pass

        def recvmsg(self, *_args):
            """Implement the recvmsg test stub.

            Args:
                *_args: Unused positional arguments required by the mocked native interface.
            """
            raise OSError(errno.ENOBUFS, "overflow")

    calls = []

    def snapshot():
        """Stop after proving overflow caused the second full reconciliation."""
        calls.append(True)
        if len(calls) == 2:
            raise StopMonitor

    monkeypatch.setattr(domains.socket, "AF_NETLINK", 16, raising=False)
    monkeypatch.setattr(domains.socket, "NETLINK_ROUTE", 0, raising=False)
    monkeypatch.setattr(domains.socket, "socket", lambda *_args: FakeSocket())
    monkeypatch.setattr(domains.select, "select", lambda *_args: ([True], [], []))
    monkeypatch.setattr(domains, "reconcile", snapshot)
    with pytest.raises(StopMonitor):
        domains.monitor()
    assert len(calls) == 2


def test_rules_use_only_literal_ip_command_arguments():
    """No mutation accepts a shell, config path, namespace, or route operation."""
    command = domains.rule_command("del", domains.Rule(5001, "2001:db8::10", None))
    assert command == ["/usr/sbin/ip", "-6", "rule", "del", "priority", "5001", "from", "2001:db8::10/128",
                       "iif", "lo", "protocol", "2", "unreachable"]
    assert json.loads(json.dumps(native_rule(domains.Rule(5001, "2001:db8::10", None))))["action"] == "unreachable"

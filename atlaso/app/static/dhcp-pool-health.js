/* Applied DHCP pool evidence uses the shared read-only Tasks grid contract. */
document.addEventListener("DOMContentLoaded", () => {
  "use strict";
  const panel = document.getElementById("dhcp-pool-health");
  if (!panel || !window.AtlasoUiPatterns) return;
  const root = document.documentElement.dataset.managementUiRoot || "/ui/management";
  const path = (value) => `${root}${value}`;
  const message = document.getElementById("dhcp-pool-status");
  const title = document.getElementById("dhcp-pool-detail-title");
  const taskLink = document.getElementById("dhcp-pool-task-link");
  let reports = JSON.parse(panel.dataset.reports || "[]");
  let selected = Number(panel.dataset.selectedPool) || null;
  let busy = false;
  let addressReady = false;
  let refreshing = false;
  let gridReady = false;
  const text = (cell) => {
    const span = document.createElement("span");
    const value = cell.getValue();
    span.textContent = Array.isArray(value) ? value.join(", ") : String(value ?? "Not recorded");
    return span;
  };
  const addressGrid = window.AtlasoUiPatterns.createGrid({
    element: document.getElementById("dhcp-pool-address-grid"),
    fallback: "#dhcp-pool-address-fallback", pattern: "read-only",
    emptyMessage: "No address evidence recorded for this pool.",
    options: {data: reports.find((item) => item.scope_id === selected)?.observations || [], index: "ip_address", height: "360px", layout: "fitDataStretch",
      columns: [
        {title: "IP", field: "ip_address", formatter: text},
        {title: "State", field: "status", formatter: text},
        {title: "Unresolved", field: "unresolved", formatter: text},
        {title: "Observed MAC", field: "observed_mac_addresses", formatter: text},
        {title: "Expected MAC", field: "expected_mac_addresses", formatter: text},
        {title: "Client IDs", field: "expected_client_ids", formatter: text},
        {title: "Reason", field: "reason", formatter: text, minWidth: 360},
        {title: "First seen", field: "first_seen", formatter: text},
        {title: "Last seen", field: "last_seen", formatter: text},
        {title: "Verification time", field: "verified_at", formatter: text},
        {title: "Prior finding", field: "previous_status", formatter: text},
        {title: "Resolved at", field: "resolved_at", formatter: text},
      ]},
  }).table;
  addressGrid?.on("tableBuilt", () => {addressReady = true; if (selected) show(selected);});
  const show = (id) => {
    selected = Number(id);
    const report = reports.find((item) => item.scope_id === selected);
    title.textContent = report ? `${report.name} · ${report.interface_name}` : "Address evidence";
    message.textContent = report ? `${report.reason} Progress: ${report.progress_percent}%. dnsmasq: ${report.dnsmasq_version || "Not recorded"}.` : "Pool no longer exists.";
    taskLink.href = path(report?.job_id ? `/tasks?job_id=${encodeURIComponent(report.job_id)}` : "/tasks");
    if (addressReady) addressGrid?.replaceData(report?.observations || []);
  };
  const verify = async (id) => {
    if (busy) return;
    busy = true;
    try {
      const body = new FormData();
      body.set("csrf", panel.dataset.csrf);
      const response = await fetch(path(`/dhcp/scopes/${id}/verification`), {method: "POST", body,
        headers: {"X-Requested-With": "XMLHttpRequest"}, credentials: "same-origin"});
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || result.title || "Verification could not be queued.");
      selected = Number(id);
      message.textContent = "Verification queued. Open Tasks for progress and cancellation.";
      await refresh();
    } catch (error) {message.textContent = error.message;} finally {busy = false;}
  };
  const actions = [{label: "View address evidence", action: (_event, row) => show(row.getData().scope_id)}];
  if (panel.dataset.canVerify === "true") {
    actions.push({label: "Verify pool", action: (_event, row) => verify(row.getData().scope_id)});
    actions.push({label: "Schedule verification", action: (_event, row) => {
      window.location.assign(path(`/automation?new=dhcp_pool_verify&scope_id=${row.getData().scope_id}`));
    }});
  }
  const grid = window.AtlasoUiPatterns.createGrid({
    element: document.getElementById("dhcp-pool-health-grid"), fallback: "#dhcp-pool-health-fallback",
    pattern: "read-only", emptyMessage: "No DHCP pools configured.", rowActions: actions,
    onOpenRow: (data) => show(data.scope_id),
    onReady: () => {gridReady = true; refresh();},
    options: {data: reports, index: "scope_id", height: "240px", layout: "fitDataStretch",
      columns: [
        {title: "Pool", field: "name", formatter: text},
        {title: "Interface / VLAN", field: "interface_name", formatter: text},
        {title: "Verification", field: "state", formatter: text},
        {title: "Unresolved", field: "unresolved_count", formatter: text},
        {title: "Progress %", field: "progress_percent", formatter: text},
        {title: "Verified at", field: "verified_at", formatter: text},
      ]},
  }).table;
  grid?.on("rowClick", (_event, row) => show(row.getData().scope_id));
  async function refresh() {
    if (document.hidden || panel.hidden || refreshing || !gridReady) return;
    refreshing = true;
    grid?.redraw(true);
    addressGrid?.redraw(true);
    try {
      const response = await fetch(path("/dhcp/verification"), {cache: "no-store", credentials: "same-origin"});
      if (!response.ok) throw new Error("Pool verification status is unavailable; retained evidence may be stale.");
      reports = await response.json();
      await grid?.replaceData(reports);
      if (selected) show(selected);
    } catch (error) {message.textContent = error.message;} finally {refreshing = false;}
  }
  if (selected) {
    document.querySelector('[data-tab-target="dhcp-pool-health"]')?.click();
    show(selected);
  }
  document.addEventListener("visibilitychange", refresh);
  new MutationObserver(refresh).observe(panel, {attributes: true, attributeFilter: ["hidden"]});
  window.setInterval(refresh, 20000);
}, {once: true});

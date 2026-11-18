(function initializeMonitorRuntimeModule(global) {
  "use strict";

  const GRID_COLUMNS = {
    routes: [
      { title: "Family", field: "family", width: 95 },
      { title: "Table", field: "table_label", minWidth: 120 },
      { title: "Destination", field: "destination", minWidth: 150 },
      { title: "Gateway", field: "gateway", minWidth: 140 },
      { title: "Interface", field: "interface", minWidth: 110 },
      { title: "Metric", field: "metric", width: 90 },
      { title: "Type", field: "type", width: 120 },
      { title: "Protocol", field: "protocol", width: 110 },
    ],
    rules: [
      { title: "Family", field: "family", width: 95 },
      { title: "Priority", field: "priority", width: 100, sorter: "number" },
      { title: "Source", field: "source", minWidth: 140 },
      { title: "Destination", field: "destination", minWidth: 140 },
      { title: "Ingress", field: "ingress", minWidth: 110 },
      { title: "Egress", field: "egress", minWidth: 110 },
      { title: "Table", field: "table_label", minWidth: 120 },
      { title: "Action", field: "action", minWidth: 120 },
      { title: "Selectors", field: "selectors_text", minWidth: 160 },
    ],
    interfaces: [
      { title: "Interface", field: "interface", minWidth: 120 },
      { title: "Link", field: "carrier", minWidth: 95 },
      { title: "Parent / VLAN", field: "parent_vlan", minWidth: 135 },
      { title: "Addresses", field: "addresses_text", minWidth: 220 },
      { title: "MTU", field: "mtu", width: 85 },
      { title: "RX errors", field: "rx_errors", width: 105 },
      { title: "TX errors", field: "tx_errors", width: 105 },
    ],
    neighbors: [
      { title: "Family", field: "family", width: 95 },
      { title: "Address", field: "address", minWidth: 170 },
      { title: "Interface", field: "interface", minWidth: 125 },
      { title: "State", field: "state", minWidth: 115 },
    ],
    services: [
      { title: "Service", field: "name", minWidth: 165 },
      { title: "State", field: "state", minWidth: 110 },
      { title: "Active for", field: "uptime_text", minWidth: 120 },
      { title: "Restarts", field: "restarts", width: 100 },
      { title: "Listeners", field: "listeners_text", minWidth: 220 },
      { title: "Configuration", field: "url", minWidth: 130, formatter: serviceLinkFormatter },
    ],
  };

  function serviceLinkFormatter(cell) {
    const url = cell.getValue();
    if (typeof url !== "string" || (!url.startsWith("/") || url.startsWith("//"))) return "Unavailable";
    const link = document.createElement("a");
    const managementRoot = document.documentElement.dataset.managementUiRoot || "";
    link.href = url.startsWith(`${managementRoot}/`) ? url : `${managementRoot}${url}`;
    link.textContent = "Open settings";
    return link;
  }

  function familyLabel(value) {
    const family = String(value ?? "");
    return family.toLowerCase().startsWith("ipv") ? family : `IPv${family}`;
  }

  function monitorRuntimeStatusText(sectionStates) {
    const entries = Object.entries(sectionStates || {});
    const states = entries.map(([, state]) => state);
    if (!states.length || states.every((state) => state === "unavailable")) return "Runtime data is unavailable.";
    if (states.some((state) => state === "partial" || state === "unavailable")) {
      const affected = entries.filter(([, state]) => state === "partial" || state === "unavailable").map(([key]) => key);
      return `Some runtime data is partial or unavailable (${affected.join(", ")}).`;
    }
    return "Runtime data is current.";
  }

  function createMonitorRuntimeLoadCoordinator(options) {
    let requestId = 0;
    let inFlight = null;
    return {
      refresh() {
        if (inFlight) return inFlight;
        const activeRequest = ++requestId;
        options.onStart?.();
        inFlight = Promise.resolve()
          .then(options.request)
          .then((payload) => {
            if (activeRequest === requestId) options.onData(payload);
            return payload;
          })
          .catch((error) => {
            if (activeRequest === requestId) options.onError(error);
            return null;
          })
          .finally(() => {
            inFlight = null;
          });
        return inFlight;
      },
    };
  }

  function tableLabel(value) {
    if (Number(value) === 100) return "Management (100)";
    if (Number(value) === 200) return "Lab (200)";
    if (Number(value) === 254) return "Main (254)";
    return value === null || value === undefined || value === "" ? "--" : String(value);
  }

  function formatDuration(value) {
    if (value === null || value === undefined || value === "") return "Unavailable";
    const seconds = Number(value);
    if (!Number.isFinite(seconds) || seconds < 0) return "Unavailable";
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days) return `${days}d ${hours}h`;
    if (hours) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  }

  function clockSourceLabel(value) {
    return ({
      ntp_client: "NTP client",
      ntp_server: "NTP server",
      vmware_tools: "VMware Tools",
      manual: "Manual",
      unverified: "Unverified",
    })[value] || "Unavailable";
  }

  function monitorSectionRows(payload, key) {
    const section = payload?.sections?.[key];
    return Array.isArray(section?.rows) ? section.rows : [];
  }

  function projectRows(key, rows) {
    return rows.map((row) => {
      const rowKey = [key, row.family, row.table, row.priority, row.destination, row.source, row.interface, row.address, row.unit, row.metric, row.protocol, row.type, JSON.stringify(row.nexthops || [])]
        .map((value) => String(value ?? ""))
        .join("|");
      if (key === "routes") {
        const nextHops = Array.isArray(row.nexthops) ? row.nexthops : [];
        return {
          ...row,
          _runtime_row: rowKey,
          table_label: tableLabel(row.table),
          family: familyLabel(row.family),
          gateway: nextHops.length
            ? nextHops.map((item) => item.gateway || "On-link").join(", ")
            : row.gateway || (row.interface ? "On-link" : "—"),
          interface: nextHops.length ? nextHops.map((item) => item.interface).filter(Boolean).join(", ") || row.interface : row.interface,
        };
      }
      if (key === "rules") {
        return {
          ...row,
          _runtime_row: rowKey,
          family: familyLabel(row.family),
          table_label: row.table === null || row.table === undefined ? "--" : tableLabel(row.table),
          selectors_text: Array.isArray(row.selectors) ? row.selectors.join(", ") : typeof row.selectors === "string" ? row.selectors : row.selectors && typeof row.selectors === "object" ? Object.entries(row.selectors).map(([name, value]) => `${name} ${value}`).join(", ") : "--",
        };
      }
      if (key === "interfaces") {
        return {
          ...row,
          _runtime_row: rowKey,
          parent_vlan: row.parent ? `${row.parent}${row.vlan === null || row.vlan === undefined ? "" : ` · VLAN ${row.vlan}`}` : "--",
          addresses_text: Array.isArray(row.addresses)
            ? row.addresses.map((item) => `${item.address}/${item.prefix} · ${item.origin || "unknown"}`).join(", ") || "No addresses"
            : "Unavailable",
        };
      }
      if (key === "neighbors") return { ...row, _runtime_row: rowKey, family: familyLabel(row.family) };
      if (key === "services") {
        return {
          ...row,
          _runtime_row: rowKey,
          uptime_text: row.uptime_seconds === null || row.uptime_seconds === undefined ? "Unavailable" : formatDuration(row.uptime_seconds),
          listeners_text: Array.isArray(row.listeners)
            ? row.listeners.map((listener) => {
                const address = listener.address.includes(":") ? `[${listener.address}]` : listener.address;
                return `${listener.protocol} ${address}:${listener.port}`;
              }).join(", ") || "No listeners"
            : "Unavailable",
        };
      }
      return row;
    });
  }

  function monitorCaptureLabel(value) {
    if (typeof value !== "string" || !value) return "Not captured";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "Capture time unavailable" : date.toLocaleString();
  }

  function renderMonitorUpdateComparison(root, payload) {
    const container = root.querySelector("[data-monitor-update-sections]");
    if (!container) return;
    const status = root.querySelector("[data-monitor-update-status]");
    const phases = payload?.phases || {};
    root.querySelector("[data-monitor-update-before]").textContent = phases.before?.state === "unrecorded" ? "No comparison recorded" : monitorCaptureLabel(phases.before?.captured_at);
    root.querySelector("[data-monitor-update-after]").textContent = phases.after?.state === "unrecorded" ? "No comparison recorded" : monitorCaptureLabel(phases.after?.captured_at);
    const sections = payload?.sections || {};
    container.replaceChildren();
    const labels = { routes: "Routes", rules: "Policy rules", interfaces: "Interfaces and addresses", forwarding: "Forwarding" };
    Object.entries(labels).forEach(([key, label]) => {
      const section = sections[key];
      const card = document.createElement("section");
      card.className = "monitor-update-diff-section";
      const heading = document.createElement("h4");
      heading.textContent = label;
      card.append(heading);
      if (payload?.state === "unrecorded" || section?.state === "unrecorded") {
        const message = document.createElement("p");
        message.textContent = "No comparison recorded.";
        card.append(message);
      } else if (!section) {
        const message = document.createElement("p");
        message.textContent = "No comparison recorded.";
        card.append(message);
      } else {
        const added = Array.isArray(section.added) ? section.added : [];
        const removed = Array.isArray(section.removed) ? section.removed : [];
        const changed = Array.isArray(section.changed) ? section.changed : [];
        const message = document.createElement("p");
        message.textContent = section.state === "unavailable"
          ? "Comparison unavailable."
          : section.state === "partial"
            ? `Partial comparison · ${added.length} added, ${removed.length} removed, ${changed.length} changed.`
            : added.length || removed.length || changed.length
              ? `${added.length} added, ${removed.length} removed, ${changed.length} changed.`
              : "No changes.";
        card.append(message);
        if (section.state !== "unavailable" && (added.length || removed.length || changed.length)) {
          const details = document.createElement("details");
          const summary = document.createElement("summary");
          summary.textContent = "View changed entries";
          details.append(summary);
          const groups = [["Added", added], ["Removed", removed], ["Changed", changed]];
          groups.forEach(([groupLabel, rows]) => {
            if (!rows.length) return;
            const heading = document.createElement("h5");
            heading.textContent = groupLabel;
            const list = document.createElement("ul");
            rows.forEach((row) => {
              const item = document.createElement("li");
              item.textContent = row.before && row.after
                ? `${comparisonRowSummary(key, row.before)} → ${comparisonRowSummary(key, row.after)}`
                : comparisonRowSummary(key, row);
              list.append(item);
            });
            details.append(heading, list);
          });
          card.append(details);
        }
      }
      container.append(card);
    });
    if (status) {
      const states = Object.values(sections).map((section) => section?.state);
      const outcome = payload?.outcome?.status;
      const outcomeLabel = outcome ? `Update ${outcome}. ` : "";
      status.textContent = payload?.state === "unrecorded"
        ? "No comparison recorded for this task."
        : outcomeLabel + (states.length && states.every((state) => state === "ok")
        ? "Comparison captured before and after the update."
        : "Some update observations are partial or unavailable.");
    }
  }

  function comparisonRowSummary(section, row) {
    if (section === "routes") {
      const family = familyLabel(row.family);
      const table = tableLabel(row.table);
      const destination = row.destination || "unknown destination";
      const nextHops = Array.isArray(row.nexthops) ? row.nexthops : [];
      const gateway = nextHops.length
        ? nextHops.map((hop) => hop.gateway || hop.type || "On-link").join(", ")
        : row.gateway || (row.type && row.type !== "unicast" ? row.type : "On-link");
      const egressInterface = nextHops.length
        ? nextHops.map((hop) => hop.interface).filter(Boolean).join(", ") || row.interface
        : row.interface;
      return `${family} ${table} ${destination} via ${gateway}${egressInterface ? ` on ${egressInterface}` : ""}${row.metric === null || row.metric === undefined ? "" : ` (metric ${row.metric})`}`;
    }
    if (section === "rules") {
      return `IPv${row.family} priority ${row.priority}: ${row.source || "all"} → ${row.destination || "all"}, ${row.action || "lookup"} ${tableLabel(row.table)}${row.ingress ? ` from ${row.ingress}` : ""}`;
    }
    if (section === "interfaces") {
      const addresses = (Array.isArray(row.addresses) ? row.addresses : []).map(({ address, prefix, origin }) =>
        `${address}/${prefix}${origin ? ` (${origin})` : ""}`).join(", ");
      const parent = row.parent ? ` on ${row.parent}` : "";
      const vlan = row.vlan == null ? "" : ` VLAN ${row.vlan}`;
      const carrier = row.carrier === true ? "up" : row.carrier === false ? "down" : "unavailable";
      return `${row.interface || "Interface"}${parent}${vlan} · Carrier ${carrier} · MTU ${row.mtu ?? "unavailable"} · ${addresses || "no addresses"}`;
    }
    return `IPv${row.family} forwarding ${row.enabled === true ? "enabled" : row.enabled === false ? "disabled" : "unavailable"}`;
  }

  function renderClockSummary(panel, clock) {
    const source = panel.querySelector("[data-monitor-clock-source]");
    const sync = panel.querySelector("[data-monitor-clock-sync]");
    const pending = panel.querySelector("[data-monitor-clock-pending]");
    if (source) source.textContent = clockSourceLabel(clock?.source);
    if (sync) {
      const value = clock?.synchronization;
      sync.textContent = value ? value.charAt(0).toUpperCase() + value.slice(1) : "Unavailable";
    }
    if (pending) {
      pending.textContent = clock?.pending === true ? "Pending or unverified"
        : clock?.pending === false ? "No transition pending" : "Unavailable";
    }
  }

  function setGridFallback(table, key, rows, state) {
    const body = table?.tBodies?.[0];
    if (!body) return;
    body.replaceChildren();
    if (!rows.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = table.tHead?.rows?.[0]?.cells?.length || 1;
      cell.textContent = state === "unavailable" ? "Observation unavailable." : state === "partial" ? "Observation is partial; no rows were returned." : "No entries observed.";
      row.append(cell);
      body.append(row);
      return;
    }
    rows.forEach((item) => {
      const row = document.createElement("tr");
      const values = key === "routes"
        ? [item.family, item.table_label, item.destination, item.gateway, item.interface, item.metric, item.type]
        : key === "rules"
          ? [item.family, item.priority, item.source, item.destination, item.ingress, item.table_label || item.action]
          : key === "interfaces"
            ? [item.interface, item.carrier, item.parent_vlan, item.addresses_text, item.mtu, item.rx_errors, item.tx_errors]
            : key === "neighbors"
              ? [item.family, item.address, item.interface, item.state]
              : [item.name, item.state, item.uptime_text, item.restarts, item.listeners_text, item.url ? "Open settings" : "Unavailable"];
      values.forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value === null || value === undefined || value === "" ? "--" : String(value);
        row.append(cell);
      });
      body.append(row);
    });
  }

  function initializeMonitorRuntimePage() {
    const root = document.querySelector("[data-monitor-runtime-page]");
    if (!(root instanceof HTMLElement) || root.dataset.runtimeInitialized === "true") return;
    root.dataset.runtimeInitialized = "true";
    const tabList = root.querySelector(".monitor-section-tabs");
    const tabs = Array.from(tabList?.querySelectorAll("[role='tab']") || []);
    const syncTabStops = () => tabs.forEach((tab) => {
      tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
    });
    tabs.forEach((tab) => tab.addEventListener("click", syncTabStops));
    tabList?.addEventListener("keydown", (event) => {
      const current = tabs.indexOf(event.target);
      if (current < 0) return;
      let next;
      if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
      else if (event.key === "ArrowLeft") next = (current + tabs.length - 1) % tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else return;
      event.preventDefault();
      tabs[next].click();
      tabs[next].focus();
    });
    syncTabStops();
    const grids = new Map();
    const initializeGrids = (panel) => {
      panel.querySelectorAll("[data-monitor-grid]").forEach((element) => {
        const key = element.dataset.monitorGrid;
        const columns = GRID_COLUMNS[key];
        if (grids.has(key) || !columns || !global.AtlasoUiPatterns?.createGrid) return;
        const grid = { table: null, ready: false, replace: null };
        const filter = key === "routes" ? panel.querySelector("[data-monitor-route-filter]") : null;
        const applyFilter = () => {
          if (!filter || !grid.ready) return;
          const query = filter.value.trim().toLowerCase();
          if (query) {
            grid.table.setFilter((row) => [row.family, row.table_label, row.destination, row.gateway, row.interface]
              .some((field) => String(field ?? "").toLowerCase().includes(query)));
          } else {
            grid.table.clearFilter();
          }
        };
        filter?.addEventListener("input", applyFilter);
        grid.table = global.AtlasoUiPatterns.createGrid({
          element,
          fallback: `#${element.dataset.fallbackId}`,
          pattern: "read-only",
          emptyMessage: "No entries observed.",
          loadingMessage: "Waiting for a live observation.",
          onReady: () => {
            grid.ready = true;
            applyFilter();
            grid.replace?.();
          },
          options: {
            data: [],
            index: "_runtime_row",
            height: "240px",
            layout: "fitColumns",
            columns,
            rowFormatter: key === "routes" ? (row) => {
              const destination = row.getData()?.destination;
              row.getElement()?.classList.toggle("monitor-default-route-row", ["default", "0.0.0.0/0", "::/0"].includes(destination));
            } : undefined,
          },
        }).table;
        grids.set(key, grid);
      });
    };

    const renderPayload = (panel, payload) => {
      initializeGrids(panel);
      const sections = payload?.sections || {};
      const states = Object.fromEntries(Object.entries(sections).map(([key, section]) => [key, section?.state || "unavailable"]));
      const status = panel.querySelector("[data-monitor-runtime-status]");
      if (status) {
        const capturedAt = monitorCaptureLabel(payload?.captured_at);
        status.textContent = `${monitorRuntimeStatusText(states)} Last capture: ${capturedAt}.`;
        status.dataset.state = states ? (Object.values(states).includes("unavailable") || Object.values(states).includes("partial") ? "warning" : "ready") : "unavailable";
      }
      Object.keys(GRID_COLUMNS).forEach((key) => {
        const section = sections[key];
        if (!section) return;
        const rows = projectRows(key, monitorSectionRows(payload, key));
        const grid = grids.get(key);
        const gridElement = panel.querySelector(`[data-monitor-grid="${key}"]`);
        const fallback = gridElement ? panel.querySelector(`#${gridElement.dataset.fallbackId}`) : null;
        setGridFallback(fallback, key, rows, section.state);
        if (grid?.table) {
          grid.replace = () => {
            grid.replace = null;
            grid.table.replaceData(rows).then(() => {
              if (section.state === "unavailable" && gridElement && fallback) {
                gridElement.classList.add("hidden");
                fallback.classList.remove("hidden");
              }
            }).catch(() => {});
          };
          if (grid.ready) grid.replace();
        }
        const sectionStatus = panel.querySelector(`[data-monitor-section-status="${key}"]`);
        if (sectionStatus) {
          sectionStatus.textContent = section.state === "unavailable"
            ? "This observation is unavailable."
            : section.state === "partial"
              ? "Some runtime entries or fields are unavailable."
              : rows.length ? "" : "No entries observed.";
          sectionStatus.classList.toggle("hidden", !sectionStatus.textContent);
        }
      });
      const clockStatus = panel.querySelector('[data-monitor-section-status="clock"]');
      if (clockStatus && sections.clock) {
        clockStatus.textContent = sections.clock.state === "unavailable"
          ? "Clock observation is unavailable."
          : sections.clock.state === "partial"
            ? "Clock status is partial or unverified."
            : "";
        clockStatus.classList.toggle("hidden", !clockStatus.textContent);
      }
      sections.forwarding?.rows?.forEach((row) => {
        const value = panel.querySelector(`[data-monitor-forwarding-family="${row.family}"]`);
        if (value) value.textContent = row.enabled === true ? "Enabled" : row.enabled === false ? "Disabled" : "Unavailable";
      });
      renderClockSummary(panel, sections.clock?.rows?.[0]);
      const ingress = panel.querySelector("[data-monitor-route-lookup] select[name='ingress']");
      if (ingress && sections.interfaces?.rows) {
        const selected = ingress.value;
        ingress.replaceChildren(new Option("Local traffic", ""));
        sections.interfaces.rows.forEach((row) => ingress.add(new Option(row.interface, row.interface)));
        ingress.value = selected;
      }

    };

    const requestJson = async (url) => {
      const response = await fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      if (!response.ok) {
        if (response.status === 403) throw new Error("Your account cannot view this runtime data.");
        if (response.status === 422) throw new Error("Enter a valid destination IP address and a matching optional source address.");
        throw new Error("The runtime observation could not be loaded.");
      }
      return response.json();
    };
    const coordinators = new Map();
    [
      ["monitor-network-panel", root.dataset.networkUrl],
      ["monitor-services-panel", root.dataset.servicesUrl],
    ].forEach(([panelId, url]) => {
      const panel = root.querySelector(`#${panelId}`);
      if (!panel || !url) return;
      const status = panel.querySelector("[data-monitor-runtime-status]");
      let hasSuccessfulObservation = false;
      let lastCaptureLabel = "";
      const coordinator = createMonitorRuntimeLoadCoordinator({
        onStart: () => { if (status) status.textContent = "Refreshing live runtime data…"; },
        request: () => requestJson(url),
        onData: (payload) => {
          hasSuccessfulObservation = true;
          lastCaptureLabel = monitorCaptureLabel(payload?.captured_at);
          renderPayload(panel, payload);
        },
        onError: (error) => {
          if (status) {
            status.textContent = hasSuccessfulObservation
              ? `Stale · ${error.message} Last successful capture: ${lastCaptureLabel}.`
              : `${error.message} No successful runtime observation is available.`;
            status.dataset.state = "error";
          }
        },
      });
      coordinators.set(panelId, coordinator);
      panel.querySelectorAll("[data-monitor-refresh]").forEach((button) => button.addEventListener("click", () => coordinator.refresh()));
      const tab = root.querySelector(`[data-tab-target="${panelId}"]`);
      tab?.addEventListener("click", () => coordinator.refresh());
    });

    const lookupForm = root.querySelector("[data-monitor-route-lookup]");
    lookupForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = lookupForm.querySelector('button[type="submit"]');
      if (submit?.disabled) return;
      const status = root.querySelector("[data-monitor-lookup-status]");
      const output = root.querySelector("[data-monitor-lookup-result]");
      const form = new FormData(lookupForm);
      const params = new URLSearchParams({ destination: String(form.get("destination") || "").trim() });
      const source = String(form.get("source") || "").trim();
      const ingress = String(form.get("ingress") || "").trim();
      if (source) params.set("source", source);
      if (ingress) params.set("ingress", ingress);
      if (!params.get("destination")) {
        if (status) status.textContent = "Enter a destination IP address.";
        return;
      }
      if (status) status.textContent = "Checking the kernel route selection…";
      if (submit) submit.disabled = true;
      if (output) output.hidden = true;
      try {
        const payload = await requestJson(`${root.dataset.lookupUrl}?${params.toString()}`);
        const rows = Array.isArray(payload.rows) ? payload.rows : [];
        if (output) {
          output.textContent = rows.length
            ? rows.map((row) => comparisonRowSummary("routes", row)).join("\n")
            : payload.state === "unreachable"
              ? "The kernel reports this destination as unreachable."
              : "No route result was returned.";
          output.hidden = false;
        }
        if (status) status.textContent = payload.state === "unreachable" ? "Route lookup reports the destination as unreachable." : payload.state === "unavailable" ? "Route lookup is unavailable." : "Route selection observed. No packets were sent.";
      } catch (error) {
        if (status) status.textContent = error.message;
      } finally {
        if (submit) submit.disabled = false;
      }
    });

    const comparison = root.querySelector("[data-monitor-update]");
    if (comparison && root.dataset.updateUrlTemplate) {
      const jobId = comparison.dataset.monitorUpdate;
      const url = root.dataset.updateUrlTemplate.replace("__JOB_ID__", encodeURIComponent(jobId));
      const updateStatus = comparison.querySelector("[data-monitor-update-status]");
      const updateLoad = createMonitorRuntimeLoadCoordinator({
        request: () => requestJson(url),
        onData: (payload) => renderMonitorUpdateComparison(root, payload),
        onError: (error) => { if (updateStatus) updateStatus.textContent = error.message; },
      });
      comparison.closest(".tab-panel")?.querySelector("[data-monitor-refresh]")
        ?.addEventListener("click", () => updateLoad.refresh());
      updateLoad.refresh();
    }

    const params = new URLSearchParams(global.location.search);
    const requestedView = params.get("view") || (params.has("update") ? "network" : "overview");
    const requestedPanel = requestedView === "network" ? "monitor-network-panel" : requestedView === "services" ? "monitor-services-panel" : "monitor-overview-panel";
    const requestedTab = root.querySelector(`[data-tab-target="${requestedPanel}"]`);
    if (requestedTab && !requestedTab.classList.contains("active")) requestedTab.click();
    else if (requestedPanel !== "monitor-overview-panel") coordinators.get(requestedPanel)?.refresh();

    global.addEventListener("pageshow", () => {
      const activePanel = root.querySelector(".tab-panel.active");
      if (activePanel?.id) coordinators.get(activePanel.id)?.refresh();
    });
  }

  global.MonitorRuntime = {
    createMonitorRuntimeLoadCoordinator,
    clockSourceLabel,
    formatDuration,
    monitorRuntimeStatusText,
    renderClockSummary,
    renderMonitorUpdateComparison,
    tableLabel,
  };
  document.addEventListener("DOMContentLoaded", initializeMonitorRuntimePage);
})(window);

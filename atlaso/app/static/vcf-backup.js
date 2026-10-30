/* Approved VCF Backup remote-operation wizard adapter. */
(() => {
  "use strict";

  const form = document.querySelector("[data-vcf-backup-form]");
  const dialog = document.getElementById("vcf-backup-modal");
  const statusDialog = document.getElementById("vcf-backup-status-modal");
  if (!form || !dialog || !statusDialog || !window.AtlasoUiPatterns) return;

  const field = (name) => form.elements.namedItem(name) || statusDialog.querySelector(`[name="${name}"]`);
  const node = (selector) => form.querySelector(selector) || statusDialog.querySelector(selector) || document.querySelector(selector);
  const endpoint = form.dataset.endpoint || "";
  const receiverReady = form.dataset.setupReady === "true";
  const setupStatus = form.querySelector("[data-vcf-backup-status]");
  const operationStatus = statusDialog.querySelector("[data-vcf-backup-status]");
  const mode = node("[data-vcf-backup-credential-mode]");
  const vaultSelect = node("[data-vcf-backup-vault]");
  const entrySelect = node("[data-vcf-backup-entry]");
  const sourceKind = node("[data-vcf-backup-source-kind]");
  const gridElement = node("[data-vcf-backup-grid]");
  const fallbackRows = node("[data-vcf-backup-grid-fallback-rows]");
  const errors = node("[data-atlaso-wizard-error]");
  let vaults = [];
  let secrets = [];
  try { vaults = JSON.parse(document.getElementById("vcf-vault-credential-options")?.textContent || "[]"); } catch { vaults = []; }
  try { secrets = JSON.parse(document.getElementById("vcf-backup-secret-options")?.textContent || "[]"); } catch { secrets = []; }
  const vaultById = new Map(vaults.map((item) => [String(item.id), item]));
  (vaults || []).forEach((item) => vaultSelect?.append(new Option(item.name || `Vault ${item.id}`, String(item.id))));
  const vaultModeOption = mode?.querySelector('option[value="vault"]');
  if (vaultModeOption) vaultModeOption.disabled = vaults.length === 0;
  let operationId = "";
  let inspectionRevision = "";
  let inspectedSources = [];
  let components = [];
  let receiver = null;
  let reviewToken = "";
  let review = null;
  let operationStarted = false;
  let operationState = "";
  let canCloseWithoutCredentials = false;
  let grid = null;
  let operationsGrid = null;
  let operationsCursor = "";
  let operationsLoading = false;
  let operationsInitialized = false;
  let operationsGridReady = false;
  let operationsGridNeedsResize = true;
  let selectAllSupportedCheckbox = null;
  let busy = false;
  let pollTimer = null;
  let statusViewEpoch = 0;

  const setStatus = (message, error = false) => {
    const status = statusDialog.open ? operationStatus : setupStatus;
    if (!status) return;
    status.textContent = message;
    status.dataset.state = error ? "error" : "ready";
    status.setAttribute("role", error ? "alert" : "status");
  };
  const setError = (message = "") => {
    if (errors) {
      errors.textContent = message;
      errors.classList.toggle("hidden", !message);
    }
  };
  const safeText = (value, fallback = "Not recorded") => value === undefined || value === null || value === "" ? fallback : String(value);
  const sourceKindLabel = (kind) => kind === "fleet" ? "VCF Operations" : safeText(kind, "Source");
  function serviceBasePath(value) {
    const path = typeof value === "string" ? value.replace(/^\/+|\/+$/g, "") : "";
    return path ? `/${path}` : "";
  }
  async function call(path, payload) {
    const response = await fetch(`${endpoint}${path}`, {
      method: payload === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: payload === undefined ? {Accept: "application/json"} : {
        "Content-Type": "application/json", Accept: "application/json", "X-CSRF-Token": form.dataset.csrf || "",
      },
      body: payload === undefined ? undefined : JSON.stringify(payload),
    });
    let data = {};
    try { data = await response.json(); } catch { data = {}; }
    if (!response.ok) {
      const error = new Error(typeof data.detail === "string" ? data.detail : "The VCF Backup request could not complete.");
      error.status = response.status;
      throw error;
    }
    return data;
  }
  function invalidateReview() {
    reviewToken = "";
    review = null;
  }
  function invalidateStatusView() {
    statusViewEpoch += 1;
    busy = false;
    return statusViewEpoch;
  }
  function isCurrentStatusView(epoch, id) {
    return statusDialog.open && statusViewEpoch === epoch && operationId === id;
  }
  function selectedVaultEntry() {
    const selected = entrySelect?.selectedOptions?.[0];
    if (!selected?.value) return null;
    return {vault_id: String(vaultSelect.value), entry_id: String(selected.value), uri: selected.dataset.uri || ""};
  }
  function fillVaultEntries() {
    if (!vaultSelect || !entrySelect) return;
    const vault = vaultById.get(String(vaultSelect.value));
    entrySelect.replaceChildren(new Option(vault ? "Choose a key and HTTPS URI" : "Choose a Vault first", ""));
    (vault?.entries || []).forEach((entry) => {
      (entry.uris || []).filter((uri) => /^https:\/\//i.test(uri)).forEach((uri) => {
        const option = new Option(`${entry.key}${entry.username ? ` — ${entry.username}` : ""} — ${uri}`, String(entry.id));
        option.dataset.uri = uri;
        entrySelect.append(option);
      });
    });
    entrySelect.disabled = !vault || entrySelect.options.length < 2;
  }
  function updateCredentialMode() {
    const isVault = mode?.value === "vault";
    vaultSelect?.closest("label")?.classList.toggle("hidden", !isVault);
    entrySelect?.closest("label")?.classList.toggle("hidden", !isVault);
    field("username").required = !isVault;
    field("password").required = !isVault;
    field("username").disabled = isVault;
    field("password").disabled = isVault;
    if (isVault) field("password").value = "";
    else field("address").readOnly = false;
    wizard?.setSkippedSteps(isVault ? ["login"] : []);
    updateSourceFields();
  }
  function updateSourceFields() {
    const kinds = new Set(inspectedSources.map((item) => item.request.source_kind));
    const selectedKinds = selectedSourceKinds();
    const operationsSelected = selectedKinds.has("fleet");
    const directDailySelected = ["sddc", "vcenter"].some((kind) => selectedKinds.has(kind));
    const operationsDaily = operationsSelected && fleetScheduleMode() === "daily";
    const daily = directDailySelected || operationsDaily;
    const nsx = kinds.has("nsx");
    const stateChange = nsx || kinds.has("sddc");
    const generalRetention = kinds.has("fleet") || kinds.has("vcenter");
    node("[data-vcf-backup-fleet-schedule-mode]")?.classList.toggle("hidden", !operationsSelected);
    node("[data-vcf-backup-fleet-schedule-help]")?.classList.toggle("hidden", !operationsSelected);
    node("[data-vcf-backup-daily-time]")?.classList.toggle("hidden", !daily);
    const dailyLabel = node("[data-vcf-backup-daily-time] span");
    const utcProducts = [operationsDaily ? "Operations" : "", selectedKinds.has("sddc") ? "SDDC Manager" : ""].filter(Boolean);
    const timezoneDetails = [
      utcProducts.length ? `UTC for ${utcProducts.join(" and ")}` : "",
      selectedKinds.has("vcenter") ? "appliance timezone for vCenter" : "",
    ].filter(Boolean).join("; ");
    if (dailyLabel) dailyLabel.textContent = `${operationsDaily && !directDailySelected ? "Daily recurring backup time" : "Daily full backup time"} (${timezoneDetails || "appliance timezone"})`;
    node("[data-vcf-backup-nsx-interval]")?.classList.toggle("hidden", !nsx);
    node("[data-vcf-backup-state-change]")?.classList.toggle("hidden", !stateChange);
    node("[data-vcf-backup-general-retention]")?.classList.toggle("hidden", !generalRetention);
    node("[data-vcf-backup-sddc-retention]")?.classList.toggle("hidden", !kinds.has("sddc"));
    if (entrySelect?.value && mode?.value === "vault") {
      const saved = selectedVaultEntry();
      if (saved) {
        try {
          const url = new URL(saved.uri);
          field("address").value = url.hostname;
          field("port").value = url.port || "443";
          field("address").readOnly = true;
          field("username").value = vaultById.get(saved.vault_id)?.entries?.find((item) => String(item.id) === saved.entry_id)?.username || "";
        } catch { /* Server validation remains authoritative for URI parsing. */ }
      }
    } else if (field("address")) field("address").readOnly = false;
  }
  function captureSource() {
    const vault = mode?.value === "vault" ? selectedVaultEntry() : null;
    return {
      source_kind: field("source_kind").value,
      address: field("address").value.trim(),
      port: Number(field("port").value || 443),
      confirmed: true,
      confirmed_tls_fingerprint: tlsFingerprints.server || "",
      credential_vault_id: vault?.vault_id || "",
      credential_entry_id: vault?.entry_id || "",
      credential_uri: vault?.uri || "",
      username: mode?.value === "vault" ? "" : field("username").value.trim(),
      password: mode?.value === "vault" ? "" : field("password").value,
    };
  }
  const tlsFingerprints = {server: ""};
  function commonPayload(source) {
    const request = source || captureSource();
    const payload = {...request, password: request.password || ""};
    if (operationId) payload.operation_id = operationId;
    return payload;
  }
  function sourceSignature(source) {
    return JSON.stringify([source.source_kind, source.address.toLowerCase(), source.port]);
  }
  function coverageText(item) {
    if (typeof item === "string") return item;
    return `${item.component || item.product || "Coverage"}: ${item.reason || item.coverage_gap || JSON.stringify(item)}`;
  }
  function sideEffectText(value) {
    if (typeof value === "string") return value;
    const changes = Array.isArray(value.changes) ? value.changes.join(", ") : "";
    return [value.scope, changes ? `Changes: ${changes}` : "", value.limitation].filter(Boolean).join(". ")
      || value.description || value.effect || value.detail || "Review the listed native side effect.";
  }
  function buildRecoverySource(source) {
    const reference = source.credential_reference || {};
    const request = {
      source_id: source.source_id,
      source_kind: source.kind,
      address: source.address,
      port: source.port,
      confirmed: true,
      confirmed_tls_fingerprint: source.fingerprint,
      credential_vault_id: reference.vault_id || "",
      credential_entry_id: reference.entry_id || "",
      credential_uri: reference.uri || "",
      username: reference.username || "",
      password: "",
    };
    return {
      request,
      summary: {source_kind: source.kind, address: source.address, port: source.port, source_id: source.source_id, service: source.service || null},
      credentialMode: reference.mode || "manual",
    };
  }
  function validProbes() {
    return Boolean(tlsFingerprints.server && node('[data-vcf-backup-confirm="server"]')?.checked);
  }
  function probeRequest() {
    return {
      source_kind: field("source_kind").value,
      address: field("address").value.trim(), port: Number(field("port").value || 443),
    };
  }
  async function probeTargets() {
    setError("");
    const result = await call("/probe", probeRequest());
    for (const target of (result.targets || [])) {
      const key = "server";
      tlsFingerprints[key] = target.sha256 || "";
      const label = node(`[data-vcf-backup-fingerprint-value="${key}"]`);
      if (label) label.textContent = `${safeText(target.sha256)} · ${safeText(target.subject)} · ${safeText(target.issuer)}`;
      const checkbox = node(`[data-vcf-backup-confirm="${key}"]`);
      if (checkbox) { checkbox.disabled = !target.sha256; checkbox.checked = false; }
    }
    return result;
  }
  function selectedSecret(name) {
    const raw = field(name).value || "";
    const [vault_id, entry_id] = raw.split(":", 2);
    return {vault_id: vault_id || "", entry_id: entry_id || ""};
  }
  function policyPayload() {
    return {
      fleet_schedule_mode: fleetScheduleMode(),
      full_time: field("full_time").value,
      nsx_interval_minutes: Number(field("nsx_interval_minutes").value),
      state_change: field("state_change").checked,
      retention_mode: field("retention_mode").value,
      retention_value: Number(field("retention_value").value),
      sddc_most_recent: Number(field("sddc_most_recent").value),
      sddc_hourly_days: Number(field("sddc_hourly_days").value),
      sddc_daily_days: Number(field("sddc_daily_days").value),
    };
  }
  function selectedSourceKinds() {
    const selectedIds = new Set(selectedComponentIds());
    return new Set(components
      .filter((component) => selectedIds.has(String(component.id)))
      .map((component) => inspectedSources.find((item) => String(item.summary?.source_id || item.request.source_id || "") === String(component.source_id || ""))?.request.source_kind)
      .filter(Boolean));
  }
  function fleetScheduleMode() {
    return field("fleet_schedule_mode")?.value || "preserve";
  }
  function settingsAreValid() {
    const kinds = selectedSourceKinds();
    const requiresDaily = ["sddc", "vcenter"].some((kind) => kinds.has(kind)) || (kinds.has("fleet") && fleetScheduleMode() === "daily");
    const requiresRetention = kinds.has("fleet") || kinds.has("vcenter");
    const hasNSX = kinds.has("nsx");
    const hasSDDC = kinds.has("sddc");
    return secrets.length > 0 && Boolean(field("sftp_secret_ref").value && field("encryption_secret_ref").value)
      && (!requiresDaily || Boolean(field("full_time").value))
      && (!hasNSX || Number(field("nsx_interval_minutes").value) >= 5 && Number(field("nsx_interval_minutes").value) <= 1440)
      && (!requiresRetention || Number(field("retention_value").value) >= 1 && Number(field("retention_value").value) <= 365)
      && (!hasSDDC || Number(field("sddc_most_recent").value) >= 1 && Number(field("sddc_most_recent").value) <= 600
        && Number(field("sddc_hourly_days").value) >= 0 && Number(field("sddc_hourly_days").value) <= 14
        && Number(field("sddc_daily_days").value) >= 0 && Number(field("sddc_daily_days").value) <= 30);
  }
  function selectedComponentIds() {
    const rows = grid?.table?.getSelectedData?.() || [];
    return rows.filter((row) => row.supported === true).map((row) => String(row.id));
  }
  function isSupportedBackupRow(row) {
    return row.getData().supported === true;
  }
  function lockUnsupportedRowSelection(row) {
    const checkbox = row.getElement()?.querySelector('input[aria-label="Select Row"]');
    if (!checkbox) return;
    checkbox.disabled = !isSupportedBackupRow(row);
    if (checkbox.disabled) {
      checkbox.checked = false;
      if (row.isSelected?.()) row.deselect?.();
    }
  }
  function syncSupportedSelectionHeader(table) {
    if (!selectAllSupportedCheckbox) return;
    const eligible = table.getRows().filter(isSupportedBackupRow);
    const selected = table.getSelectedRows().filter(isSupportedBackupRow).length;
    selectAllSupportedCheckbox.disabled = eligible.length === 0;
    selectAllSupportedCheckbox.checked = eligible.length > 0 && selected === eligible.length;
    selectAllSupportedCheckbox.indeterminate = selected > 0 && selected < eligible.length;
  }
  function restoreSupportedSelection(table, selectedIds) {
    const wanted = new Set((selectedIds || []).map(String));
    if (!wanted.size) return;
    const rows = table.getRows().filter((row) => isSupportedBackupRow(row) && wanted.has(String(row.getData().id)));
    if (rows.length) table.selectRow(rows);
  }
  function supportedSelectionHeaderFormatter(cell) {
    const table = cell.getTable();
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.setAttribute("aria-label", "Select all supported backup components");
    checkbox.addEventListener("click", (event) => event.stopPropagation());
    checkbox.addEventListener("change", () => {
      const eligible = table.getRows().filter(isSupportedBackupRow);
      if (checkbox.checked) table.selectRow(eligible);
      else table.deselectRow(eligible);
      syncSupportedSelectionHeader(table);
    });
    selectAllSupportedCheckbox = checkbox;
    syncSupportedSelectionHeader(table);
    return checkbox;
  }
  function isDiscoveryStepActive() {
    const step = node('[data-atlaso-wizard-step="discovery"]');
    return Boolean(step && !step.hidden && !step.classList.contains("hidden"));
  }
  function renderComponents() {
    if (!gridElement || !window.AtlasoUiPatterns) return;
    if (!isDiscoveryStepActive()) {
      renderFallbackRows();
      return;
    }
    const rowText = (value) => { const span = document.createElement("span"); span.textContent = safeText(value); return span; };
    let created = false;
    if (!grid) {
      created = true;
      grid = window.AtlasoUiPatterns.createGrid({
        element: gridElement,
        fallback: "[data-vcf-backup-grid-fallback]",
        status: node("[data-vcf-backup-grid-status]"),
        pattern: "wizard-backed",
        emptyMessage: "No supported backup components were discovered.",
        errorMessage: "The discovery results could not be displayed. Inspect the source again to retry.",
        onReady: (table) => { syncSupportedSelectionHeader(table); table.redraw?.(true); },
        options: {
          data: components, index: "id", layout: "fitColumns", responsiveLayout: "collapse", selectableRows: true, selectableRowsCheck: isSupportedBackupRow,
          rowFormatter: lockUnsupportedRowSelection,
          rowHeader: {formatter: "rowSelection", titleFormatter: supportedSelectionHeaderFormatter, headerSort: false, hozAlign: "center", headerHozAlign: "center", width: 42},
          columns: [
            {title: "Component", field: "name", minWidth: 180, formatter: (cell) => rowText(cell.getValue())},
            {title: "Product / version", field: "product", minWidth: 150, formatter: (cell) => rowText(`${safeText(cell.getValue())} ${safeText(cell.getRow().getData().version, "")}`)},
            {title: "Current state", field: "current", minWidth: 180, formatter: (cell) => rowText(groupConfigurationState({current: cell.getValue()}))},
            {title: "Coverage", field: "coverage_gap", minWidth: 180, formatter: (cell) => {
              const item = cell.getRow().getData();
              return rowText(item.supported === false ? `Not supported — ${safeText(item.coverage_gap || item.reason, "not eligible")}` : safeText(item.coverage_gap, "Supported"));
            }},
          ],
        },
        permission: {allowed: true},
      });
      grid?.table?.on?.("rowSelectionChanged", () => {
        invalidateReview();
        if (grid?.table) syncSupportedSelectionHeader(grid.table);
        updateSourceFields();
      });
    }
    if (!grid?.table) {
      grid?.setError?.("The discovery grid could not be initialized. Enable JavaScript and refresh to retry.");
      renderFallbackRows();
      return;
    }
    if (!created) {
      const selectedIds = selectedComponentIds();
      const update = grid.table.setData || grid.table.replaceData;
      if (update) {
        const changed = update.call(grid.table, components);
        const refreshSelection = () => {
          if (!grid?.table) return;
          restoreSupportedSelection(grid.table, selectedIds);
          grid.table.redraw?.(true);
          syncSupportedSelectionHeader(grid.table);
        };
        if (changed && typeof changed.then === "function") changed.then(refreshSelection);
        else refreshSelection();
      }
    }
    renderFallbackRows();
  }
  function renderFallbackRows() {
    if (!fallbackRows) return;
    fallbackRows.replaceChildren();
    if (!components.length) {
      const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 5; cell.textContent = "No components discovered."; row.append(cell); fallbackRows.append(row); return;
    }
    components.forEach((item) => {
      const row = document.createElement("tr");
      ["Selection requires the interactive grid", item.name, `${safeText(item.product)} ${safeText(item.version, "")}`, groupConfigurationState(item), item.supported === false ? `Not supported — ${safeText(item.coverage_gap || item.reason, "not eligible")}` : item.coverage_gap || "Supported"].forEach((value) => { const cell = document.createElement("td"); cell.textContent = safeText(value); row.append(cell); });
      fallbackRows.append(row);
    });
  }
  function renderSourceSummaries() {
    const container = node("[data-vcf-backup-source-summaries]");
    if (!container) return;
    container.replaceChildren();
    inspectedSources.forEach(({summary, request}) => {
      const row = document.createElement("div"); const label = document.createElement("span"); const value = document.createElement("strong");
      label.textContent = sourceKindLabel(summary?.source_kind);
      const service = summary?.service;
      const serviceDetails = service ? ` · Discovered Fleet LCM ${safeText(service.address)}:${safeText(service.port)}${serviceBasePath(service.base_path)} · ${safeText(service.key, "")}${service.fingerprint ? ` · SHA-256 ${safeText(service.fingerprint)}` : ""}${service.version ? ` · ${safeText(service.version)}` : ""}` : "";
      value.textContent = `${summary?.address || ""}:${summary?.port || ""} · SHA-256 ${request.confirmed_tls_fingerprint || "not recorded"}${serviceDetails}`;
      row.append(label, value); container.append(row);
    });
  }
  function renderReview() {
    const container = node("[data-vcf-backup-review]");
    const coverage = node("[data-vcf-backup-coverage]");
    if (!container || !review) return;
    container.replaceChildren();
    appendReviewSection(container, "Current backup state", (review.components || []).map((group) => [
      (group.names || []).join(", ") || sourceKindLabel(group.kind),
      groupConfigurationState(group),
    ]));
    const operationsGroups = (review.components || []).filter((group) => group.kind === "fleet");
    if (operationsGroups.length) {
      const intent = {preserve: "Preserve existing schedule", daily: "Daily recurring backups", disabled: "Disable recurring backups"}[fleetScheduleMode()];
      appendReviewSection(container, "VCF Operations recurring backups", [
        ["Scheduling intent", intent || "Preserve existing schedule"],
        ["Initial backup", "Runs once in every mode"],
        ["Unconfigured schedule", "Preserve leaves recurring backups disabled when no schedule exists."],
      ]);
    }
    const sideEffects = (review.components || []).flatMap((group) => {
      const effects = Array.isArray(group.side_effects) ? group.side_effects : group.side_effects ? [group.side_effects] : [];
      const title = (group.names || []).join(", ") || sourceKindLabel(group.kind);
      return effects.map((effect) => `${title}: ${sideEffectText(effect)}`);
    });
    if (sideEffects.length) {
      const notice = document.createElement("div");
      notice.className = "alert warning";
      const heading = document.createElement("strong");
      heading.textContent = "Important native side effects";
      const list = document.createElement("ul");
      sideEffects.forEach((effect) => { const item = document.createElement("li"); item.textContent = effect; list.append(item); });
      notice.append(heading, list);
      container.append(notice);
    }
    const fleetSourceIds = new Set((review.components || []).filter((group) => group.kind === "fleet").map((group) => String(group.source_id || "")));
    const discoveredServices = inspectedSources
      .filter((item) => fleetSourceIds.has(String(item.summary?.source_id || "")) && item.summary?.service)
      .map((item) => {
        const service = item.summary.service;
        return `${service.address || ""}:${service.port || ""}${serviceBasePath(service.base_path)} · ${service.key || ""}${service.fingerprint ? ` · SHA-256 ${service.fingerprint}` : ""}${service.version ? ` · ${service.version}` : ""}`;
      });
    if (discoveredServices.length) {
      appendReviewSection(container, "Discovered Fleet LCM service", discoveredServices.map((value) => ["Service details", value]));
    }
    const groups = review.components || [];
    groups.forEach((group) => appendReviewSection(container, (group.names || []).join(", ") || sourceKindLabel(group.kind), groupSettingRows(group)));
    const labels = review.secret_labels || {};
    appendReviewSection(container, "Write-only Vault references", [
      ["Destination password key", labels.sftp || "Not returned"],
      ["Backup-encryption passphrase key", labels.encryption || "Not returned"],
      ["Secret values", "Write-only; values are not shown or returned."],
    ]);
    appendReviewSection(container, "Warnings", [["Review warnings", (review.warnings || []).join("; ") || "None"]]);
    const gaps = review.coverage_gaps || [];
    if (coverage) { coverage.textContent = gaps.length ? `Coverage gaps: ${gaps.map(coverageText).join("; ")}` : "No coverage gaps were reported."; coverage.classList.toggle("hidden", !gaps.length); }
  }
  function groupConfigurationState(group) {
    const current = group.current;
    if (!current || typeof current !== "object") return "Not configured";
    if (typeof current.configured === "boolean") return current.configured ? "Configured" : "Not configured";
    const hasValue = (value) => Array.isArray(value) ? value.length > 0 : value !== null && value !== undefined && value !== "";
    const destinationFields = ["host", "user", "directory", "ecdsa_fingerprint", "ssh_fingerprint"];
    const scheduleFields = ["full_time", "days", "interval_minutes", "retention_mode", "retention_value", "schedule_timezone", "sddc_most_recent", "sddc_hourly_days", "sddc_daily_days", "parts"];
    const enabledFields = ["schedule_enabled", "incremental_enabled", "state_change"];
    return [...destinationFields, ...scheduleFields].some((key) => hasValue(current[key]))
      || enabledFields.some((key) => current[key] === true)
      ? "Configured" : "Not configured";
  }
  function publicValue(settings, key, formatter = formatReviewValue) {
    if (!settings || typeof settings !== "object" || !Object.prototype.hasOwnProperty.call(settings, key)) return "Not returned";
    return formatter(settings[key]);
  }
  function formatReviewValue(value) {
    if (value === null || value === undefined || value === "") return "Not set";
    if (typeof value === "boolean") return value ? "Enabled" : "Disabled";
    if (Array.isArray(value)) return value.length ? value.map((item) => String(item).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())).join(", ") : "None";
    return String(value);
  }
  function settingComparison(label, key, current, proposed, formatter = formatReviewValue) {
    return [label, `Current: ${publicValue(current, key, formatter)} → Proposed: ${publicValue(proposed, key, formatter)}`];
  }
  function fleetSshFingerprint(settings) {
    const key = settings && Object.prototype.hasOwnProperty.call(settings, "ssh_fingerprint") ? "ssh_fingerprint" : "ecdsa_fingerprint";
    return publicValue(settings, key);
  }
  function retentionValue(settings) {
    if (!settings || !Object.prototype.hasOwnProperty.call(settings, "retention_value")) return "Not returned";
    const value = settings.retention_value;
    if (value === null || value === undefined || value === "") return "Not set";
    return settings.retention_mode === "days" ? `${value} days` : settings.retention_mode === "count" ? `${value} backups` : String(value);
  }
  function retentionMode(value) {
    if (value === "count") return "Keep most recent backups";
    if (value === "days") return "Keep backups by age in days";
    if (value === "policy") return "Product-specific policy";
    return formatReviewValue(value);
  }
  function groupSettingRows(group) {
    const current = group.current && typeof group.current === "object" ? group.current : {};
    const proposed = group.proposed && typeof group.proposed === "object" ? group.proposed : {};
    const rows = [
      settingComparison("Backup schedule", "schedule_enabled", current, proposed),
      settingComparison("Destination host", "host", current, proposed),
      settingComparison("Destination port", "port", current, proposed),
      settingComparison("Destination account", "user", current, proposed),
      settingComparison("Destination directory", "directory", current, proposed),
    ];
    if (group.kind === "vcenter") {
      rows.push(["ECDSA host-key pin", "Current: Not supported by native vCenter API → Proposed: Not supported by native vCenter API"]);
    } else if (group.kind === "fleet") {
      rows.push(["SSH host-key fingerprint", `Current: ${fleetSshFingerprint(current)} → Proposed: ${fleetSshFingerprint(proposed)}`]);
    } else {
      rows.push(settingComparison("ECDSA host-key fingerprint", "ecdsa_fingerprint", current, proposed));
    }
    if (group.kind !== "nsx") {
      rows.push(settingComparison("Daily backup time", "full_time", current, proposed));
      rows.push(settingComparison("Backup days", "days", current, proposed));
    }
    if (group.kind === "nsx") {
      rows.push(settingComparison("Backup interval (minutes)", "interval_minutes", current, proposed));
      rows.push(settingComparison("Back up on state change", "state_change", current, proposed));
    }
    if (group.kind === "sddc") {
      rows.push(settingComparison("Back up on state change", "state_change", current, proposed));
      rows.push(settingComparison("Most recent backups retained", "sddc_most_recent", current, proposed));
      rows.push(settingComparison("Hourly backup retention (days)", "sddc_hourly_days", current, proposed));
      rows.push(settingComparison("Daily backup retention (days)", "sddc_daily_days", current, proposed));
    }
    if (group.kind === "fleet") {
      const exactFleetValue = (value) => value === null || value === undefined || value === "" ? "Not set" : String(value);
      const currentStartTime = {value: current.fleet_schedule?.fullSchedule?.schedule?.startTime};
      const proposedStartTime = {value: proposed.fleet_schedule?.fullSchedule?.schedule?.startTime};
      const currentFallback = {value: current.fleet_schedule?.incrementalSchedule?.fallbackToFull};
      const proposedFallback = {value: proposed.fleet_schedule?.incrementalSchedule?.fallbackToFull};
      rows.push(settingComparison("Full schedule start time (RFC 3339)", "value", currentStartTime, proposedStartTime, exactFleetValue));
      rows.push(settingComparison("Incremental fallback to full backup", "value", currentFallback, proposedFallback, exactFleetValue));
      rows.push(settingComparison("Schedule timezone", "schedule_timezone", current, proposed));
      rows.push(settingComparison("Incremental schedule", "incremental_enabled", current, proposed));
      rows.push(settingComparison("Incremental interval (minutes)", "interval_minutes", current, proposed));
    }
    if (group.kind === "fleet" || group.kind === "vcenter") {
      rows.push(settingComparison("Retention mode", "retention_mode", current, proposed, retentionMode));
      rows.push(["Retention count or age", `Current: ${retentionValue(current)} → Proposed: ${retentionValue(proposed)}`]);
    }
    if (group.kind === "vcenter") rows.push(settingComparison("Backup parts", "parts", current, proposed));
    return rows;
  }
  function appendReviewSection(container, title, rows, collapsible = false) {
    const section = document.createElement(collapsible ? "details" : "section");
    section.className = "settings-list compact-settings-list validation-settings-list";
    const heading = document.createElement(collapsible ? "summary" : "h4");
    heading.textContent = title;
    section.append(heading);
    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      const key = document.createElement("span");
      const text = document.createElement("strong");
      key.textContent = label;
      text.textContent = safeText(value, "Not returned");
      row.append(key, text);
      section.append(row);
    });
    container.append(section);
  }
  function operationStateLabel(value) {
    const state = String(value || "").toLowerCase();
    const labels = {needs_recovery: "Needs attention", reconciled: "Reconciled", succeeded: "Succeeded", queued: "Queued", pending: "Pending", running: "Running", reviewed: "Review recorded", draft: "Inspection in progress"};
    return labels[state] || state.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) || "Status not recorded";
  }
  function checkpointLabel(value) {
    const labels = {
      reviewed: "Review recorded; no native writes sent",
      queued: "Waiting for the backup task to start",
      configuration_dispatch_pending: "Configuration may have been sent; reconcile before taking further action",
      configuration_submitted: "Native configuration submitted",
      backup_dispatch_pending: "Initial backup may have been started; reconcile before taking further action",
      backup_submitted: "Initial backup submitted to the native appliance",
      verified: "Native backup completion verified",
      closed_without_replay: "Recovery record closed without replaying native writes",
    };
    return labels[String(value || "").toLowerCase()] || "Checkpoint not recorded";
  }
  function nativeStateLabel(value) {
    const state = String(value || "").toLowerCase();
    const labels = {running: "Running", succeeded: "Succeeded", success: "Succeeded", complete: "Complete", completed: "Complete", failed: "Failed", pending: "Pending", queued: "Queued", canceled: "Canceled", cancelled: "Canceled"};
    return labels[state] || (state ? state.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()) : "No native task status returned");
  }
  function nativeOperationRunning(report) {
    const configurationRunning = String(report?.native_configuration?.state || "").toLowerCase() === "running";
    const backupRunning = String(report?.native_backup?.state || "").toLowerCase() === "running" && report.native_backup.native_task_terminal !== true;
    return configurationRunning || backupRunning;
  }
  function groupCurrentSettings(groupKind, current) {
    const settings = current && typeof current === "object" ? current : {};
    const rows = [
      ["Backup schedule", "schedule_enabled"], ["Destination host", "host"], ["Destination port", "port"],
      ["Destination account", "user"], ["Destination directory", "directory"],
    ].map(([label, key]) => [label, publicValue(settings, key)]);
    if (groupKind === "fleet") rows.push(["SSH host-key fingerprint", fleetSshFingerprint(settings)]);
    else if (groupKind !== "vcenter") rows.push(["ECDSA host-key fingerprint", publicValue(settings, "ecdsa_fingerprint")]);
    if (groupKind !== "nsx") {
      rows.push(["Daily backup time", publicValue(settings, "full_time")]);
      rows.push(["Backup days", publicValue(settings, "days")]);
    }
    if (groupKind === "fleet") {
      rows.push(["Schedule timezone", publicValue(settings, "schedule_timezone")]);
      rows.push(["Incremental schedule", publicValue(settings, "incremental_enabled")]);
      rows.push(["Incremental interval (minutes)", publicValue(settings, "interval_minutes")]);
      rows.push(["Retention mode", publicValue(settings, "retention_mode", retentionMode)]);
      rows.push(["Retention count or age", retentionValue(settings)]);
    } else if (groupKind === "sddc") {
      rows.push(["Back up on state change", publicValue(settings, "state_change")]);
      rows.push(["Most recent backups retained", publicValue(settings, "sddc_most_recent")]);
      rows.push(["Hourly backup retention (days)", publicValue(settings, "sddc_hourly_days")]);
      rows.push(["Daily backup retention (days)", publicValue(settings, "sddc_daily_days")]);
    } else if (groupKind === "nsx") {
      rows.push(["Backup interval (minutes)", publicValue(settings, "interval_minutes")]);
      rows.push(["Back up on state change", publicValue(settings, "state_change")]);
    } else if (groupKind === "vcenter") {
      rows.push(["Retention mode", publicValue(settings, "retention_mode", retentionMode)]);
      rows.push(["Retention count or age", retentionValue(settings)]);
      rows.push(["Backup parts", publicValue(settings, "parts")]);
    }
    return rows;
  }
  function syncOperationView() {
    wizard?.setNavigationLocked(operationStarted);
  }
  function renderOperationSources() {
    const container = node("[data-vcf-backup-operation-sources]");
    if (!container) return;
    container.replaceChildren();
    inspectedSources.forEach(({request, summary}) => {
      const row = document.createElement("div");
      const label = document.createElement("span");
      const value = document.createElement("strong");
      label.textContent = sourceKindLabel(request.source_kind);
      value.textContent = `${request.address}:${request.port} · SHA-256 ${request.confirmed_tls_fingerprint || "not recorded"}`;
      row.append(label, value);
      container.append(row);
      if (summary?.service) {
        const service = summary.service;
        const detail = document.createElement("div");
        const serviceLabel = document.createElement("span");
        const serviceValue = document.createElement("strong");
        serviceLabel.textContent = "Discovered Fleet LCM service";
        serviceValue.textContent = `${safeText(service.address)}:${safeText(service.port)}${serviceBasePath(service.base_path)} · ${safeText(service.key, "")}${service.fingerprint ? ` · SHA-256 ${safeText(service.fingerprint)}` : ""}${service.version ? ` · ${safeText(service.version)}` : ""}`;
        detail.append(serviceLabel, serviceValue);
        container.append(detail);
      }
    });
  }
  function reconciliationStatusText(result) {
    const state = String(result.reconciliation_state || "").toLowerCase();
    if (state === "queued") return "Read-only reconciliation is queued. Native settings and backup status are being checked.";
    if (state === "running") return "Read-only reconciliation is running. Native settings and backup status are being checked.";
    if (state === "succeeded") return "Read-only reconciliation completed.";
    if (state === "failed") return result.reconciliation_error || "Read-only reconciliation failed. Review the operation status before trying again.";
    return "";
  }
  function renderOperationGroups(groups, checkpoint, reconciliation) {
    const container = node("[data-vcf-backup-operation-detail]");
    if (!container) return;
    container.replaceChildren();
    const summary = document.createElement("p");
    summary.textContent = "Reconcile reads current native settings and backup status. It does not configure native settings or start another backup.";
    container.append(summary);
    if (checkpoint) {
      const latest = document.createElement("p");
      latest.textContent = `Latest checkpoint: ${checkpointLabel(checkpoint)}`;
      container.append(latest);
    }
    const reportRows = Array.isArray(reconciliation) ? reconciliation : [];
    const reports = new Map(reportRows.map((report) => [String(report.group_id || ""), report]));
    (Array.isArray(groups) ? groups : []).forEach((group, index) => {
      const memberIds = new Set((group.component_ids || []).map(String));
      const members = components.filter((component) => memberIds.has(String(component.id)));
      const names = members.map((component) => component.name).filter(Boolean);
      const source = inspectedSources.find((item) => members.some((component) => String(component.source_id) === String(item.request.source_id)));
      const kind = source?.request.source_kind || "";
      const report = reports.get(String(group.id || ""));
      let currentSettings = null;
      const rows = [["Latest checkpoint", checkpointLabel(group.checkpoint || report?.checkpoint)]];
      if (report) {
        rows.push(["Native configuration task", nativeStateLabel(report.native_configuration?.state)]);
        rows.push(["Initial backup task", nativeStateLabel(report.native_backup?.native_task_status || report.native_backup?.native_task_state || report.native_backup?.state)]);
        if (typeof report.artifacts_verified === "boolean" || typeof report.configuration_matches_review === "boolean") {
          rows.push(["Backup artifact verification", report.artifacts_verified === true ? "Verified" : report.artifacts_verified === false ? "Not verified" : "Not confirmed"]);
          rows.push(["Reviewed configuration", report.configuration_matches_review === true ? "Matches reviewed policy" : report.configuration_matches_review === false ? "Changed since review" : "Not confirmed"]);
        } else {
          rows.push(["Atlaso backup verification", report.verified === true ? "Verified" : report.verified === false ? "Not verified" : "Not confirmed"]);
        }
        const current = report.current && typeof report.current === "object" ? report.current : null;
        rows.push(["Current backup configuration", current ? groupConfigurationState({current}) : "No native settings read-back returned"]);
        const warnings = [report.warning, report.native_configuration?.warning, report.native_backup?.warning].filter((value, offset, values) => typeof value === "string" && value && values.indexOf(value) === offset);
        if (warnings.length) rows.push(["Native read-back warnings", warnings.join(" · ")]);
        if (current) {
          currentSettings = groupCurrentSettings(kind, current);
        }
      } else if (reportRows.length) {
        rows.push(["Native read-back", "No reconciliation report matched this group."]);
      }
      appendReviewSection(container, `${names.join(", ") || `Native backup group ${index + 1}`} — operation status`, rows);
      if (currentSettings) appendReviewSection(container, "Latest native settings", currentSettings, true);
    });
    if (reportRows.length && !groups?.length) {
      reportRows.forEach((_report, index) => appendReviewSection(container, `Native backup group ${index + 1} — reconciliation`, [["Native read-back", "The group could not be matched to its public operation status."]]));
    }
  }
  function renderOperation(result) {
    syncOperationView();
    operationState = String(result.state || "").toLowerCase();
    canCloseWithoutCredentials = result.can_close_without_credentials === true;
    node("[data-vcf-backup-operation-state]").textContent = operationStateLabel(result.state);
    node("[data-vcf-backup-operation-id]").textContent = safeText(result.operation_id || operationId, "Not loaded");
    const error = node("[data-vcf-backup-operation-error]");
    if (error) { error.textContent = result.error || ""; error.classList.toggle("hidden", !error.textContent); }
    const guidance = node("[data-vcf-backup-recovery-guidance]");
    if (guidance) { guidance.textContent = result.recovery_warning || "Reconcile checks current native settings and backup status without repeating native writes."; guidance.classList.toggle("hidden", !result.recovery_warning); }
    const runningWarning = node("[data-vcf-backup-native-running-warning]");
    const reconciliation = Array.isArray(result.reconciliation) ? result.reconciliation : [];
    const nativeRunning = reconciliation.some(nativeOperationRunning);
    if (runningWarning) { runningWarning.textContent = "A native configuration or backup task is still running. Check its status again before finishing recovery."; runningWarning.classList.toggle("hidden", !nativeRunning); }
    const reconciliationStatus = node("[data-vcf-backup-reconciliation-status]");
    const reconciliationState = String(result.reconciliation_state || "").toLowerCase();
    const reconciliationActive = ["queued", "running"].includes(reconciliationState);
    if (reconciliationStatus) {
      reconciliationStatus.textContent = reconciliationStatusText(result);
      reconciliationStatus.hidden = !reconciliationStatus.textContent;
      reconciliationStatus.classList.toggle("alert", reconciliationState === "failed");
      reconciliationStatus.classList.toggle("error", reconciliationState === "failed");
    }
    renderOperationGroups(result.groups, result.checkpoint, reconciliation);
    renderOperationSources();
    if (["succeeded", "reconciled"].includes(operationState)) {
      clearManualPasswords();
      node("[data-vcf-backup-recovery-credentials]")?.replaceChildren();
    }
    else if (reconciliationActive) node("[data-vcf-backup-recovery-credentials]")?.replaceChildren();
    else if ((operationState === "needs_recovery" || result.recovery_warning || result.error) && !node("[data-vcf-backup-recovery-credentials]")?.childElementCount) renderRecoveryCredentials();
    const progress = node("[data-vcf-backup-progress]");
    if (progress) {
      const value = Number(result.progress_percent || 0);
      if (["queued", "pending", "running"].includes(operationState) && value === 0) progress.removeAttribute("value");
      else progress.value = value;
      progress.classList.toggle("hidden", ["needs_recovery", "reconciled"].includes(operationState));
    }
    const link = node("[data-vcf-backup-task-link]");
    if (link && result.job_id) { link.href = `${form.dataset.tasksRoot}?job_id=${encodeURIComponent(result.job_id)}`; link.classList.remove("hidden"); }
    else link?.classList.add("hidden");
    node("[data-vcf-backup-close-control]")?.classList.toggle("hidden", operationState !== "needs_recovery");
    const reconcileButton = node("[data-vcf-backup-reconcile]");
    reconcileButton?.classList.toggle("hidden", ["succeeded", "reconciled"].includes(operationState));
    if (reconcileButton) reconcileButton.disabled = reconciliationActive;
    if (["queued", "pending", "running"].includes(String(result.state || "").toLowerCase()) || reconciliationActive) schedulePoll(1800);
    else window.clearTimeout(pollTimer);
  }
  function renderRecoveryCredentials() {
    const container = node("[data-vcf-backup-recovery-credentials]");
    if (!container) return;
    container.replaceChildren();
    inspectedSources.forEach(({request, credentialMode}) => {
      const row = document.createElement("div");
      row.className = "settings-list compact-settings-list";
      const description = document.createElement("p");
      description.textContent = `${sourceKindLabel(request.source_kind)} · ${request.address}:${request.port} · SHA-256 ${request.confirmed_tls_fingerprint || "not recorded"} · ${request.username || "saved Vault account"}`;
      row.append(description);
      if (credentialMode === "manual") {
        const label = document.createElement("label");
        const title = document.createElement("span");
        const input = document.createElement("input");
        title.textContent = `Re-enter password for ${request.username || request.address}`;
        input.type = "password";
        input.autocomplete = "new-password";
        input.dataset.vcfBackupRecoveryPassword = request.source_id;
        input.addEventListener("input", () => { request.password = input.value; });
        label.append(title, input);
        row.append(label);
      } else {
        const saved = document.createElement("p");
        saved.textContent = "Credential uses the recorded Vault reference; the Vault value is resolved server-side.";
        row.append(saved);
      }
      container.append(row);
    });
  }
  function hydrateOperation(result) {
    invalidateReview();
    operationId = result.operation_id || operationId;
    operationStarted = true;
    inspectionRevision = result.revision || "";
    inspectedSources = (result.sources || []).map(buildRecoverySource);
    components = result.components || [];
    receiver = result.receiver || receiver;
    renderOperation(result);
    node("[data-vcf-backup-recovery-id]").value = operationId;
    setStatus("Status loaded. Recovery can inspect or reconcile this operation; it cannot repeat native writes.");
  }
  async function openOperationStatus(requestedId) {
    const viewEpoch = invalidateStatusView();
    window.clearTimeout(pollTimer);
    pollTimer = null;
    if (requestedId) node("[data-vcf-backup-recovery-id]").value = requestedId;
    showStatusDialog();
    if (!requestedId) {
      setStatus("Enter an operation ID or choose an operation from the list.");
      return;
    }
    if (requestedId !== operationId) {
      clearManualPasswords();
      inspectedSources = [];
      components = [];
      receiver = null;
      operationStarted = false;
      operationState = "";
      canCloseWithoutCredentials = false;
      node("[data-vcf-backup-recovery-credentials]").replaceChildren();
      node("[data-vcf-backup-operation-detail]").replaceChildren();
      node("[data-vcf-backup-operation-sources]").replaceChildren();
      node("[data-vcf-backup-operation-error]").classList.add("hidden");
      node("[data-vcf-backup-native-running-warning]").classList.add("hidden");
      node("[data-vcf-backup-task-link]").classList.add("hidden");
      field("close_recovery").checked = false;
    }
    operationId = requestedId;
    node("[data-vcf-backup-operation-id]").textContent = requestedId;
    setStatus("Loading operation status…");
    try {
      const result = await call(`/operations/${encodeURIComponent(requestedId)}`);
      if (!isCurrentStatusView(viewEpoch, requestedId)) return;
      hydrateOperation(result);
    } catch (error) {
      if (!isCurrentStatusView(viewEpoch, requestedId)) return;
      const message = error?.message || "The operation status could not be loaded.";
      setStatus(message, true);
      const panelError = node("[data-vcf-backup-operation-error]");
      if (panelError) { panelError.textContent = message; panelError.classList.remove("hidden"); }
    }
  }
  async function loadOperation() {
    const requestedId = node("[data-vcf-backup-recovery-id]").value.trim();
    if (!requestedId) throw new Error("Enter an operation ID first.");
    return openOperationStatus(requestedId);
  }
  function showStatusDialog() {
    if (!statusDialog.open) statusDialog.showModal();
    window.requestAnimationFrame(() => node("[data-vcf-backup-recovery-id]")?.focus({preventScroll: true}));
  }
  function operationSourceSummary(sources) {
    return (Array.isArray(sources) ? sources : []).map((source) => `${sourceKindLabel(source.kind)} · ${safeText(source.address)}:${safeText(source.port)}`).join("; ") || "Not recorded";
  }
  function operationCell(value, fallback = "Not recorded") {
    const span = document.createElement("span");
    span.textContent = safeText(value, fallback);
    return span;
  }
  async function loadOperations(append = false) {
    if (!operationsGrid?.table || operationsLoading) return;
    operationsLoading = true;
    const status = document.querySelector("[data-vcf-backup-operations-status]");
    const refresh = document.querySelector("[data-vcf-backup-operations-refresh]");
    const more = document.querySelector("[data-vcf-backup-operations-more]");
    if (refresh) refresh.disabled = true;
    if (more) more.disabled = true;
    if (status) status.textContent = "Loading backup operations…";
    const query = new URLSearchParams({limit: "25"});
    if (append && operationsCursor) query.set("cursor", operationsCursor);
    try {
      const result = await call(`/operations?${query.toString()}`);
      const items = Array.isArray(result.items) ? result.items : [];
      if (append) await operationsGrid.table.addData(items);
      else await operationsGrid.table.setData(items);
      operationsCursor = result.next_cursor || "";
      if (more) more.classList.toggle("hidden", !operationsCursor);
      scheduleOperationsResize();
      if (status) status.textContent = `Loaded ${operationsGrid.table.getDataCount?.() ?? operationsGrid.table.getData?.().length ?? items.length} backup operation(s).`;
    } catch (error) {
      const message = error?.message || "Backup operations could not be loaded.";
      operationsGrid.setError(message);
      if (status) status.textContent = message;
    } finally {
      operationsLoading = false;
      if (refresh) refresh.disabled = false;
      if (more) more.disabled = false;
    }
  }
  function resizeOperationsGrid() {
    const element = document.querySelector("[data-vcf-backup-operations-grid]");
    const table = operationsGrid?.table;
    if (!operationsGridReady || !element || !table) return;
    const rect = element.getBoundingClientRect();
    if (!element.isConnected || element.closest("[hidden], .hidden") || rect.width <= 0) {
      element.style.height = "";
      operationsGridNeedsResize = true;
      return;
    }
    const compact = window.innerWidth <= 1100;
    const footer = document.querySelector(".management-info-footnote")?.getBoundingClientRect().height || 0;
    const more = document.querySelector("[data-vcf-backup-operations-more]");
    const moreHeight = more && !more.classList.contains("hidden") ? more.getBoundingClientRect().height + 12 : 0;
    const nextHeight = compact ? "" : `${Math.max(300, Math.floor(window.innerHeight - Math.max(0, rect.top) - footer - moreHeight - 44))}px`;
    if (element.style.height === nextHeight && !operationsGridNeedsResize) return;
    element.style.height = nextHeight;
    table.setHeight(nextHeight);
    table.redraw(true);
    operationsGridNeedsResize = false;
  }
  let operationsResizeFrame = null;
  function scheduleOperationsResize() {
    window.cancelAnimationFrame(operationsResizeFrame);
    operationsResizeFrame = window.requestAnimationFrame(resizeOperationsGrid);
  }
  function initializeOperationsGrid() {
    const element = document.querySelector("[data-vcf-backup-operations-grid]");
    if (operationsInitialized || !element) return;
    operationsInitialized = true;
    const rowAction = (item) => openOperationStatus(item.operation_id);
    operationsGrid = window.AtlasoUiPatterns.createGrid({
      element,
      fallback: "[data-vcf-backup-operations-fallback]",
      status: document.querySelector("[data-vcf-backup-operations-status]"),
      pattern: "read-only",
      loadingMessage: "Loading recent VCF backup operations…",
      emptyMessage: "No backup operations have been recorded.",
      errorMessage: "The backup operation list could not be displayed. Refresh to retry.",
      onReady: () => { operationsGridReady = true; window.requestAnimationFrame(() => { resizeOperationsGrid(); loadOperations(false); }); },
      onOpenRow: (item) => rowAction(item),
      rowActions: [{label: "View status", action: (_event, row) => rowAction(row.getData())}],
      options: {
        data: [], index: "operation_id", layout: "fitColumns", responsiveLayout: "collapse",
        pagination: true, paginationSize: 25, selectableRows: 1,
        columns: [
          {title: "Created", field: "created_at", minWidth: 170, formatter: (cell) => operationCell(cell.getValue()), headerFilter: "input", headerFilterPlaceholder: "Filter date"},
          {title: "Operation", field: "operation_id", minWidth: 220, formatter: (cell) => operationCell(cell.getValue()), headerFilter: "input", headerFilterPlaceholder: "Filter operation"},
          {title: "Status", field: "state", minWidth: 150, formatter: (cell) => operationCell(operationStateLabel(cell.getValue())), headerFilter: "list", headerFilterParams: {values: {"": "All", queued: "Queued", running: "Running", needs_recovery: "Needs attention", succeeded: "Succeeded", reconciled: "Reconciled"}}, headerFilterFunc: "="},
          {title: "Components", field: "component_count", width: 125, formatter: (cell) => operationCell(cell.getValue(), "0"), headerFilter: "number", headerFilterPlaceholder: "Count", headerFilterParams: {min: 0, step: 1}, headerFilterFunc: "="},
          {title: "Sources", field: "sources", minWidth: 240, formatter: (cell) => operationCell(operationSourceSummary(cell.getValue())), headerFilter: "input", headerFilterPlaceholder: "Filter product or server", headerFilterFunc: (value, sources) => operationSourceSummary(sources).toLowerCase().includes(String(value).toLowerCase())},
        ],
      },
      permission: {allowed: true},
    });
    operationsGrid?.table?.on?.("rowClick", (_event, row) => rowAction(row.getData()));
    if (!operationsGrid?.table) operationsGrid?.setError?.("The backup operation list could not be initialized. Refresh to retry.");
    else {
      window.addEventListener("resize", scheduleOperationsResize);
      if (typeof ResizeObserver !== "undefined") {
        const observer = new ResizeObserver(scheduleOperationsResize);
        observer.observe(element.closest("[data-vcf-backup-operations-section]") || element);
      }
    }
  }
  const backupTab = document.getElementById("vcf-helper-backup");
  const backupTabButton = document.querySelector('[data-tab-target="vcf-helper-backup"]');
  const initializeVisibleOperationsGrid = () => {
    if (backupTab && !backupTab.hidden) { initializeOperationsGrid(); scheduleOperationsResize(); }
  };
  backupTabButton?.addEventListener("click", () => window.requestAnimationFrame(initializeVisibleOperationsGrid));
  if (backupTab && !backupTab.hidden) initializeOperationsGrid();
  document.querySelector("[data-vcf-backup-operations-refresh]")?.addEventListener("click", () => {
    operationsCursor = "";
    loadOperations(false);
  });
  document.querySelector("[data-vcf-backup-operations-more]")?.addEventListener("click", () => loadOperations(true));
  function clearManualPasswords() {
    inspectedSources.forEach(({request, credentialMode}) => {
      if (credentialMode === "manual") request.password = "";
    });
    node("[data-vcf-backup-recovery-credentials]")?.querySelectorAll("input[type='password']").forEach((input) => { input.value = ""; });
    field("password").value = "";
  }
  function openBackupConfiguration(launcher) {
    if (!receiverReady) return;
    invalidateStatusView();
    window.clearTimeout(pollTimer);
    clearManualPasswords();
    form.reset();
    grid?.table?.deselectRow?.();
    operationId = "";
    inspectionRevision = "";
    inspectedSources = [];
    components = [];
    receiver = null;
    operationStarted = false;
    operationState = "";
    canCloseWithoutCredentials = false;
    invalidateReview();
    resetCurrentSource();
    renderComponents();
    renderSourceSummaries();
    node("[data-vcf-backup-recovery-id]").value = "";
    node("[data-vcf-backup-recovery-credentials]").replaceChildren();
    node("[data-atlaso-wizard-submit]").disabled = false;
    node("[data-vcf-backup-task-link]").classList.add("hidden");
    wizard.open({launcher, step: "credential", highestStep: "credential"});
    setStatus("Choose credentials for a new backup configuration.");
  }
  function schedulePoll(delay) {
    window.clearTimeout(pollTimer);
    pollTimer = window.setTimeout(() => { if (statusDialog.open && operationId) pollOperation().catch(() => {}); }, delay);
  }
  function lockSubmitAfterOperation() {
    window.setTimeout(() => {
      if (operationStarted) node("[data-atlaso-wizard-submit]").disabled = true;
    }, 0);
  }
  async function pollOperation() {
    if (!operationId || busy || !statusDialog.open) return;
    const requestedId = operationId;
    const viewEpoch = statusViewEpoch;
    busy = true;
    try {
      const result = await call(`/operations/${encodeURIComponent(requestedId)}`);
      if (isCurrentStatusView(viewEpoch, requestedId)) renderOperation(result);
    }
    finally { if (statusViewEpoch === viewEpoch && operationId === requestedId) busy = false; }
  }
  async function reconcile() {
    if (!operationId || busy || !statusDialog.open) return;
    const requestedId = operationId;
    const viewEpoch = statusViewEpoch;
    const closeReviewed = field("close_recovery").checked;
    if (!(closeReviewed && canCloseWithoutCredentials) && inspectedSources.some(({request, credentialMode}) => credentialMode === "manual" && !request.password)) {
      renderRecoveryCredentials();
      setStatus("Enter the source password(s) required for read-only reconciliation, then choose Reconcile again.", true);
      return;
    }
    busy = true;
    try {
      const result = await call("/reconcile", {operation_id: requestedId, sources: inspectedSources.map(({request}) => request), close_reviewed: closeReviewed});
      if (!isCurrentStatusView(viewEpoch, requestedId)) return;
      renderOperation(result);
      if (["queued", "running"].includes(String(result.reconciliation_state || "").toLowerCase())) {
        clearManualPasswords();
        setStatus("Read-only reconciliation started. You can close this popup; native settings will not be changed.");
      } else if (String(result.reconciliation_state || "").toLowerCase() === "failed") {
        setStatus(result.reconciliation_error || "Read-only reconciliation failed.", true);
      } else setStatus("");
    }
    catch (error) {
      if (isCurrentStatusView(viewEpoch, requestedId)) throw error;
    }
    finally { if (statusViewEpoch === viewEpoch && operationId === requestedId) busy = false; }
  }
  async function inspectCurrentSource() {
    if (!validProbes()) throw new Error("Probe and explicitly confirm every required TLS fingerprint before inspecting this source.");
    const request = commonPayload();
    const result = await call("/inspect", request);
    operationId = result.operation_id || operationId;
    inspectionRevision = result.revision || inspectionRevision;
    if (!operationId) throw new Error("The inspection response did not include an operation reference.");
    receiver = result.receiver || receiver;
    const newItems = (result.components || []).map((item) => ({...item, source_id: item.source_id || result.source_id}));
    const signature = sourceSignature(request);
    const previousSources = inspectedSources.filter((item) => sourceSignature(item.request) === signature);
    inspectedSources = inspectedSources.filter((item) => sourceSignature(item.request) !== signature);
    const sourceRequest = {...request, source_id: result.source_id || ""};
    const sourceMetadata = (result.sources || []).find((item) => String(item.source_id) === String(result.source_id));
    inspectedSources.push({request: sourceRequest, credentialMode: request.credential_vault_id ? "vault" : "manual", summary: {source_kind: request.source_kind, address: request.address, port: request.port, source_id: result.source_id, service: sourceMetadata?.service || null}});
    const replacedSourceIds = new Set(previousSources.map((item) => String(item.summary?.source_id || "")));
    components = [...components.filter((item) => !replacedSourceIds.has(String(item.source_id || "")) && !newItems.some((incoming) => String(incoming.id) === String(item.id))), ...newItems];
    updateSourceFields();
    node("[data-vcf-backup-receiver]").textContent = `${receiver?.host || ""}:${receiver?.port || ""} · ${receiver?.username || ""}${receiver?.directory || ""}`;
    node("[data-vcf-backup-host-key]").textContent = safeText(receiver?.ecdsa_fingerprint);
    const blockers = result.coverage_gaps || [];
    node("[data-vcf-backup-discovery-blockers]").textContent = blockers.map(coverageText).join("; ");
    node("[data-vcf-backup-discovery-blockers]").classList.toggle("hidden", !blockers.length);
    renderComponents(); renderSourceSummaries(); invalidateReview();
    field("username").value = "";
    field("password").value = "";
    setStatus(`Discovered ${newItems.length} component(s). Select components to continue.`);
    return result;
  }
  function resetCurrentSource() {
    mode.value = "manual"; mode.dispatchEvent(new Event("change", {bubbles: true}));
    sourceKind.value = "fleet"; field("address").value = ""; field("port").value = "443";
    field("username").value = ""; field("password").value = "";
    vaultSelect.value = ""; fillVaultEntries(); updateCredentialMode(); updateSourceFields();
    tlsFingerprints.server = "";
    const box = node('[data-vcf-backup-confirm="server"]'); if (box) { box.checked = false; box.disabled = true; }
    const text = node('[data-vcf-backup-fingerprint-value="server"]'); if (text) text.textContent = "Not checked";
  }
  function reviewPayload() {
    const secret = (name) => selectedSecret(name);
    return {
      operation_id: operationId,
      revision: inspectionRevision,
      sources: inspectedSources.map(({request}) => request),
      selected_ids: selectedComponentIds(),
      policy: policyPayload(),
      sftp_secret: secret("sftp_secret_ref"),
      encryption_secret: secret("encryption_secret_ref"),
    };
  }
  const stepIds = ["credential", "server", "fingerprint", "login", "discovery", "settings", "review"];
  const stepCopy = {
    credential: ["Choose credentials", "Select a saved Vault key or use a one-time manual login."],
      server: ["Select the VCF component", "Choose a component type and enter its server endpoint. VCF Operations discovers Fleet LCM automatically."],
      fingerprint: ["Confirm TLS identity", "Probe the server and compare its fingerprint with a trusted source."],
    login: ["Sign in to the appliance", "Manual credentials are submitted only after TLS confirmation."],
    discovery: ["Discover backup components", "Inspect supported components and select the exact targets."],
    settings: ["Set destination and schedule", "Choose stored secret references and review backup policy settings."],
    review: ["Review and configure", "Review exact current and proposed settings before starting the initial backup task."],
  };
  let wizard;
  wizard = window.AtlasoUiPatterns.createWizard({
    form, dialog, steps: stepIds.map((id) => ({id, title: stepCopy[id][0], description: stepCopy[id][1]})),
    validateStep: ({step}) => {
      if (step.id === "credential") return mode.value === "vault" ? Boolean(selectedVaultEntry()) : true;
      if (step.id === "server") return Boolean(field("address").value.trim() && Number(field("port").value) > 0);
      if (step.id === "fingerprint") return validProbes();
      if (step.id === "login") return Boolean(field("username").value.trim() && field("password").value);
      if (step.id === "discovery") return Boolean(inspectedSources.length && selectedComponentIds().length);
      if (step.id === "settings") return settingsAreValid();
      if (step.id === "review") return Boolean(reviewToken && field("recovery_ready").checked && field("replacements_confirmed").checked && field("acknowledged").checked);
      return true;
    },
    onOpen: async () => {
      setError(""); setStatus("Credentials and TLS confirmations stay in this open wizard only.");
      updateCredentialMode(); updateSourceFields();
      syncOperationView();
    },
    onStepChange: ({step}) => {
      const body = node(".vcf-sddc-wizard-body");
      if (body?.scrollTo) body.scrollTo({top: 0});
      else if (body) body.scrollTop = 0;
      if (step.id === "discovery") renderComponents();
      syncOperationView();
      if (!operationStarted) setStatus("");
    },
    onNext: async ({step}) => {
      if (step.id === "server") {
        tlsFingerprints.server = "";
        const checkbox = node('[data-vcf-backup-confirm="server"]'); if (checkbox) { checkbox.checked = false; checkbox.disabled = true; }
        try { await probeTargets(); return "fingerprint"; } catch (error) { setError(error.message); return false; }
      }
      if (step.id === "login") {
        try { await inspectCurrentSource(); return "discovery"; } catch (error) { setError(error.message); return false; }
      }
      if (step.id === "fingerprint" && mode.value === "vault") {
        try { await inspectCurrentSource(); return "discovery"; } catch (error) { setError(error.message); return false; }
      }
      if (step.id === "discovery" && inspectedSources.length) return "settings";
      if (step.id === "settings") {
        if (!selectedComponentIds().length) { setError("Select at least one discovered component."); return false; }
        try {
          invalidateReview();
          const result = await call("/review", reviewPayload());
          inspectionRevision = result.revision || inspectionRevision;
          reviewToken = result.review_token || ""; review = result.review || null;
          if (!reviewToken || !review) throw new Error("The review response did not include its exact review and token.");
          renderReview();
          return "review";
        } catch (error) { setError(error.message); return false; }
      }
      return true;
    },
    onSubmit: async () => {
      if (!reviewToken) return {ok: false, message: "Build a fresh exact review before configuring backups."};
      setError("");
      const submittedReviewToken = reviewToken;
      reviewToken = "";
      try {
        const result = await call("/execute", {...reviewPayload(), review_token: submittedReviewToken, acknowledged: field("acknowledged").checked, replacements_confirmed: field("replacements_confirmed").checked, recovery_ready: field("recovery_ready").checked});
        if (!result.operation_id) throw new Error("The execute response did not include operation status.");
        operationId = result.operation_id || operationId;
        operationStarted = true;
        syncOperationView();
        lockSubmitAfterOperation();
        wizard.markClean();
        wizard.close("submit");
        showStatusDialog();
        renderOperation(result);
        if (operationsGrid) loadOperations(false).catch(() => {});
        return {ok: true, close: false};
      } catch (error) {
        const outcomeMayBeUnknown = !error.status || error.status >= 500 || [408, 429].includes(error.status);
        if (!outcomeMayBeUnknown) return {ok: false, message: error.message};
        operationStarted = true;
        syncOperationView();
        wizard.markClean();
        wizard.close("submit");
        showStatusDialog();
        renderOperation({operation_id: operationId, state: "needs_recovery", error: error.message});
        try { renderOperation(await call(`/operations/${encodeURIComponent(operationId)}`)); } catch { /* Keep the recovery action available when status is temporarily unreachable. */ }
        lockSubmitAfterOperation();
        if (operationsGrid) loadOperations(false).catch(() => {});
        return {ok: true, close: false};
      }
    },
    closeOnSubmit: false,
  });
  mode?.addEventListener("change", updateCredentialMode);
  vaultSelect?.addEventListener("change", () => { fillVaultEntries(); invalidateReview(); });
  entrySelect?.addEventListener("change", () => {
    updateSourceFields(); invalidateReview(); tlsFingerprints.server = "";
    const checkbox = node('[data-vcf-backup-confirm="server"]'); if (checkbox) { checkbox.checked = false; checkbox.disabled = true; }
  });
  sourceKind?.addEventListener("change", () => { updateSourceFields(); invalidateReview(); });
  form.addEventListener("input", (event) => {
    if (event.target.matches("[name='address'],[name='port']")) {
      invalidateReview(); tlsFingerprints.server = "";
      const checkbox = node('[data-vcf-backup-confirm="server"]'); if (checkbox) { checkbox.checked = false; checkbox.disabled = true; }
    } else if (event.target.matches("[name='username'],[name='password']")) invalidateReview();
    else if (event.target.closest("[data-atlaso-wizard-step='settings']")) invalidateReview();
  });
  form.addEventListener("change", (event) => {
    if (event.target.matches("[data-vcf-backup-confirm]")) invalidateReview();
    if (event.target.matches("[name='source_kind']")) {
      updateSourceFields(); invalidateReview(); tlsFingerprints.server = "";
      const checkbox = node('[data-vcf-backup-confirm="server"]'); if (checkbox) { checkbox.checked = false; checkbox.disabled = true; }
    }
    if (event.target.closest("[data-atlaso-wizard-step='settings']")) {
      updateSourceFields();
      invalidateReview();
    }
  });
  form.addEventListener("click", (event) => {
    const probeButton = event.target.closest("[data-vcf-backup-probe]");
    if (probeButton) {
      event.preventDefault();
      probeTargets().catch((error) => setError(error.message));
      return;
    }
    if (event.target.closest("[data-vcf-backup-inspect]")) {
      event.preventDefault();
      inspectCurrentSource().catch((error) => setError(error.message));
      return;
    }
    if (event.target.closest("[data-vcf-backup-add-source]")) {
      event.preventDefault();
      resetCurrentSource();
      updateCredentialMode();
      wizard.setHighestStep("fingerprint");
      wizard.showStep("credential", {unlock: true});
      setStatus("Add another source. Previously inspected source inputs remain only in this open wizard.");
      return;
    }
  });
  statusDialog.addEventListener("click", (event) => {
    if (event.target.closest("[data-vcf-backup-reconcile]")) {
      event.preventDefault();
      const requestedId = operationId;
      const viewEpoch = statusViewEpoch;
      reconcile().catch((error) => {
        if (!isCurrentStatusView(viewEpoch, requestedId)) return;
        setStatus(error.message, true);
        const panelError = node("[data-vcf-backup-operation-error]");
        if (panelError) { panelError.textContent = error.message; panelError.classList.remove("hidden"); }
      });
    }
    if (event.target.closest("[data-vcf-backup-load-operation]")) {
      event.preventDefault(); loadOperation().catch((error) => setStatus(error.message, true));
    }
    if (event.target.closest("[data-vcf-backup-status-close]")) {
      event.preventDefault(); statusDialog.close();
    }
  });
  node('[data-vcf-backup-confirm="server"]')?.addEventListener("change", invalidateReview);
  document.querySelector("[data-vcf-backup-open]")?.addEventListener("click", (event) => {
    if (!event.currentTarget.disabled) openBackupConfiguration(event.currentTarget);
  });
  document.querySelector("[data-vcf-backup-resume]")?.addEventListener("click", (event) => {
    openOperationStatus(operationStarted && operationId ? operationId : "");
  });
  statusDialog.addEventListener("close", () => {
    if (!statusDialog.open) invalidateStatusView();
    window.clearTimeout(pollTimer); pollTimer = null;
    clearManualPasswords();
  });
  dialog.addEventListener("close", () => {
    window.clearTimeout(pollTimer); pollTimer = null;
    clearManualPasswords();
    invalidateReview();
    if (!operationId) { inspectedSources = []; components = []; receiver = null; }
  });
  fillVaultEntries(); updateCredentialMode(); updateSourceFields();
})();

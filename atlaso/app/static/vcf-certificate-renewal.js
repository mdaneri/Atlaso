/* VCF Helper renewal UI. The shared grid and wizard own collection and step behavior. */
(() => {
  "use strict";

  const root = document.querySelector("[data-vcf-renewal-root]");
  if (!root || root.dataset.admin !== "true" || !window.AtlasoUiPatterns) return;

  const panel = document.getElementById("vcf-helper-certificates");
  const tab = document.getElementById("vcf-helper-certificates-tab");
  const endpoint = root.dataset.endpoint;
  const csrf = root.dataset.csrf || "";
  const message = root.querySelector("[data-vcf-renewal-message]");
  const taskLink = root.querySelector("[data-vcf-renewal-task]");
  const gridElement = document.getElementById("vcf-renewal-grid");
  let state = { connections: [], profiles: [], inventory: [], policies: [] };
  let refreshTimer = null;
  let refreshBusy = false;
  let selectedPolicyId = "";
  let reviewOperationId = "";
  let reviewToken = "";
  let reviewRevision = 0;

  const text = (value, empty = "Not recorded") => value === null || value === undefined || value === "" ? empty : String(value);
  const safeCell = (value, empty = "Not recorded") => {
    const span = document.createElement("span");
    span.textContent = text(value, empty);
    return span;
  };
  const setMessage = (value, isError = false) => {
    message.textContent = value;
    message.classList.remove("hidden");
    message.dataset.state = isError ? "error" : "ready";
    message.classList.toggle("error", isError);
    message.setAttribute("role", isError ? "alert" : "status");
  };
  const isVisible = () => Boolean(panel && !panel.hidden && document.visibilityState !== "hidden");

  async function call(path, body) {
    const response = await fetch(`${endpoint}${path}`, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: body === undefined ? {} : { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let result;
    try { result = await response.json(); } catch { result = {}; }
    if (!response.ok) {
      const error = new Error(typeof result.detail === "string" ? result.detail : "The certificate renewal request could not complete.");
      error.status = response.status;
      throw error;
    }
    return result;
  }

  const connectionById = (id) => state.connections.find((item) => String(item.id) === String(id));
  const policyByTarget = new Map();
  const targetKey = (connectionId, certificateId) => `${connectionId}\u0000${certificateId}`;
  function rowRecords() {
    policyByTarget.clear();
    for (const policy of state.policies || []) policyByTarget.set(targetKey(policy.connection_id, policy.certificate_id), policy);
    return (state.inventory || []).map((item) => {
      const policy = policyByTarget.get(targetKey(item.connection_id, item.certificate_id));
      const connection = connectionById(item.connection_id);
      return {
        ...item,
        connection_name: connection?.name || item.connection_id,
        enrolled: Boolean(policy),
        enabled: Boolean(policy?.enabled),
        threshold_days: policy?.threshold_days ?? 30,
        proposal_state: policy?.proposal_state || "None",
        operation_id: policy?.operation_id || "",
        job_id: policy?.job_id || "",
        policy_id: policy?.id || "",
        last_check_at: policy?.last_check_at || "",
        next_check_at: policy?.next_check_at || "",
      };
    });
  }

  const rows = rowRecords();
  const rowAction = (label, action, disabled = () => false) => ({
    label,
    disabled: (row) => disabled(row?.getData?.() || {}),
    action: (_event, row) => action(row?.getData?.() || {}),
  });

  let grid;
  grid = window.AtlasoUiPatterns.createGrid({
    element: gridElement,
    fallback: "#vcf-renewal-fallback",
    status: root.querySelector("[data-vcf-renewal-grid-status]"),
    pattern: "read-only",
    emptyMessage: "No VCF-managed vCenter Machine SSL certificates were discovered.",
    loadingMessage: "Loading saved renewal state…",
    errorMessage: "The renewal inventory could not be displayed. Refresh to retry.",
    pinRowsLast: false,
    options: {
      data: rows,
      layout: "fitColumns",
      responsiveLayout: "collapse",
      pagination: true,
      paginationSize: 20,
      columns: [
        { title: "Target", field: "host", minWidth: 180, formatter: (cell) => safeCell(cell.getValue()) },
        { title: "Issuer", field: "issuer", minWidth: 160, formatter: (cell) => safeCell(cell.getValue()) },
        { title: "Expiry", field: "expiry", minWidth: 150, formatter: (cell) => safeCell(cell.getValue()) },
        { title: "Eligibility", field: "eligible", minWidth: 190, formatter: (cell) => {
          const item = cell.getRow().getData();
          return safeCell(item.eligible ? "Eligible" : `Not eligible — ${text(item.reason, "reason not recorded")}`);
        } },
        { title: "Enrollment / proposal", field: "proposal_state", minWidth: 180, formatter: (cell) => {
          const item = cell.getRow().getData();
          return safeCell(`${item.enrolled ? (item.enabled ? "Enabled" : "Disabled") : "Not enrolled"} · ${text(item.proposal_state, "None")}`);
        } },
        { title: "Last check", field: "last_check_at", minWidth: 150, formatter: (cell) => safeCell(cell.getValue()) },
        { title: "Next check", field: "next_check_at", minWidth: 150, formatter: (cell) => safeCell(cell.getValue()) },
        { title: "Native Auto Renewal", field: "native_auto_renewal", minWidth: 170, formatter: (cell) => safeCell(cell.getValue(), "Not reported by VCF") },
        { title: "Task history", field: "job_id", minWidth: 130, headerSort: false, formatter: (cell) => {
          const id = cell.getValue();
          if (!id) return safeCell("No task recorded");
          const link = document.createElement("a");
          link.href = `${root.dataset.tasksRoot}?job_id=${encodeURIComponent(String(id))}`;
          link.textContent = "Open task";
          return link;
        } },
      ],
    },
    rowActions: [
      rowAction("Check now", (item) => runAction("check", { policy_id: item.policy_id }), (item) => !item.policy_id || !item.enabled),
      rowAction("Enroll / Edit policy", (item) => openPolicy(item)),
      rowAction("Prepare renewal", (item) => openPrepare(item), (item) => !item.policy_id || !item.enabled || !item.eligible || item.proposal_state !== "proposal"),
      rowAction("Review replacement", (item) => openReview(item), (item) => !item.operation_id || item.proposal_state !== "prepared"),
      rowAction("Reconcile status", (item) => runAction("reconcile", { operation_id: item.operation_id }), (item) => !item.operation_id || item.proposal_state !== "needs_recovery"),
    ],
    permission: { allowed: true },
  });

  function updateGrid() {
    const data = rowRecords();
    if (!grid?.table) return;
    if (grid?.table?.setData) grid.table.setData(data);
    else if (grid?.table?.replaceData) grid.table.replaceData(data);
    if (gridElement) gridElement.classList.remove("hidden");
    document.getElementById("vcf-renewal-fallback")?.classList.add("hidden");
    grid?.setState?.(data.length ? "ready" : "empty");
  }

  async function loadState({ discover = false } = {}) {
    if (refreshBusy) return;
    refreshBusy = true;
    grid?.setState?.("loading", "Loading renewal inventory…");
    try {
      const previousInventory = state.inventory || [];
      state = await call("/state");
      state.connections ||= [];
      state.profiles ||= [];
      state.inventory ||= [];
      state.policies ||= [];
      if (!discover) {
        const recorded = new Set(state.inventory.map((item) => targetKey(item.connection_id, item.certificate_id)));
        state.inventory.push(...previousInventory.filter((item) => connectionById(item.connection_id) && !recorded.has(targetKey(item.connection_id, item.certificate_id))));
      }
      if (discover) {
        for (const connection of state.connections) {
          const result = await call("/inventory", { connection_id: connection.id });
          const inventory = Array.isArray(result) ? result : result.inventory;
          if (Array.isArray(inventory)) {
            state.inventory = state.inventory.filter((item) => String(item.connection_id) !== String(connection.id)).concat(inventory);
          }
        }
      }
      updateGrid();
      if (!state.connections.length) setMessage("Connect a VCF Operations endpoint to load certificate inventory.");
      else if (!state.inventory.length) setMessage("No inventory is recorded yet. Refresh inventory to discover vCenter Machine SSL targets.");
      else setMessage(`Loaded ${state.inventory.length} certificate inventory record${state.inventory.length === 1 ? "" : "s"}.`);
      return state;
    } catch (error) {
      grid?.setError?.(error.message || "The certificate renewal state could not be loaded.");
      setMessage(error.message || "The certificate renewal state could not be loaded.", true);
      throw error;
    } finally {
      refreshBusy = false;
    }
  }

  function showTask(id) {
    if (!taskLink) return;
    if (!id) {
      taskLink.classList.add("hidden");
      taskLink.removeAttribute("href");
      return;
    }
    taskLink.href = `${root.dataset.tasksRoot}?job_id=${encodeURIComponent(String(id))}`;
    taskLink.textContent = "Open task details";
    taskLink.classList.remove("hidden");
  }

  async function runAction(action, values) {
    try {
      const result = await call(`/${action}`, values);
      showTask(result.job_id || result.task_id);
      setMessage(result.message || `${action.replaceAll("_", " ")} request accepted. Review task details for progress.`);
      await loadState();
      return result;
    } catch (error) {
      setMessage(error.message || "The renewal action could not complete.", true);
      return null;
    }
  }

  const connectDialog = document.getElementById("vcf-renewal-connection-dialog");
  const connectForm = connectDialog?.querySelector("[data-vcf-renewal-connection-form]");
  const connectField = (name) => connectForm?.elements.namedItem(name);
  const connectFingerprint = connectDialog?.querySelector("[data-vcf-renewal-fingerprint]");
  const connectProbe = connectDialog?.querySelector("[data-vcf-renewal-probe]");
  const connectCredentialStatus = connectForm?.querySelector("[data-vcf-credential-status]");
  let observedFingerprint = "";
  let fingerprintRevision = 0;
  const updateConnectCredentialStatus = () => {
    if (!connectCredentialStatus) return;
    const selected = connectField("credential_vault_id")?.value && connectField("credential_entry_id")?.value;
    connectCredentialStatus.textContent = selected
      ? "Saved Vault credential selected. Its password stays on the server."
      : "Choose a saved HTTP/HTTPS Vault credential. Manual credentials are not available for scheduled renewal.";
  };
  const connectionWizard = connectForm ? window.AtlasoUiPatterns.createWizard({
    form: connectForm,
    dialog: connectDialog,
    steps: [
      { id: "credential", title: "Choose a saved Vault credential", description: "Scheduled checks use only the saved credential reference." },
      { id: "server", title: "Identify VCF Operations", description: "Review the endpoint filled from the selected Vault URI." },
      { id: "fingerprint", title: "Confirm TLS identity", description: "Verify the exact observed endpoint fingerprint out of band." },
    ],
    validateStep: ({ step }) => {
      if (step.id === "credential" && !(connectField("credential_vault_id")?.value && connectField("credential_entry_id")?.value)) return { valid: false, message: "Choose a saved Vault entry with an HTTP or HTTPS endpoint for scheduled use.", field: connectField("credential_vault_id")?.value ? "credential_entry_id" : "credential_vault_id" };
      if (step.id === "fingerprint" && !observedFingerprint) return { valid: false, message: "Read the endpoint fingerprint before confirming the connection identity.", field: connectProbe };
      if (step.id === "fingerprint" && !connectField("confirm_fingerprint")?.checked) return { valid: false, message: "Confirm the observed endpoint fingerprint against a trusted source before saving.", field: "confirm_fingerprint" };
      if (step.id === "server" && !(connectField("name")?.value.trim() && connectField("address")?.value.trim() && Number(connectField("port")?.value) >= 1 && Number(connectField("port")?.value) <= 65535)) return { valid: false, message: "Review the connection name and the valid server address and port filled from the selected Vault URI.", field: !connectField("name")?.value.trim() ? "name" : !connectField("address")?.value.trim() ? "address" : "port" };
      return true;
    },
    onOpen: () => {
      invalidateFingerprint();
      window.setTimeout(updateConnectCredentialStatus, 0);
    },
    onSubmit: async () => {
      const body = {
        name: connectField("name").value.trim(),
        address: connectField("address").value.trim(),
        port: Number(connectField("port").value),
        confirmed_tls_fingerprint: observedFingerprint,
        credential_vault_id: connectField("credential_vault_id").value,
        credential_entry_id: connectField("credential_entry_id").value,
      };
      const result = await call("/save_connection", body);
      setMessage("VCF Operations connection saved. Discovering certificate inventory…");
      showTask(result.job_id || result.task_id);
      await loadState({ discover: true });
      return { close: true };
    },
  }) : null;

  function invalidateFingerprint() {
    fingerprintRevision += 1;
    observedFingerprint = "";
    if (connectFingerprint) connectFingerprint.textContent = "Not checked";
    const confirm = connectField("confirm_fingerprint");
    if (confirm) confirm.checked = false;
  }
  ["address", "port", "credential_vault_id", "credential_entry_id"].forEach((name) => {
    connectField(name)?.addEventListener("input", invalidateFingerprint);
    connectField(name)?.addEventListener("change", invalidateFingerprint);
  });
  ["credential_vault_id", "credential_entry_id"].forEach((name) => connectField(name)?.addEventListener("change", () => window.setTimeout(updateConnectCredentialStatus, 0)));
  connectProbe?.addEventListener("click", async () => {
    connectProbe.disabled = true;
    invalidateFingerprint();
    const probeRevision = fingerprintRevision;
    try {
      const address = connectField("address").value.trim();
      const port = Number(connectField("port").value);
      if (!address || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Choose a saved endpoint with a valid server address and port first.");
      const result = await call("/probe", { address, port });
      if (probeRevision !== fingerprintRevision) {
        connectionWizard.setError("The endpoint or saved Vault credential changed during the probe. Read the fingerprint again.");
        return;
      }
      observedFingerprint = String(result.fingerprint || "");
      connectFingerprint.textContent = observedFingerprint || "Fingerprint was not returned.";
      if (!observedFingerprint) throw new Error("VCF Operations did not return a TLS fingerprint.");
    } catch (error) {
      connectFingerprint.textContent = "Probe failed";
      connectionWizard.setError(error.message || "TLS fingerprint probe failed.");
    } finally {
      connectProbe.disabled = false;
    }
  });
  connectDialog?.addEventListener("close", () => {
    invalidateFingerprint();
    connectionWizard?.reset();
  });

  const policyDialog = document.getElementById("vcf-renewal-policy-dialog");
  const policyForm = policyDialog?.querySelector("[data-vcf-renewal-policy-form]");
  const policyField = (name) => policyForm?.elements.namedItem(name);
  const policyConnection = policyField("connection_id");
  const policyCertificate = policyField("certificate_id");
  const policyProfile = policyField("profile_id");
  const targetFingerprint = policyDialog?.querySelector("[data-vcf-renewal-target-fingerprint]");
  const targetHost = policyDialog?.querySelector("[data-vcf-renewal-target-host]");
  const healthCredentialStatus = policyDialog?.querySelector("[data-vcf-credential-status]");
  const updateHealthCredentialStatus = () => {
    if (!healthCredentialStatus) return;
    const selected = policyField("health_credential_vault_id")?.value && policyField("health_credential_entry_id")?.value;
    healthCredentialStatus.textContent = selected
      ? "Saved vCenter health credential selected. The backend verifies its endpoint matches the target host."
      : "Choose a saved HTTP/HTTPS credential for read-only checks. Manual credentials are not available here.";
  };
  const cronExpression = policyField("cron_expression");
  const cronFrequency = policyDialog?.querySelector("[data-automation-cron-frequency]");
  const cronMinute = policyDialog?.querySelector("[data-automation-cron-minute]");
  const cronTime = policyDialog?.querySelector("[data-automation-cron-time]");
  const cronWeekday = policyDialog?.querySelector("[data-automation-cron-weekday]");
  const cronMonthday = policyDialog?.querySelector("[data-automation-cron-monthday]");
  const cronCustom = policyDialog?.querySelector("[data-automation-cron-custom]");
  const cronSummary = policyDialog?.querySelector("[data-automation-cron-summary]");
  const cronPreview = policyDialog?.querySelector("[data-automation-cron-preview]");
  function addOption(select, value, label) {
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = text(label);
    select.append(option);
  }
  function fillCertificateOptions(connectionId, selectedId = "") {
    policyCertificate.replaceChildren();
    addOption(policyCertificate, "", "Choose a vCenter Machine SSL target");
    for (const item of state.inventory.filter((row) => String(row.connection_id) === String(connectionId))) {
      addOption(policyCertificate, item.certificate_id, `${text(item.host)} · expires ${text(item.expiry)}`);
    }
    policyCertificate.value = String(selectedId || "");
    const selectedTarget = state.inventory.find((row) => String(row.connection_id) === String(connectionId) && String(row.certificate_id) === String(selectedId));
    if (targetHost) targetHost.textContent = text(selectedTarget?.host, "Choose a target first.");
    if (targetFingerprint) targetFingerprint.textContent = text(selectedTarget?.fingerprint, "Target fingerprint unavailable; refresh inventory first.");
    policyField("confirm_target_fingerprint").checked = false;
  }
  function fillPolicyChoices(selected = {}) {
    policyConnection.replaceChildren();
    addOption(policyConnection, "", "Choose a VCF connection");
    for (const item of state.connections) addOption(policyConnection, item.id, item.name);
    policyProfile.replaceChildren();
    addOption(policyProfile, "", "Choose an enabled Atlaso CA profile");
    for (const item of state.profiles) addOption(policyProfile, item.id, item.name);
    policyConnection.value = String(selected.connection_id || "");
    fillCertificateOptions(policyConnection.value, selected.certificate_id);
    policyProfile.value = String(selected.profile_id || "");
    policyField("health_credential_vault_id").value = String(selected.health_credential_vault_id || "");
    policyField("health_credential_entry_id").value = String(selected.health_credential_entry_id || "");
    policyField("confirm_target_fingerprint").checked = false;
    targetFingerprint.textContent = text(selected.fingerprint, "Target fingerprint unavailable; refresh inventory first.");
    targetHost.textContent = text(selected.host, "Choose a target first.");
    window.setTimeout(updateHealthCredentialStatus, 0);
  }

  function updateCronBuilder() {
    if (!cronFrequency || !cronExpression) return;
    const frequency = cronFrequency.value;
    policyDialog.querySelectorAll("[data-automation-cron-control]").forEach((element) => {
      const kind = element.getAttribute("data-automation-cron-control");
      const visible = kind === frequency || (kind === "time" && ["daily", "weekly", "monthly"].includes(frequency));
      element.classList.toggle("hidden", !visible);
      element.querySelectorAll("input,select").forEach((input) => { input.required = visible; });
    });
    const timezone = String(policyField("timezone_name").value || "UTC");
    const [hour = "2", minute = "0"] = String(cronTime?.value || "02:00").split(":");
    const hourValue = String(Number(hour));
    let minuteValue = String(Number(minute));
    const timeLabel = `${hour.padStart(2, "0")}:${minute.padStart(2, "0")}`;
    let expression = "0 2 * * *";
    let summary = `Every day at ${timeLabel} ${timezone}`;
    if (frequency === "hourly") {
      minuteValue = String(Number(cronMinute?.value || 0));
      expression = `${minuteValue} * * * *`;
      summary = `Every hour at minute ${minuteValue} · ${timezone}`;
    } else if (frequency === "daily") {
      expression = `${minuteValue} ${hourValue} * * *`;
    } else if (frequency === "weekly") {
      const weekday = String(cronWeekday?.value || "1");
      const names = { "0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday", "4": "Thursday", "5": "Friday", "6": "Saturday" };
      expression = `${minuteValue} ${hourValue} * * ${weekday}`;
      summary = `Every ${names[weekday]} at ${timeLabel} ${timezone}`;
    } else if (frequency === "monthly") {
      const monthday = String(Number(cronMonthday?.value || 1));
      expression = `${minuteValue} ${hourValue} ${monthday} * *`;
      summary = `Every month on day ${monthday} at ${timeLabel} ${timezone}`;
    } else {
      expression = String(cronCustom?.value || "").trim();
      summary = `Custom schedule in ${timezone}`;
    }
    cronExpression.value = expression;
    cronSummary.textContent = summary;
    cronPreview.textContent = expression;
  }

  function loadCronBuilder(rawExpression) {
    const expression = String(rawExpression || "0 2 * * *").trim();
    const fields = expression.split(/\s+/);
    const numeric = (value, minimum, maximum) => /^\d+$/.test(value) && Number(value) >= minimum && Number(value) <= maximum;
    let frequency = "custom";
    if (fields.length === 5 && numeric(fields[0], 0, 59) && fields.slice(1).every((value) => value === "*")) {
      frequency = "hourly";
      cronMinute.value = fields[0];
    } else if (fields.length === 5 && numeric(fields[0], 0, 59) && numeric(fields[1], 0, 23) && fields[2] === "*" && fields[3] === "*" && fields[4] === "*") {
      frequency = "daily";
    } else if (fields.length === 5 && numeric(fields[0], 0, 59) && numeric(fields[1], 0, 23) && fields[2] === "*" && fields[3] === "*" && numeric(fields[4], 0, 6)) {
      frequency = "weekly";
      cronWeekday.value = fields[4];
    } else if (fields.length === 5 && numeric(fields[0], 0, 59) && numeric(fields[1], 0, 23) && numeric(fields[2], 1, 31) && fields[3] === "*" && fields[4] === "*") {
      frequency = "monthly";
      cronMonthday.value = fields[2];
    }
    if (frequency === "daily" || frequency === "weekly" || frequency === "monthly") {
      cronTime.value = `${fields[1].padStart(2, "0")}:${fields[0].padStart(2, "0")}`;
    } else if (frequency === "custom") {
      cronCustom.value = expression;
    }
    cronFrequency.value = frequency;
    updateCronBuilder();
  }
  [cronFrequency, cronMinute, cronTime, cronWeekday, cronMonthday, cronCustom].forEach((control) => {
    control?.addEventListener("input", updateCronBuilder);
    control?.addEventListener("change", updateCronBuilder);
  });
  policyField("timezone_name")?.addEventListener("input", updateCronBuilder);
  policyField("timezone_name")?.addEventListener("change", updateCronBuilder);
  ["health_credential_vault_id", "health_credential_entry_id"].forEach((name) => policyField(name)?.addEventListener("change", () => window.setTimeout(updateHealthCredentialStatus, 0)));
  policyConnection?.addEventListener("change", () => fillCertificateOptions(policyConnection.value));
  policyCertificate?.addEventListener("change", () => {
    const selectedTarget = state.inventory.find((row) => String(row.connection_id) === String(policyConnection.value) && String(row.certificate_id) === String(policyCertificate.value));
    targetHost.textContent = text(selectedTarget?.host, "Choose a target first.");
    targetFingerprint.textContent = text(selectedTarget?.fingerprint, "Target fingerprint unavailable; refresh inventory first.");
    policyField("confirm_target_fingerprint").checked = false;
  });
  const policyWizard = policyForm ? window.AtlasoUiPatterns.createWizard({
    form: policyForm,
    dialog: policyDialog,
    steps: [
      { id: "target", title: "Choose target and CA profile", description: "Select a discovered target and enabled Atlaso CA profile." },
      { id: "target-health", title: "Confirm target health access", description: "Choose a saved vCenter health credential and independently confirm the observed TLS fingerprint." },
      { id: "policy", title: "Set renewal policy", description: "Set a daily discovery schedule and expiry threshold." },
    ],
    onOpen: ({ context }) => {
      const selected = context?.item || {};
      fillPolicyChoices(selected);
      policyField("policy_id").value = String(selected.policy_id || selected.id || "");
      policyField("enabled").checked = Boolean(selected.enabled);
      policyField("threshold_days").value = String(selected.threshold_days ?? 30);
      policyField("timezone_name").value = selected.timezone_name || "UTC";
      loadCronBuilder(selected.cron_expression || "0 2 * * *");
    },
    validateStep: ({ step }) => {
      if (step.id === "target" && !(policyConnection.value && policyCertificate.value && policyProfile.value)) return { valid: false, message: "Choose a VCF connection, discovered certificate target, and enabled Atlaso CA profile.", field: !policyConnection.value ? "connection_id" : !policyCertificate.value ? "certificate_id" : "profile_id" };
      if (step.id === "target-health" && !(policyField("health_credential_vault_id").value && policyField("health_credential_entry_id").value)) return { valid: false, message: "Choose a saved Vault credential for authenticated, read-only vCenter checks.", field: policyField("health_credential_vault_id").value ? "health_credential_entry_id" : "health_credential_vault_id" };
      if (step.id === "target-health" && (!targetFingerprint.textContent || targetFingerprint.textContent === "Target fingerprint unavailable; refresh inventory first.")) return { valid: false, message: "Refresh inventory to obtain the observed vCenter TLS fingerprint.", step: "target", field: "certificate_id" };
      if (step.id === "target-health" && !policyField("confirm_target_fingerprint").checked) return { valid: false, message: "Compare the observed target fingerprint with a trusted source and confirm it.", field: "confirm_target_fingerprint" };
      if (step.id === "policy" && !(Number(policyField("threshold_days").value) >= 1 && Number(policyField("threshold_days").value) <= 365)) return { valid: false, message: "Set an expiry threshold from 1 through 365 days.", field: "threshold_days" };
      if (step.id === "policy" && !(policyField("cron_expression").value.trim() && policyField("timezone_name").value.trim())) return { valid: false, message: "Choose a valid schedule and IANA timezone.", field: "timezone_name" };
      return true;
    },
    onSubmit: async () => {
      updateCronBuilder();
      const body = {
        connection_id: policyConnection.value,
        certificate_id: policyCertificate.value,
        profile_id: policyProfile.value,
        health_credential_vault_id: policyField("health_credential_vault_id").value,
        health_credential_entry_id: policyField("health_credential_entry_id").value,
        confirmed_target_tls_fingerprint: targetFingerprint.textContent,
        threshold_days: Number(policyField("threshold_days").value),
        enabled: policyField("enabled").checked,
        cron_expression: policyField("cron_expression").value.trim(),
        timezone_name: policyField("timezone_name").value.trim(),
      };
      if (policyField("policy_id").value) body.policy_id = policyField("policy_id").value;
      await call("/save_policy", body);
      await loadState();
      setMessage("Renewal policy saved. Scheduled checks will create proposals only.");
      return { close: true };
    },
  }) : null;
  policyDialog?.addEventListener("close", () => policyWizard?.reset());

  function openPolicy(item = {}) {
    if (!policyWizard) return;
    const current = { ...item, ...(policyByTarget.get(targetKey(item.connection_id, item.certificate_id)) || {}) };
    policyWizard.open({ launcher: document.activeElement, context: { item: current } }).catch((error) => setMessage(error.message, true));
  }

  const prepareDialog = document.getElementById("vcf-renewal-prepare-dialog");
  const prepareForm = prepareDialog?.querySelector("[data-vcf-renewal-prepare-form]");
  function openPrepare(item) {
    if (!item.policy_id) return;
    selectedPolicyId = String(item.policy_id);
    prepareForm.reset();
    prepareDialog.showModal();
    prepareForm.querySelector("[name='acknowledge_preparation']")?.focus();
  }

  const reviewDialog = document.getElementById("vcf-renewal-review-dialog");
  const reviewForm = reviewDialog?.querySelector("[data-vcf-renewal-review-form]");
  const reviewSummary = reviewDialog?.querySelector("[data-vcf-renewal-review-summary]");
  const reviewApprove = reviewForm?.querySelector("[type='submit']");
  function openReview(item) {
    if (!item.operation_id) return;
    const revision = ++reviewRevision;
    reviewOperationId = String(item.operation_id);
    reviewToken = "";
    reviewForm.reset();
    reviewApprove.disabled = true;
    reviewSummary.textContent = "Loading exact replacement details…";
    reviewDialog.showModal();
    call("/review", { operation_id: reviewOperationId }).then((result) => {
      if (revision !== reviewRevision || !reviewDialog.open) return;
      reviewToken = String(result.review_token || "");
      const summary = result.summary;
      reviewSummary.textContent = typeof summary === "string" ? summary : JSON.stringify(summary ?? {}, null, 2);
      if (!reviewToken) throw new Error("The review response did not include an approval token.");
    }).catch((error) => {
      if (revision !== reviewRevision || !reviewDialog.open) return;
      reviewSummary.textContent = "Review details could not be loaded.";
      const alert = reviewForm.querySelector("[data-vcf-renewal-dialog-error]");
      alert.textContent = error.message || "Review details could not be loaded.";
      alert.classList.remove("hidden");
    });
  }
  reviewForm?.querySelector("[name='approve_replacement']")?.addEventListener("change", (event) => {
    reviewApprove.disabled = !event.target.checked || !reviewToken;
  });
  reviewDialog?.addEventListener("close", () => {
    reviewRevision += 1;
    reviewToken = "";
    reviewOperationId = "";
    reviewSummary.textContent = "Review details have not been loaded.";
  });

  root.querySelector("[data-vcf-renewal-connect-open]")?.addEventListener("click", (event) => {
    connectionWizard?.open({ launcher: event.currentTarget }).catch((error) => setMessage(error.message, true));
  });
  root.querySelector("[data-vcf-renewal-refresh]")?.addEventListener("click", () => loadState({ discover: true }).catch(() => {}));
  prepareForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorNode = prepareForm.querySelector("[data-vcf-renewal-dialog-error]");
    errorNode.classList.add("hidden");
    try {
      const result = await call("/prepare", {
        policy_id: selectedPolicyId,
        acknowledge_preparation: prepareForm.elements.namedItem("acknowledge_preparation").checked,
        acknowledge_recovery: prepareForm.elements.namedItem("acknowledge_recovery").checked,
      });
      showTask(result.job_id || result.task_id);
      setMessage("Renewal preparation was queued. The target-owned CSR and issuance will be handled by the task.");
      prepareDialog.close();
      await loadState();
    } catch (error) {
      errorNode.textContent = error.message || "Renewal preparation could not start.";
      errorNode.classList.remove("hidden");
    }
  });
  reviewForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!reviewToken || !reviewForm.elements.namedItem("approve_replacement").checked) return;
    const errorNode = reviewForm.querySelector("[data-vcf-renewal-dialog-error]");
    errorNode.classList.add("hidden");
    try {
      const result = await call("/execute", { operation_id: reviewOperationId, review_token: reviewToken });
      reviewToken = "";
      showTask(result.job_id || result.task_id);
      setMessage("Reviewed replacement was submitted. Reconcile status and verify task results.");
      reviewDialog.close();
      await loadState();
    } catch (error) {
      reviewToken = "";
      reviewApprove.disabled = true;
      errorNode.textContent = error.message || "Replacement approval could not complete. Reopen the review to obtain a fresh approval.";
      errorNode.classList.remove("hidden");
    }
  });
  [prepareDialog, reviewDialog].forEach((dialog) => dialog?.querySelectorAll("[data-vcf-renewal-cancel]").forEach((button) => button.addEventListener("click", () => dialog.close())));

  function scheduleRefresh() {
    window.clearTimeout(refreshTimer);
    refreshTimer = null;
    if (!isVisible()) return;
    refreshTimer = window.setTimeout(() => {
      loadState().catch(() => {}).finally(scheduleRefresh);
    }, 30000);
  }
  function activateWorkspace() {
    if (!isVisible()) {
      window.clearTimeout(refreshTimer);
      refreshTimer = null;
      return;
    }
    loadState().catch(() => {}).finally(scheduleRefresh);
  }
  tab?.addEventListener("click", () => window.setTimeout(activateWorkspace, 0));
  tab?.closest?.(".vcf-helper-tabs")?.querySelectorAll("[data-tab-target]").forEach((button) => {
    if (button === tab) return;
    button.addEventListener("click", () => window.setTimeout(activateWorkspace, 0));
  });
  document.addEventListener("visibilitychange", activateWorkspace);
  if (isVisible()) activateWorkspace();
})();

/* Remote maintenance uses the shared wizard; manual credentials remain request-local. */
(() => {
  "use strict";
  const form = document.querySelector("[data-vcf-lab-form]");
  if (!form) return;
  const field = (name) => form.elements.namedItem(name);
  const node = (name) => form.querySelector(`[data-lab-${name}]`);
  const dialog = form.closest("dialog");
  let trust = null;
  let inspected = false;
  let token = null;
  let revision = 0;
  let busy = false;
  let submitted = false;
  const steps = [
    {id: "credential", title: "Choose separate credentials", description: "Use saved credentials or enter a one-time login after confirming target trust."},
    {id: "target", title: "Review the server", description: "Confirm the saved endpoint or enter the target hostname and SSH port."},
    {id: "trust", title: "Confirm target fingerprints", description: "Verify the SSH identity out of band before credentials are sent."},
    {id: "login", title: "Enter manual credentials", description: "Supply one-time vcf SSH and root credentials."},
    {id: "options", title: "Select property changes", description: "Inspect the actual property values, then edit the desired settings."},
    {id: "review", title: "Review the remote task", description: "Only the final submission can change properties and restart domainmanager."},
  ];
  const manual = () => field("credential_mode").value === "manual";
  const credentials = () => Object.fromEntries(["ssh", "root"].map((key) => [key, field(`${key}_password`).value]));
  function clearPasswords() { ["ssh", "root"].forEach((key) => { field(`${key}_password`).value = ""; }); }
  function modeChanged() {
    wizard.setSkippedSteps(manual() ? [] : ["login"]);
    ["ssh_password", "root_password"].forEach((name) => { field(name).disabled = !manual(); });
    node("saved").classList.toggle("hidden", manual());
    node("manual-server").classList.toggle("hidden", !manual());
    node("manual-login").classList.toggle("hidden", !manual());
    ["ssh_credential", "root_credential"].forEach((name) => { field(name).disabled = manual(); });
  }
  function inputs(withPasswords = true) {
    const selected = {};
    if (manual()) {
      Object.assign(selected, {credential_mode: "manual", host: field("host").value.trim(), ssh_port: Number(field("ssh_port").value)});
      if (withPasswords) selected.credentials = credentials();
    } else for (const [name, prefix] of [["ssh_credential", "ssh"], ["root_credential", "root"]]) {
      const pair = field(name).value.split(":").map(Number);
      if (pair.length !== 2 || pair.some((value) => !Number.isInteger(value) || value < 1)) throw new Error("Choose vcf SSH and separate root credentials.");
      selected[`${prefix}_entry_id`] = pair[0];
      selected[`${prefix}_uri_index`] = pair[1];
    }
    return {...selected, ssh_fingerprint: trust?.ssh_fingerprint || "",
      confirmed: field("confirmed").checked, desired: Object.fromEntries(["esa", "nic"].map((key) => [key, field(key).value === "absent" ? null : field(key).value]))};
  }
  async function call(path, body) {
    const response = await fetch(form.dataset.endpoint + path, {
      method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
      headers: body ? {"Content-Type": "application/json", "X-CSRF-Token": field("csrf").value} : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "The operation could not complete. Inspect the target and try again.");
    return result;
  }
  async function request(path, values) {
    if (busy) throw new Error("Wait for the current request to finish.");
    busy = true;
    const current = revision;
    try {
      const result = await call(path, values);
      if (current !== revision || !dialog.open) throw new Error("Inputs changed. Repeat inspection and review.");
      return result;
    } finally { busy = false; }
  }
  function invalidate() {
    revision += 1;
    token = null;
    field("acknowledged").checked = false;
  }
  async function probe() {
    invalidate();
    trust = null;
    inspected = false;
    field("confirmed").checked = false;
    const result = await request("/probe", inputs(false));
    trust = result;
    node("ssh").textContent = result.ssh_fingerprint;
  }
  async function inspect() {
    if (!trust || !field("confirmed").checked) throw new Error("Confirm target fingerprints first.");
    invalidate();
    inspected = false;
    const result = await request("/inspect", inputs());
    inspected = true;
    for (const key of ["esa", "nic"]) { field(key).value = result.values[key] ?? "absent"; node(`${key}-current`).textContent = result.values[key] ?? "Not configured"; }
    node("options").disabled = false;
    node("observed").textContent = `${result.target} · ${result.role} · VCF ${result.version}. ESA: ${result.values.esa ?? "absent"}; NIC: ${result.values.nic ?? "absent"}; domainmanager: ${result.service_active ? "active" : "not active"}.`;
  }
  const wizard = window.AtlasoUiPatterns.createWizard({
    form, dialog, steps, closeOnSubmit: false,
    async onOpen() {
      trust = null; inspected = false; submitted = false; clearPasswords(); modeChanged(); invalidate();
      node("options").disabled = true; node("ssh").textContent = "Not probed";
      node("observed").textContent = "Current properties have not been inspected.";
      node("status").textContent = "";
      node("task").hidden = true; node("task").classList.add("hidden");
      ["esa", "nic"].forEach((key) => { field(key).value = "absent"; node(`${key}-current`).textContent = "Not inspected"; });
    },
    onClose() { clearPasswords(); invalidate(); },
    validateStep({step}) {
      if (busy) return "Wait for the current request to finish.";
      if (submitted) return "This task is already queued. Open Tasks for progress and results, or reopen the wizard for another operation.";
      if (step.id === "credential" && !manual()) { inputs(false); }
      if (step.id === "target" && manual() && !field("host").value.trim()) return "Enter the target hostname or IP.";
      if (["trust", "login", "options", "review"].includes(step.id) && (!trust || !field("confirmed").checked)) return "Confirm the automatically probed SSH fingerprint before continuing.";
      if (step.id === "options" && !inspected) return {valid: false, message: "Verify login and inspect current properties before applying changes.", step: "options"};
      if (step.id === "review" && (!token || !field("acknowledged").checked)) return "Review the current changes and acknowledge the lab-only operation.";
      return true;
    },
    onStepChange({step}) {
      if (step.id === "trust" && !trust && !busy) {
        node("ssh").textContent = "Probing SSH identity…";
        probe().catch((error) => { node("ssh").textContent = "Probe failed. Go Back and return to retry."; wizard.setError(error.message); });
      }
      if (step.id === "target") {
        const select = field("ssh_credential");
        node("target").textContent = manual() ? "Enter the SSH hostname below." : select.selectedOptions[0]?.dataset.endpoint || "Choose a vcf SSH credential";
      }
    },
    async prepareReview() {
      try {
      if (!trust || !field("confirmed").checked) return "Confirm the SSH fingerprint again before review.";
      if (!inspected) return {valid: false, step: "options", message: "Inspect current properties first."};
      token = null;
      const result = await request("/review", inputs());
      token = result.token;
      field("acknowledged").checked = false;
      node("review-target").textContent = `Apply: ${result.target} · ${result.role} · VCF ${result.version}${result.identity_source ? ` (${result.identity_source})` : ""}`;
      node("changes").replaceChildren();
      result.changes.forEach((change) => {
        const item = document.createElement("li");
        item.textContent = `${change.key}: ${change.previous ?? "absent"} → ${change.value ?? "absent (remove managed property)"}`;
        node("changes").append(item);
      });
      node("restart").textContent = result.restart_required ? "domainmanager will restart. Property readback and service readiness will be checked." : "No property changes or service restart are required.";
      form.querySelector("[data-atlaso-wizard-submit]").textContent = "Apply reviewed changes";
      return true;
      } catch (error) { return {valid: false, message: error.message}; }
    },
    async onSubmit() {
      if (!token || submitted) return "Inspect and review again before submitting.";
      const result = await request("/execute", {token, acknowledged: true, ...(manual() ? {credentials: credentials()} : {})});
      submitted = true; clearPasswords(); invalidate();
      node("status").textContent = "Remote task queued. Tasks reports progress, property readback and service recovery separately.";
      node("task").href = `${form.dataset.tasksRoot}?job_id=${encodeURIComponent(result.job_id)}`;
      node("task").hidden = false; node("task").classList.remove("hidden"); node("task").focus();
      return {close: false};
    },
  });
  document.querySelector("[data-vcf-lab-open]")?.addEventListener("click", (event) => wizard.open({launcher: event.currentTarget}));
  form.querySelector('[data-lab-action="inspect"]').addEventListener("click", () => inspect().catch((error) => wizard.setError(error.message)));
  form.addEventListener("change", (event) => {
    if (event.target.name === "acknowledged") return;
    invalidate();
    if (event.target.name === "credential_mode") { clearPasswords(); modeChanged(); }
    if (["credential_mode", "host", "ssh_port", "ssh_credential", "root_credential"].includes(event.target.name)) {
      trust = null; inspected = false; field("confirmed").checked = false;
      node("ssh").textContent = "Not probed";
    }
    if (event.target.name === "confirmed") inspected = false;
    if (["ssh_password", "root_password"].includes(event.target.name)) inspected = false;
    node("options").disabled = !inspected;
  });
  form.addEventListener("input", (event) => {
    if (["ssh_password", "root_password", "host", "ssh_port"].includes(event.target.name)) {
      invalidate(); inspected = false;
      if (["host", "ssh_port"].includes(event.target.name)) { trust = null; field("confirmed").checked = false; }
    }
  });
  try {
    const vaults = JSON.parse(document.getElementById("vcf-vault-credential-options").textContent);
    vaults.forEach((vault) => vault.entries.forEach((entry) => (entry.uris || []).forEach((uri, index) => {
      if (!entry.username || !entry.has_value) return;
      let parsed;
      try { parsed = new URL(uri); } catch { return; }
      if (parsed.username || parsed.password) return;
      const name = ["ssh:", "sftp:"].includes(parsed.protocol) ? (entry.username === "vcf" ? "ssh_credential" : entry.username === "root" ? "root_credential" : null) : null;
      if (!name) return;
      const option = new Option(`${vault.name} / ${entry.key} · ${parsed.host}`, `${entry.id}:${index + 1}`);
      option.dataset.endpoint = parsed.host;
      field(name).add(option);
    })));
  } catch { node("status").textContent = "Vault credential choices are unavailable. Refresh to retry."; }
})();

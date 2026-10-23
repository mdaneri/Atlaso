/* Certificate replacement adapter; the shared Atlaso wizard owns navigation and focus. */
(() => {
  "use strict";
  const form = document.querySelector("[data-vcf-appliance-cert-form]");
  if (!form || !window.AtlasoUiPatterns) return;
  const field = (name) => form.elements.namedItem(name);
  const node = (name) => form.querySelector(`[data-cert-${name}]`);
  const dialog = form.closest("dialog");
  const steps = ["credential", "server", "fingerprint", "login", "target", "prepare", "review", "replace", "results"];
  let probe = null;
  let inspection = null;
  let operationId = null;
  let reviewToken = null;
  let busy = false;
  let pollTimer = null;
  let revision = 0;
  const operationStorageKey = "atlaso:vcf-helper:certificate-operation";
  const savedOperation = () => { try { return window.localStorage.getItem(operationStorageKey) || ""; } catch { return ""; } };
  const saveOperation = (value) => { try { if (value) window.localStorage.setItem(operationStorageKey, value); else window.localStorage.removeItem(operationStorageKey); } catch { /* The durable task remains available without browser storage. */ } };
  const manual = () => !field("credential_vault_id").value || !Array.from(field("credential_entry_id").options).some((option) => option.value);
  function message(text, error = false) {
    const target = node(error ? "error" : "status");
    target.textContent = text;
    target.classList.remove("hidden");
  }
  function clearMessage() { [node("error"), node("status")].forEach((item) => { item.textContent = ""; item.classList.add("hidden"); }); }
  function invalidate() {
    revision += 1; inspection = null; reviewToken = null;
    node("prerequisites").replaceChildren();
    if (operationId) message("Inputs changed. The existing task remains active; reconcile it before any new operation.", true);
  }
  function invalidateReview() { revision += 1; reviewToken = null; }
  function invalidateCredential() { revision += 1; inspection = null; reviewToken = null; }
  function invalidateEndpoint() { invalidate(); probe = null; field("confirmed").checked = false; node("fingerprint").textContent = "Not checked"; }
  function credentials() {
    const pair = [field("credential_vault_id").value, field("credential_entry_id").value];
    const payload = {product: field("product").value, address: field("address").value.trim(), port: Number(field("port").value), confirmed_tls_fingerprint: probe?.fingerprint || "", confirmed: field("confirmed").checked};
    if (pair[0] && pair[1]) Object.assign(payload, {credential_vault_id: pair[0], credential_entry_id: pair[1]});
    else Object.assign(payload, {username: field("username").value, password: field("password").value});
    return payload;
  }
  function targetFields() {
    return {common_name: field("common_name").value.trim(), dns_names: field("dns_names").value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean), ip_addresses: field("ip_addresses").value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean), profile_id: field("profile_id").value, recovery_reference: field("recovery_reference").value.trim()};
  }
  async function call(path, body) {
    const response = await fetch(`${form.dataset.endpoint}${path}`, {method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", headers: body ? {"Content-Type": "application/json", "X-CSRF-Token": field("csrf").value} : {}, body: body ? JSON.stringify(body) : undefined});
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "The certificate operation could not complete.");
    return result;
  }
  async function run(action) {
    if (busy) return;
    busy = true; clearMessage();
    const inputState = Array.from(form.querySelectorAll("input,select,textarea")).map((input) => [input, input.disabled]);
    inputState.forEach(([input]) => { input.disabled = true; });
    form.querySelectorAll("[data-cert-probe],[data-cert-inspect],[data-cert-prepare],[data-cert-review-action],[data-cert-execute],[data-cert-reconcile]").forEach((button) => { button.disabled = true; });
    try { await action(); } catch (error) { message(error.message || "The operation failed.", true); }
    finally {
      busy = false;
      inputState.forEach(([input, disabled]) => { input.disabled = disabled; });
      if (operationId) lockOperationFields(true);
      form.querySelectorAll("[data-cert-probe],[data-cert-inspect],[data-cert-prepare],[data-cert-review-action],[data-cert-execute],[data-cert-reconcile]").forEach((button) => {
        button.disabled = (button.matches("[data-cert-prepare]") && Boolean(operationId)) || (button.matches("[data-cert-execute]") && !reviewToken);
      });
    }
  }
  function paintList(container, rows) {
    container.replaceChildren();
    for (const row of rows) { const item = document.createElement("div"); const label = document.createElement("span"); const value = document.createElement("strong"); label.textContent = row[0]; value.textContent = row[1] ?? ""; item.append(label, value); container.append(item); }
  }
  function paintOperation(result) {
    const productLabel = result.product === "vcenter" ? "vCenter" : result.product === "sddc" ? "SDDC Manager" : "SRM / Protection and Recovery";
    node("operation-target").textContent = `${productLabel} — ${result.address || ""}:${result.port || 443}${result.domain_id ? ` · Management domain ${result.domain_id}` : ""}`;
    if (operationId) wizard.markClean();
    node("result").textContent = `${result.state || "unknown"}${result.error ? ` — ${result.error}` : ""}`;
    node("progress").value = Number(result.progress_percent || 0);
    const verification = result.verification || {};
    for (const [key, target] of Object.entries({installation: "installation", exact_served_certificate: "served-certificate", strict_tls: "strict-tls", authenticated_login: "login", health: "health"})) {
      node(target).textContent = verification[key] === true ? "Verified" : ["failed", "needs_recovery"].includes(result.state) ? "Needs attention" : "Not verified";
    }
    if (result.job_id) { node("task").href = `${form.dataset.tasksRoot}?job_id=${encodeURIComponent(result.job_id)}`; node("task").classList.remove("hidden"); }
    node("continue-review").classList.toggle("hidden", result.state !== "prepared");
    node("new-operation").classList.toggle("hidden", !(result.state === "succeeded" || result.checkpoint === "reconciled_not_dispatched"));
    form.querySelector("[data-cert-prepare]").disabled = Boolean(operationId);
    lockOperationFields(Boolean(operationId));
    window.clearTimeout(pollTimer);
    pollTimer = null;
    if (dialog.open && ["preparing", "installing"].includes(result.state)) pollTimer = window.setTimeout(() => poll(), 1500);
  }
  function lockOperationFields(locked) {
    ["product", "address", "port", "common_name", "dns_names", "ip_addresses", "profile_id", "recovery_reference", "credential_vault_id", "credential_entry_id", "username"].forEach((name) => { if (field(name)) field(name).disabled = locked; });
  }
  function hydrateOperation(result) {
    operationId = result.operation_id;
    const reference = result.credential_reference || {};
    field("product").value = result.product || "srm"; field("address").value = result.address || ""; field("port").value = result.port || 443;
    node("operation-target").textContent = `${result.product === "sddc" ? "SDDC Manager" : result.product === "vcenter" ? "vCenter" : "SRM / Protection and Recovery"} — ${result.address || ""}:${result.port || 443}${result.domain_id ? ` · Management domain ${result.domain_id}` : ""}`;
    field("confirmed").checked = Boolean(result.confirmed_tls_fingerprint); probe = result.confirmed_tls_fingerprint ? {fingerprint: result.confirmed_tls_fingerprint} : null;
    node("fingerprint").textContent = probe?.fingerprint || "Not checked";
    field("username").value = reference.username || ""; field("password").value = "";
    if (reference.mode === "vault") {
      for (const [name, value, label] of [["credential_vault_id", reference.vault_id, "Saved vault"], ["credential_entry_id", reference.entry_id, "Saved key"]]) {
        const select = field(name);
        if (![...select.options].some((option) => option.value === String(value))) select.add(new Option(label, String(value)));
        select.value = String(value);
      }
      field("password").disabled = true;
    } else { field("credential_vault_id").value = ""; field("credential_entry_id").value = ""; }
    if (result.names) { field("common_name").value = result.names.common_name || ""; field("dns_names").value = (result.names.dns_names || []).join("\n"); field("ip_addresses").value = (result.names.ip_addresses || []).join("\n"); }
    if (result.profile_id) { const select = field("profile_id"); if (![...select.options].some((option) => option.value === String(result.profile_id))) select.add(new Option("Saved profile", String(result.profile_id))); select.value = String(result.profile_id); }
    field("recovery_reference").value = result.recovery_reference || "";
    inspection = result.state === "prepared" ? {supported: true} : null; paintOperation(result);
  }
  function clearTerminalOperation() {
    if (node("new-operation").classList.contains("hidden")) return;
    saveOperation(""); operationId = null; inspection = null; probe = null; reviewToken = null;
    form.reset(); lockOperationFields(false); wizard.reset(); updateMode(); clearMessage();
    form.querySelector("[data-cert-prepare]").disabled = false;
    node("result").textContent = ""; node("new-operation").classList.add("hidden");
  }
  async function poll() { if (!operationId || !dialog.open) return; await run(async () => paintOperation(await call(`/operations/${encodeURIComponent(operationId)}`))); }
  const stepCopy = {
    credential: ["Choose credentials", "Select saved vault credentials or enter temporary credentials."],
    server: ["Select the appliance", "Choose SRM, vCenter, or SDDC Manager and enter its endpoint."],
    fingerprint: ["Confirm TLS identity", "Compare the presented SHA-256 fingerprint with a trusted source."],
    login: ["Sign in to the appliance", "Manual credentials are sent only after fingerprint confirmation."],
    target: ["Check target and prerequisites", "Inspect native capabilities, topology, names, and certificate profiles."],
    prepare: ["Prepare the certificate", "Confirm recovery readiness before requesting a target-owned CSR."],
    review: ["Review the replacement", "Check the exact certificate, trust changes, interruption, and recovery plan."],
    replace: ["Approve installation", "Install only the reviewed certificate after explicit approval."],
    results: ["Verify operation results", "Review installation, TLS, login, and appliance health separately."],
  };
  const wizard = window.AtlasoUiPatterns.createWizard({form, dialog, steps: steps.map((id) => ({id, title: stepCopy[id][0], description: stepCopy[id][1]})), validateStep: ({step}) => {
    if (step.id === "credential") return Boolean(manual() || field("credential_entry_id").value);
    if (step.id === "fingerprint") return Boolean(probe && field("confirmed").checked);
    if (step.id === "login") return Boolean(probe && field("confirmed").checked && field("username").value && field("password").value);
    if (step.id === "target") return Boolean(inspection?.supported && field("profile_id").value);
    if (step.id === "prepare") return Boolean(field("recovery_ready").checked && field("acknowledged").checked && field("recovery_reference").value.trim());
    if (step.id === "review") return Boolean(reviewToken);
    if (step.id === "replace") return field("install_acknowledged").checked;
    return true;
  }, onSubmit: () => wizard.requestClose()});
  const updateMode = () => wizard.setSkippedSteps(manual() ? [] : ["login"]);
  form.addEventListener("change", (event) => {
    if (["product", "address", "port"].includes(event.target.name)) invalidateEndpoint();
    else if (["credential_vault_id", "credential_entry_id", "username", "password"].includes(event.target.name)) invalidateCredential();
    else if (["common_name", "dns_names", "ip_addresses", "profile_id", "recovery_reference"].includes(event.target.name)) invalidateReview();
    if (event.target.name === "credential_vault_id") updateMode();
  });
  form.addEventListener("input", (event) => {
    if (["address", "port", "product"].includes(event.target.name)) invalidateEndpoint();
    else if (["username", "password"].includes(event.target.name)) invalidateCredential();
    else if (["common_name", "dns_names", "ip_addresses", "profile_id", "recovery_reference"].includes(event.target.name)) invalidateReview();
  });
  form.addEventListener("click", (event) => {
    const button = event.target.closest("[data-cert-probe],[data-cert-inspect],[data-cert-prepare],[data-cert-review-action],[data-cert-execute],[data-cert-reconcile]");
    if (!button) return;
    event.preventDefault();
    run(async () => {
      if (button.matches("[data-cert-probe]")) {
        const current = credentials();
        probe = await call("/probe", {product: current.product, address: current.address, port: current.port});
        node("fingerprint").textContent = probe.fingerprint;
      }
      else if (button.matches("[data-cert-inspect]")) {
        inspection = await call("/inspect", credentials());
        paintList(node("prerequisites"), (inspection.prerequisites || []).map((p) => [p.label, `${p.ok ? "Ready" : "Blocked"}: ${p.detail}`]));
        field("common_name").value = inspection.names.common_name || ""; field("dns_names").value = (inspection.names.dns_names || []).join("\n"); field("ip_addresses").value = (inspection.names.ip_addresses || []).join("\n");
        const select = field("profile_id"); select.replaceChildren(new Option("Choose a profile", "")); (inspection.profiles || []).forEach((p) => select.add(new Option(p.name, p.id)));
        if (!inspection.supported) throw new Error("This target is unsupported or has unmet prerequisites.");
      } else if (button.matches("[data-cert-prepare]")) {
        if (operationId) throw new Error("An operation already exists. Reconcile it before starting another.");
        const result = await call("/prepare", {...credentials(), ...targetFields(), recovery_ready: field("recovery_ready").checked, acknowledged: field("acknowledged").checked});
        operationId = result.operation_id; saveOperation(operationId); wizard.setHighestStep("results"); wizard.showStep("results"); paintOperation(result);
      } else if (button.matches("[data-cert-review-action]")) {
        const result = await call("/review", {...credentials(), operation_id: operationId, ...targetFields()}); reviewToken = result.token;
        const r = result.review; paintList(node("review"), [["Target", r.target], ...(r.domain_id ? [["Management domain", r.domain_id], ["SDDC Manager resource", r.resource_id]] : []), ["Current SHA-256", r.current_certificate.fingerprint_sha256], ["Replacement SHA-256", r.replacement_certificate.fingerprint_sha256], ["Issuer", r.issuer], ["Issuer SHA-256", r.issuer_fingerprint_sha256], ["CA profile", r.profile], ["Names", (r.names || []).join(", ")], ["Validity", r.replacement_certificate.not_before + " through " + r.replacement_certificate.not_after], ["Trust changes", (r.trust_changes || []).join(", ")], ["Interruption", r.interruption], ["Recovery", r.recovery_reference]]);
      } else if (button.matches("[data-cert-execute]")) {
        const result = await call("/execute", {...credentials(), operation_id: operationId, token: reviewToken, acknowledged: field("install_acknowledged").checked}); reviewToken = null; wizard.setHighestStep("results"); wizard.showStep("results"); paintOperation(result);
      } else {
        const result = await call("/reconcile", {...credentials(), operation_id: operationId}); paintOperation(result);
      }
    });
  });
  const opener = document.querySelector("[data-vcf-appliance-certificate-open]");
  const explicitOperation = new URLSearchParams(window.location.search).get("certificate_operation");
  const restoredOperation = explicitOperation || savedOperation();
  if (restoredOperation) {
    operationId = restoredOperation;
    void call(`/operations/${encodeURIComponent(operationId)}`).then((result) => {
      hydrateOperation(result); updateMode();
      if (explicitOperation) void wizard.open({launcher: opener, reset: false, step: "results", highestStep: "results"}).then(() => poll());
    }).catch((error) => { operationId = null; saveOperation(""); message(error.message, true); });
  }
  opener?.addEventListener("click", (event) => {
    if (!opener.disabled) {
      updateMode();
      void wizard.open({launcher: event.currentTarget, reset: !operationId, step: operationId ? "results" : "credential", highestStep: operationId ? "results" : 0}).then(() => { if (operationId) void poll(); });
    }
  });
  form.querySelector("[data-atlaso-wizard-cancel]")?.addEventListener("click", () => wizard.requestClose());
  node("continue-review").addEventListener("click", () => { wizard.setHighestStep("review"); wizard.showStep("review"); });
  node("new-operation").addEventListener("click", clearTerminalOperation);
  dialog.addEventListener("cancel", (event) => { event.preventDefault(); void wizard.requestClose(); });
  dialog.addEventListener("close", () => {
    window.clearTimeout(pollTimer); pollTimer = null;
    field("password").value = ""; reviewToken = null;
    if (!operationId && !busy) { form.reset(); probe = null; inspection = null; }
  });
  updateMode();
})();

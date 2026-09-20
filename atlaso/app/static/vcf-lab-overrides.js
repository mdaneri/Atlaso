/* Explicit property management; no credentials or remote HTML enter page state. */
(() => {
  "use strict";
  const form = document.querySelector("[data-vcf-lab-form]");
  if (!form) return;
  const field = (name) => form.elements.namedItem(name);
  const node = (name) => form.querySelector(`[data-lab-${name}]`);
  const action = (name) => form.querySelector(`[data-lab-action="${name}"]`);
  const endpoint = form.dataset.endpoint;
  let trust = null;
  let inspected = false;
  let token = null;
  let revision = 0;
  let busy = false;
  let timer = null;

  function setHidden(name, hidden) {
    node(name).hidden = hidden;
    node(name).classList.toggle("hidden", hidden);
  }

  function controls() {
    action("inspect").disabled = busy || !trust?.tls_fingerprint || !field("confirmed").checked;
    node("options").disabled = busy || !inspected;
    action("review").disabled = busy || !inspected || !(field("esa").checked || field("nic").checked);
    action("revert").disabled = busy || !trust || !field("confirmed").checked || !field("source_job_id").value;
    node("execute").disabled = busy || !token || !field("acknowledged").checked;
    action("probe").disabled = busy;
    field("api_credential").disabled = busy;
    field("ssh_credential").disabled = busy;
  }

  function invalidate() {
    token = null;
    revision += 1;
    field("acknowledged").checked = false;
    setHidden("review", true);
    controls();
  }

  async function call(path, body) {
    const response = await fetch(endpoint + path, {
      method: body ? "POST" : "GET",
      headers: body ? {"Content-Type": "application/json", "X-CSRF-Token": field("csrf").value} : {},
      credentials: "same-origin", cache: "no-store",
      body: body ? JSON.stringify(body) : undefined,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === "string" ? result.detail : "The operation could not complete. Inspect the target and try again.");
    return result;
  }

  function inputs() {
    const api = field("api_credential").value.split(":").map(Number);
    const ssh = field("ssh_credential").value.split(":").map(Number);
    if (api.length !== 2 || ssh.length !== 2) throw new Error("Choose API and SSH credentials.");
    return {api_entry_id: api[0], api_uri_index: api[1], ssh_entry_id: ssh[0], ssh_uri_index: ssh[1],
      tls_fingerprint: trust?.tls_fingerprint || "", ssh_fingerprint: trust?.ssh_fingerprint || "",
      confirmed: field("confirmed").checked,
      selections: ["esa", "nic"].filter((key) => field(key).checked)};
  }

  async function history() {
    const result = await call("/history");
    const select = field("source_job_id");
    const chosen = select.value;
    select.replaceChildren(new Option("Choose an operation to revert", ""));
    result.jobs.forEach((job) => select.add(new Option(`${job.target} · ${job.created_at} · ${job.status}`, job.id)));
    select.value = chosen;
  }

  async function poll(jobId, deadline) {
    try {
      const result = await call(`/tasks/${encodeURIComponent(jobId)}`);
      node("status").textContent = `Task ${result.status}. ${result.error || ""}`;
      if (!["pending", "running"].includes(result.status)) {
        const evidence = result.result || {};
        node("status").textContent += ` Properties verified: ${evidence.property_verified ? "yes" : "not confirmed"}; domainmanager active: ${evidence.service_active ? "yes" : "not confirmed"}; VCF API ready: ${evidence.api_ready ? "yes" : "not confirmed"}. This does not verify a VCF validation bypass.`;
        inspected = false;
        busy = false;
        invalidate();
        await history();
        return;
      }
      if (Date.now() >= deadline) throw new Error("Monitoring timed out. Open Tasks to inspect the operation before retrying.");
      timer = window.setTimeout(() => poll(jobId, deadline), 2000);
    } catch (error) {
      node("error").textContent = error.message;
      setHidden("error", false);
      busy = false;
      inspected = false;
      invalidate();
    }
  }

  async function perform(kind) {
    setHidden("error", true);
    busy = true;
    controls();
    const currentRevision = revision;
    try {
      const values = inputs();
      const result = await call(`/${kind === "revert" ? "review" : kind}`, kind === "revert" ? {...values, source_job_id: field("source_job_id").value} : values);
      if (currentRevision !== revision) return;
      if (kind === "probe") {
        trust = result;
        inspected = false;
        invalidate();
        field("confirmed").checked = false;
        node("target").textContent = result.target;
        node("tls").textContent = result.tls_fingerprint || "Unavailable. Only recovery of a previous managed operation is available.";
        node("ssh").textContent = result.ssh_fingerprint;
        setHidden("trust", false);
        setHidden("confirm-label", false);
      } else if (kind === "inspect") {
        inspected = true;
        node("observed").textContent = `${result.target} · ${result.role} · VCF ${result.version}. ESA property: ${result.values.esa ?? "absent"}; NIC property: ${result.values.nic ?? "absent"}; domainmanager: ${result.service_active ? "active" : "not active"}.`;
      } else {
        token = result.token;
        field("acknowledged").checked = false;
        node("review-target").textContent = `${kind === "revert" ? "Revert" : "Apply"}: ${result.target} · ${result.role} · VCF ${result.version}${result.identity_source ? ` (${result.identity_source})` : ""}`;
        node("changes").replaceChildren();
        result.changes.forEach((change) => {
          const li = document.createElement("li");
          li.textContent = `${change.key}: ${change.previous ?? "absent"} → ${change.value ?? "absent (remove managed property)"}`;
          node("changes").append(li);
        });
        node("restart").textContent = result.restart_required ? "domainmanager will restart. Property readback and service/API readiness will be checked." : "No property changes or service restart are required.";
        node("execute").textContent = kind === "revert" ? "Revert reviewed changes" : "Apply reviewed changes";
        setHidden("review", false);
        field("acknowledged").focus();
      }
    } catch (error) {
      invalidate();
      node("error").textContent = error.message;
      setHidden("error", false);
    } finally {
      busy = false;
      controls();
    }
  }

  form.addEventListener("change", (event) => {
    if (event.target.name === "acknowledged") { controls(); return; }
    if (["api_credential", "ssh_credential"].includes(event.target.name)) {
      trust = null;
      inspected = false;
      field("confirmed").checked = false;
      setHidden("trust", true);
      setHidden("confirm-label", true);
      node("observed").textContent = "Current properties have not been inspected.";
    }
    if (event.target.name === "confirmed") inspected = false;
    invalidate();
  });
  form.querySelectorAll("[data-lab-action]").forEach((button) => button.addEventListener("click", () => perform(button.dataset.labAction)));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !token || !field("acknowledged").checked) return;
    busy = true;
    controls();
    try {
      const result = await call("/execute", {token, acknowledged: true});
      invalidate();
      node("task").href = `${form.dataset.tasksRoot}?job_id=${encodeURIComponent(result.job_id)}`;
      setHidden("task", false);
      node("task").focus();
      await poll(result.job_id, Date.now() + 600000);
    } catch (error) {
      node("error").textContent = error.message;
      setHidden("error", false);
      busy = false;
      invalidate();
    }
  });
  window.addEventListener("pagehide", () => window.clearTimeout(timer));
  try {
    const vaults = JSON.parse(document.getElementById("vcf-vault-credential-options").textContent);
    vaults.forEach((vault) => vault.entries.forEach((entry) => (entry.uris || []).forEach((uri, index) => {
      if (!entry.username || !entry.has_value) return;
      let parsed;
      try { parsed = new URL(uri); } catch { return; }
      const select = ["http:", "https:"].includes(parsed.protocol) ? field("api_credential") : ["ssh:", "sftp:"].includes(parsed.protocol) ? field("ssh_credential") : null;
      if (select) select.add(new Option(`${vault.name} / ${entry.key} · ${parsed.host}`, `${entry.id}:${index + 1}`));
    })));
    history().catch(() => { node("status").textContent = "Operation history is unavailable. Refresh to retry."; });
  } catch { node("status").textContent = "Vault credential choices are unavailable. Refresh to retry."; }
  controls();
})();

(function initializeDiagnostics() {
  "use strict";
  const element = document.getElementById("diagnostics-grid");
  if (!element || !window.AtlasoUiPatterns) return;
  const root = element.dataset.root;
  const form = document.getElementById("diagnostics-create");
  const detail = document.getElementById("diagnostics-detail");
  const status = document.getElementById("diagnostics-status");
  const windowSelect = document.getElementById("diagnostics-window");
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  let selected = null;
  let refreshing = false;
  let ready = false;
  let lastRows = "";
  let grid;

  async function request(url, options = {}) {
    const response = await fetch(url, { credentials: "same-origin", cache: "no-store", ...options });
    const payload = await response.json();
    if (!response.ok) throw new Error(typeof payload.detail === "string" ? payload.detail : "The diagnostic request could not be completed.");
    return payload;
  }
  function controls() {
    const custom = windowSelect.value === "custom";
    form.querySelectorAll("[data-diagnostic-time]").forEach((label) => {
      label.hidden = !custom;
      label.classList.toggle("hidden", !custom);
      label.querySelector("input").disabled = !custom;
      label.querySelector("input").required = custom;
    });
    document.getElementById("diagnostics-timezone").textContent = `Custom times use ${timezone}. Captured evidence includes UTC timestamps.`;
  }
  function selection() {
    const data = new FormData(form);
    if (windowSelect.value === "custom") {
      for (const field of ["since", "until"]) data.set(field, new Date(form.elements[field].value).toISOString());
    } else {
      data.delete("since"); data.delete("until");
    }
    return data;
  }
  function reviewLine(container, label, value) {
    const row = document.createElement("div");
    const name = document.createElement("span"); name.textContent = label;
    const content = document.createElement("strong"); content.textContent = value;
    row.append(name, content); container.append(row);
  }
  function review() {
    const container = document.getElementById("diagnostics-review"); container.replaceChildren();
    const data = selection();
    reviewLine(container, "Incident", windowSelect.value === "recent" ? "Last 30 minutes" : `${data.get("since")} — ${data.get("until")}`);
    reviewLine(container, "Contents", ["Basic diagnostics", ...data.getAll("scopes")].join(", "));
    reviewLine(container, "Detailed log evidence", data.has("detailed_logs") ? `Selected; up to ${data.get("log_lines")} events per source` : "Not selected");
    reviewLine(container, "Anonymize hostnames / usernames", data.has("anonymize") ? "On" : "Off");
    reviewLine(container, "IP / MAC addresses", "Unchanged");
    reviewLine(container, "Retention", "24 hours");
    return true;
  }
  const wizard = window.AtlasoUiPatterns.createWizard({
    form, dialog: "#diagnostics-wizard",
    steps: [
      { id: "incident", title: "Incident", description: "Select when the problem occurred." },
      { id: "contents", title: "Contents", description: "Choose the evidence to collect." },
      { id: "privacy", title: "Privacy", description: "Choose whether to anonymize hostnames and usernames." },
      { id: "review", title: "Review", description: "Review your selections before starting collection." },
    ],
    onOpen: ({ context }) => {
      windowSelect.value = "recent";
      if (context?.selection) {
        const saved = context.selection;
        for (const field of ["anonymize", "detailed_logs"]) form.elements[field].checked = Boolean(saved[field]);
        form.elements.correlation_id.value = saved.correlation_id || "";
        form.elements.log_lines.value = saved.log_lines || 500;
        form.querySelectorAll("[name='scopes']").forEach((input) => { input.checked = (saved.scopes || []).includes(input.value); });
        windowSelect.value = "custom";
        for (const field of ["since", "until"]) {
          const date = new Date(saved[field]);
          form.elements[field].value = new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
        }
      }
      controls();
    },
    validateStep: ({ step }) => {
      if (step.id === "incident" && windowSelect.value === "custom") {
        const since = new Date(form.elements.since.value);
        const until = new Date(form.elements.until.value);
        if (!Number.isFinite(+since) || !Number.isFinite(+until) || until <= since || until - since > 7 * 86400000 || until > Date.now() + 60000) return "Choose a past time range of at most seven days.";
      }
      return true;
    },
    prepareReview: review,
    onSubmit: async () => {
      await request(`${root}/create`, { method: "POST", body: selection() });
      status.textContent = "Bundle queued. You can leave this page while collection runs.";
      await refresh();
      return true;
    },
  });
  windowSelect.addEventListener("change", controls);

  async function openDetail(data) {
    if (data.is_new) { await wizard.open(); return; }
    try {
      selected = await request(`${root}/${encodeURIComponent(data.id)}`);
      document.getElementById("diagnostics-detail-status").textContent = `${selected.status.replaceAll("_", " ")} — ${selected.summary || "Collection status"}`;
      const contents = document.getElementById("diagnostics-detail-contents"); contents.replaceChildren();
      reviewLine(contents, "Created", selected.created_at);
      reviewLine(contents, "Automatic deletion", selected.expires_at);
      reviewLine(contents, "Anonymization", selected.anonymize ? "Hostnames and usernames replaced; IP / MAC unchanged" : "Off; IP / MAC unchanged");
      for (const item of selected.manifest?.collectors || []) reviewLine(contents, item.collector, item.status.replaceAll("_", " "));
      const omissions = document.getElementById("diagnostics-omissions"); omissions.replaceChildren();
      for (const omission of selected.omissions || []) { const li = document.createElement("li"); li.textContent = omission; omissions.append(li); }
      const link = document.getElementById("diagnostics-download");
      link.hidden = !["ready", "ready_with_omissions"].includes(selected.status);
      link.classList.toggle("hidden", link.hidden);
      link.href = `${root}/${encodeURIComponent(selected.id)}/download`;
      for (const [id, enabled] of [["diagnostics-cancel", ["pending", "running"].includes(selected.status)], ["diagnostics-remove", !["pending", "running", "expired", "deleted"].includes(selected.status)]]) {
        const button = document.getElementById(id);
        button.hidden = !enabled;
        button.classList.toggle("hidden", !enabled);
      }
      document.getElementById("diagnostics-task").href = `${root.split("/backup-restore")[0]}/tasks?job_id=${encodeURIComponent(selected.task_id)}`;
      detail.showModal();
    } catch (error) { status.textContent = error.message; }
  }
  async function cancel(data) {
    try {
      const body = new FormData(); body.set("csrf", form.elements.csrf.value);
      await request(`${root}/${encodeURIComponent(data.id)}/cancel`, { method: "POST", body });
      status.textContent = "Cancellation requested. The collector will stop before publishing more evidence.";
      await refresh();
    } catch (error) { status.textContent = error.message; }
  }
  async function remove(data) {
    const deletion = document.getElementById("diagnostics-delete");
    const confirmed = await window.requestConfirmation({
      title: deletion.dataset.confirmTitle, message: deletion.dataset.confirmMessage,
      label: deletion.dataset.confirmLabel,
    });
    if (!confirmed) return;
    try {
      await request(`${root}/${encodeURIComponent(data.id)}/delete`, { method: "POST", body: new FormData(deletion) });
      status.textContent = "Diagnostic bundle deleted.";
      await refresh();
    } catch (error) { status.textContent = error.message; }
  }
  const text = (cell) => {
    const span = document.createElement("span");
    if (!cell.getRow().getData().is_new) span.textContent = String(cell.getValue() ?? "").replaceAll("_", " ");
    return span;
  };
  grid = window.AtlasoUiPatterns.createGrid({
    element, fallback: "#diagnostics-fallback", pattern: "wizard-backed", status: "#diagnostics-grid-status",
    onOpenRow: (data) => openDetail(data),
    onReady: () => { ready = true; element.atlasoTabulatorReady = true; refresh(); },
    options: {
      index: "id", data: [{ id: "new", is_new: true }], layout: "fitColumns", minHeight: 240,
      rowContextMenu: [
        { label: "View contents", disabled: (row) => row.getData().is_new, action: (_event, row) => openDetail(row.getData()) },
        { label: "Cancel collection", disabled: (row) => !["pending", "running"].includes(row.getData().status), action: (_event, row) => cancel(row.getData()) },
        { label: "Delete bundle", disabled: (row) => row.getData().is_new || ["pending", "running", "expired", "deleted"].includes(row.getData().status), action: (_event, row) => remove(row.getData()) },
      ],
      columns: [
        { title: "Created", field: "created_at", minWidth: 190, formatter: (cell) => {
          if (!cell.getRow().getData().is_new) return text(cell);
          const button = document.createElement("button"); button.type = "button"; button.className = "add-row-button"; button.textContent = "+ Create diagnostic bundle";
          button.addEventListener("click", () => wizard.open({ launcher: button })); return button;
        } },
        { title: "Status", field: "status", minWidth: 155, formatter: (cell) => {
          const span = text(cell);
          if (cell.getValue() === "running") span.textContent += ` (${cell.getRow().getData().progress_percent || 0}%)`;
          return span;
        } },
        { title: "Scope", field: "scope", minWidth: 120, formatter: text },
        { title: "Anonymized", field: "anonymize", minWidth: 110, formatter: (cell) => { const span = document.createElement("span"); if (!cell.getRow().getData().is_new) span.textContent = cell.getValue() ? "Yes" : "No"; return span; } },
        { title: "Bytes", field: "size_bytes", minWidth: 100, formatter: text },
        { title: "Expires", field: "expires_at", minWidth: 190, formatter: text },
      ],
    },
  });
  element.atlasoTabulator = grid.table;
  function fitGrid() {
    if (!ready) return;
    const rect = element.getBoundingClientRect();
    const visible = !document.getElementById("maintenance-diagnostics").hidden;
    grid.table.setHeight(window.innerWidth > 900 && visible && rect.width > 0 ? Math.max(260, window.innerHeight - rect.top - 28) : "");
  }
  async function refresh() {
    if (!ready || refreshing || document.hidden || document.getElementById("maintenance-diagnostics").hidden) return;
    refreshing = true;
    try {
      const payload = await request(`${root}/data`);
      const serialized = JSON.stringify(payload.bundles);
      if (serialized !== lastRows) {
        await grid.table.replaceData([...payload.bundles, { id: "new", is_new: true }]);
        lastRows = serialized;
      }
    } catch (error) { status.textContent = error.message; }
    finally { refreshing = false; }
  }
  document.getElementById("diagnostics-detail-close").addEventListener("click", () => detail.close());
  document.getElementById("diagnostics-cancel").addEventListener("click", () => { detail.close(); cancel(selected); });
  document.getElementById("diagnostics-remove").addEventListener("click", () => { detail.close(); remove(selected); });
  document.getElementById("diagnostics-retry").addEventListener("click", () => { detail.close(); wizard.open({ context: selected }); });
  document.getElementById("maintenance-diagnostics-tab").addEventListener("click", () => { refresh(); window.requestAnimationFrame(fitGrid); });
  window.addEventListener("resize", fitGrid);
  document.addEventListener("visibilitychange", refresh);
  window.setInterval(refresh, 5000);
  controls();
})();

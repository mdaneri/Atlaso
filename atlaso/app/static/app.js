document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  const formId = target.dataset.focusForm;
  if (!formId) {
    return;
  }
  const form = document.getElementById(formId);
  const input = form?.querySelector("input, textarea, button");
  if (input instanceof HTMLElement) {
    input.focus();
    form.scrollIntoView({ behavior: "smooth", block: "center" });
  }
});

const DNS_ACTIVE_ZONE_STORAGE_KEY = "atlaso:dns:active-zone";
const PUBLIC_ADDRESS_MODE_COOKIE = "atlaso_public_address_mode";
const ATLASO_MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const APPLIANCE_APPLY_SUCCESS_AUTO_CLOSE_MS = 15000;
const atlasoDnsRecordTables = new WeakMap();
const atlasoLdapDirectoryTables = new WeakMap();
let ldapMembershipTooltip = null;
const LDAP_ORGANIZATION_SELECTION_KEY = "atlaso:ldap:organization";
let applianceApplySidebarRefreshTimer = 0;
let applianceApplyGlobalPollTimer = 0;
let applianceApplyAutoCloseTimer = 0;
let applianceApplyModalTable = null;
let applianceApplyActiveJobId = "";

function atlasoRequestMethod(input, init = {}) {
  return String(init.method || (input instanceof Request ? input.method : "GET")).toUpperCase();
}

function isAtlasoSameOriginRequest(input) {
  try {
    const rawUrl = input instanceof Request ? input.url : String(input);
    const url = new URL(rawUrl, window.location.href);
    return url.origin === window.location.origin && url.pathname !== "/appliance-apply/status";
  } catch {
    return false;
  }
}

function scheduleApplianceApplySidebarRefresh() {
  window.clearTimeout(applianceApplySidebarRefreshTimer);
  applianceApplySidebarRefreshTimer = window.setTimeout(() => {
    refreshApplianceApplySidebar().catch(() => {});
  }, 50);
}

if (typeof window.fetch === "function" && !window.fetch.atlasoApplyStatusWrapped) {
  const nativeFetch = window.fetch.bind(window);
  const wrappedFetch = async (input, init = {}) => {
    const method = atlasoRequestMethod(input, init);
    const shouldRefresh =
      ATLASO_MUTATING_METHODS.has(method) &&
      isAtlasoSameOriginRequest(input);
    const response = await nativeFetch(input, init);
    if (shouldRefresh && response.ok) {
      scheduleApplianceApplySidebarRefresh();
    }
    return response;
  };
  wrappedFetch.atlasoApplyStatusWrapped = true;
  window.fetch = wrappedFetch;
}

function readCookieValue(name) {
  const prefix = `${name}=`;
  return document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
    ?.slice(prefix.length) || "";
}

function writeCookieValue(name, value) {
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=31536000; samesite=lax`;
}

function applyPublicAddressMode(mode) {
  const normalized = mode === "ip" ? "ip" : "name";
  document.querySelectorAll("[data-public-address-mode-option]").forEach((button) => {
    if (button instanceof HTMLButtonElement) {
      button.setAttribute("aria-pressed", button.dataset.publicAddressModeOption === normalized ? "true" : "false");
    }
  });
  document.querySelectorAll("[data-public-service-card]").forEach((card) => {
    if (!(card instanceof HTMLAnchorElement)) {
      return;
    }
    const target = normalized === "ip" ? card.dataset.ipHref : card.dataset.nameHref;
    if (target) {
      card.href = target;
    }
  });
}

function initializePublicAddressModeToggle() {
  const toggle = document.querySelector("[data-public-address-mode-toggle]");
  if (!(toggle instanceof HTMLElement)) {
    return;
  }
  const saved = decodeURIComponent(readCookieValue(PUBLIC_ADDRESS_MODE_COOKIE) || "");
  const initialMode = saved === "ip" ? "ip" : "name";
  applyPublicAddressMode(initialMode);
  toggle.querySelectorAll("[data-public-address-mode-option]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      const mode = button.dataset.publicAddressModeOption === "ip" ? "ip" : "name";
      writeCookieValue(PUBLIC_ADDRESS_MODE_COOKIE, mode);
      applyPublicAddressMode(mode);
    });
  });
}

function registerAtlasoPrismLanguages() {
  if (!window.Prism || !window.Prism.languages) {
    return;
  }
  if (!window.Prism.languages.json) {
    window.Prism.languages.json = {
      property: {
        pattern: /"(?:\\.|[^\\"\r\n])*"(?=\s*:)/,
        greedy: true,
      },
      string: {
        pattern: /"(?:\\.|[^\\"\r\n])*"(?!\s*:)/,
        greedy: true,
      },
      number: /-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/i,
      boolean: /\b(?:true|false)\b/,
      null: {
        pattern: /\bnull\b/,
        alias: "keyword",
      },
      operator: /:/,
      punctuation: /[{}\[\],]/,
    };
  }
  if (!window.Prism.languages["atlaso-config"]) {
    window.Prism.languages["atlaso-config"] = {
      comment: /(^|\n)\s*[#;].*/,
      section: {
        pattern: /(^|\n)\s*\[[^\]\r\n]+\]/,
        alias: "keyword",
      },
      property: /[A-Za-z0-9_.-]+(?=\s*=)/,
      string: {
        pattern: /"(?:\\.|[^"\\])*"/,
        greedy: true,
      },
      boolean: /\b(?:true|false|yes|no|enabled|disabled|accept|drop|reject)\b/i,
      number: /\b\d+(?:\.\d+)?(?:\/\d+)?\b/,
      operator: /=|:|\{|\}/,
      punctuation: /[\[\](),;]/,
    };
  }
  if (!window.Prism.languages["atlaso-log"]) {
    window.Prism.languages["atlaso-log"] = {
      redacted: {
        pattern: /\[redacted(?: sensitive line|-token)?\]|=\s*\[redacted\]/i,
        alias: "important",
      },
      timestamp: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/,
      "level-error": {
        pattern: /\b(?:ERROR|CRITICAL|FATAL)\b/,
        alias: "important",
      },
      "level-warning": /\b(?:WARN|WARNING)\b/,
      "level-info": /\b(?:INFO|NOTICE)\b/,
      "level-debug": /\b(?:TRACE|DEBUG)\b/,
      component: {
        pattern: /\[[A-Za-z_][A-Za-z0-9_.-]+\]|\b[A-Za-z_][A-Za-z0-9_.-]+(?=\[\d+\]:)/,
        alias: "class-name",
      },
      identifier: /\b(?:job|req)_[A-Za-z0-9_-]+\b/,
      address: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/,
      label: {
        pattern: /(^|\n)(?:Job|Type|Status|State|Progress|Created|Started|Finished|Selected units|Skipped changed units|Units)(?=:)/,
        lookbehind: true,
        alias: "property",
      },
      command: {
        pattern: /(^|\n)\$ .*/,
        lookbehind: true,
        alias: "function",
      },
      stack: {
        pattern: /^\s+at\s+.+$/m,
        alias: "comment",
      },
      number: /\b\d+(?:\.\d+)*\b/,
      punctuation: /[()[\]{}:]/,
    };
  }
  if (!window.Prism.languages.csv) {
    window.Prism.languages.csv = {
      header: {
        pattern: /^[^\r\n]+/,
        alias: "property",
      },
      string: {
        pattern: /"(?:[^"]|"")*"/,
        greedy: true,
      },
      number: /(^|,)-?\d+(?:\.\d+)?(?=,|$)/m,
      punctuation: /,/,
    };
  }
  if (!window.Prism.languages["atlaso-powershell"]) {
    window.Prism.languages["atlaso-powershell"] = {
      comment: /#.*/,
      string: {
        pattern: /"(?:`.|[^"`])*"|'(?:''|[^'])*'/,
        greedy: true,
      },
      variable: /\$(?:\{[^}\r\n]+\}|[A-Za-z_][\w:]*)/,
      parameter: {
        pattern: /(^|\s)-[A-Za-z][\w-]*/,
        lookbehind: true,
        alias: "property",
      },
      function: /\b[A-Za-z]+-[A-Za-z][\w-]*\b/,
      keyword: /\b(?:begin|break|catch|class|continue|data|do|dynamicparam|else|elseif|end|enum|exit|filter|finally|for|foreach|from|function|if|in|param|process|return|switch|throw|trap|try|until|using|while|workflow)\b/i,
      boolean: /\$(?:true|false|null)\b/i,
      number: /\b(?:0x[\da-f]+|\d+(?:\.\d+)?)\b/i,
      operator: /-eq|-ne|-gt|-ge|-lt|-le|-like|-notlike|-match|-notmatch|-and|-or|-not|\+|-|\*|\/|%|=|\||&/i,
      punctuation: /[{}\[\]();,.]/,
    };
  }
  if (!window.Prism.languages["atlaso-bash"]) {
    window.Prism.languages["atlaso-bash"] = {
      comment: /#.*/,
      string: {
        pattern: /"(?:\\.|[^"\\])*"|'[^']*'/,
        greedy: true,
      },
      variable: /\$(?:\{[^}\r\n]+\}|[A-Za-z_][\w]*|\d+|[@*#?$!-])/,
      parameter: {
        pattern: /(^|\s)--?[A-Za-z][\w-]*/,
        lookbehind: true,
        alias: "property",
      },
      keyword: /\b(?:case|coproc|do|done|elif|else|esac|fi|for|function|if|in|select|then|time|until|while)\b/,
      builtin: {
        pattern: /\b(?:cd|echo|eval|exec|exit|export|printf|pwd|read|readonly|return|set|shift|source|test|trap|unset)\b/,
        alias: "function",
      },
      number: /\b\d+(?:\.\d+)?\b/,
      operator: /&&|\|\||<<|>>|[|&;<>]=?|=/,
      punctuation: /[{}\[\](),]/,
    };
  }
  if (!window.Prism.languages["atlaso-python"]) {
    window.Prism.languages["atlaso-python"] = {
      comment: /#.*/,
      string: {
        pattern: /(?:[rubf]{0,2})(?:"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*')/i,
        greedy: true,
      },
      decorator: {
        pattern: /(^[\t ]*)@[A-Za-z_][\w.]*/m,
        lookbehind: true,
        alias: "annotation",
      },
      keyword: /\b(?:and|as|assert|async|await|break|class|continue|def|del|elif|else|except|exec|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield)\b/,
      builtin: /\b(?:bool|bytes|dict|enumerate|filter|float|int|len|list|map|max|min|open|print|range|set|str|sum|super|tuple|type|zip)\b/,
      boolean: /\b(?:True|False|None)\b/,
      number: /\b(?:0[box][\da-f]+|\d+(?:\.\d+)?(?:e[+-]?\d+)?)\b/i,
      operator: /\/\/?=?|\*\*?=?|[-+%=]=?|!=|:=|<=?|>=?|==|&|\||\^|~|@/,
      punctuation: /[{}\[\];(),.:]/,
    };
  }
}

function previewLanguageForText(text, element) {
  if (element.classList.contains("language-diff")) {
    return "diff";
  }
  if (element.classList.contains("language-atlaso-log")) {
    return "atlaso-log";
  }
  if (element.classList.contains("language-json")) {
    return "json";
  }
  if (element.classList.contains("language-csv")) {
    return "csv";
  }
  const trimmed = String(text ?? "").trim();
  if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && trimmed.length > 1) {
    try {
      JSON.parse(trimmed);
      return "json";
    } catch {
      // Non-JSON previews still get the compact Atlaso config grammar.
    }
  }
  return "atlaso-config";
}

function highlightConfigPreviewElement(element) {
  if (!(element instanceof HTMLElement) || !window.Prism || typeof window.Prism.highlightElement !== "function") {
    return;
  }
  registerAtlasoPrismLanguages();
  const language = previewLanguageForText(element.textContent || "", element);
  element.classList.remove("language-json", "language-csv", "language-atlaso-config", "language-atlaso-log");
  if (language !== "diff") {
    element.classList.remove("language-diff");
  }
  element.classList.add(`language-${language}`);
  if (element.parentElement instanceof HTMLElement && element.parentElement.tagName === "PRE") {
    element.parentElement.classList.remove("language-json", "language-csv", "language-atlaso-config", "language-atlaso-log");
    if (language !== "diff") {
      element.parentElement.classList.remove("language-diff");
    }
    element.parentElement.classList.add(`language-${language}`);
  }
  window.Prism.highlightElement(element);
}

function highlightConfigPreviews(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) {
    return;
  }
  initializeConfigPreviewActions(root);
  initializeTerminalNoteActions(root);
  root
    .querySelectorAll(
      [
        ".config-preview code",
        ".config-diff code",
        ".terminal-note > code",
        "code.language-json",
        "code.language-csv",
        "code.language-atlaso-config",
        "[data-appliance-settings-preview]",
        "[data-firewall-config-preview]",
        "[data-dns-config-preview]",
        "[data-vcf-config-preview]",
        "[data-vcf-registry-harbor-preview]",
        "[data-vcf-registry-relocation-preview]",
        "[data-vcf-depot-command-preview]",
        "[data-vcf-depot-https-preview]",
        "[data-esxi-pxe-preview]",
      ].join(", "),
    )
    .forEach((element) => highlightConfigPreviewElement(element));
}

function terminalNoteTitle(note) {
  const titleElement = note.querySelector("strong") || note.querySelector("summary");
  return titleElement?.textContent?.trim() || "Preview";
}

function openPreviewModal(title, text, sourceCode) {
  const modal = document.getElementById("preview-modal");
  const titleElement = document.getElementById("preview-modal-title");
  const code = modal?.querySelector("[data-preview-modal-code]");
  if (!(modal instanceof HTMLDialogElement) || !(titleElement instanceof HTMLElement) || !(code instanceof HTMLElement)) {
    return;
  }
  titleElement.textContent = title || "Preview";
  code.textContent = text || "";
  code.className = "";
  if (sourceCode instanceof HTMLElement) {
    sourceCode.classList.forEach((className) => {
      if (className.startsWith("language-")) {
        code.classList.add(className);
      }
    });
  }
  highlightConfigPreviewElement(code);
  if (typeof modal.showModal === "function") {
    modal.showModal();
  } else {
    modal.setAttribute("open", "");
  }
}

function initializePreviewModalControls() {
  const modal = document.getElementById("preview-modal");
  if (!(modal instanceof HTMLDialogElement) || modal.dataset.previewModalInitialized === "1") {
    return;
  }
  modal.dataset.previewModalInitialized = "1";
  const copyButton = modal.querySelector("[data-preview-modal-copy]");
  const closeButton = modal.querySelector("[data-preview-modal-close]");
  const code = modal.querySelector("[data-preview-modal-code]");
  copyButton?.addEventListener("click", async () => {
    try {
      await copyTextToClipboard(code?.textContent || "", "Copied", code);
    } catch {
      showTransientGridStatus("Copy failed");
    }
  });
  closeButton?.addEventListener("click", () => {
    modal.close();
  });
}

function initializeConfigPreviewActions(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) {
    return;
  }
  root.querySelectorAll("[data-config-preview-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement) || button.dataset.configPreviewOpenInitialized === "1") {
      return;
    }
    const row = button.closest("[data-config-preview-row]");
    const code = row?.querySelector("[data-config-preview-source]");
    if (!(row instanceof HTMLElement) || !(code instanceof HTMLElement)) {
      return;
    }
    button.dataset.configPreviewOpenInitialized = "1";
    button.addEventListener("click", () => {
      const label = row.querySelector("[data-config-preview-label]")?.textContent?.trim() || "Rendered config";
      openPreviewModal(button.dataset.previewTitle || label, code.textContent || "", code);
    });
  });
}

function appendButtonIcon(button, paths) {
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("class", "button-icon");
  icon.setAttribute("viewBox", "0 0 24 24");
  icon.setAttribute("aria-hidden", "true");
  icon.setAttribute("focusable", "false");
  paths.forEach((pathData) => {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", pathData);
    icon.append(path);
  });
  button.replaceChildren(icon);
}

function initializeTerminalNoteActions(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) {
    return;
  }
  root.querySelectorAll(".terminal-note").forEach((note) => {
    if (!(note instanceof HTMLElement) || note.dataset.terminalNoteActions === "1") {
      return;
    }
    const code = note.querySelector("code");
    if (!(code instanceof HTMLElement)) {
      return;
    }
    note.dataset.terminalNoteActions = "1";
    note.classList.add("has-actions");
    const actions = document.createElement("div");
    actions.className = "terminal-note-actions";
    const copyButton = document.createElement("button");
    copyButton.className = "button secondary icon-button";
    copyButton.type = "button";
    copyButton.setAttribute("aria-label", "Copy preview");
    copyButton.setAttribute("title", "Copy preview");
    appendButtonIcon(copyButton, [
      "M8 8.75a2 2 0 0 1 2-2h7.25a2 2 0 0 1 2 2V16a2 2 0 0 1-2 2H10a2 2 0 0 1-2-2z",
      "M5.75 15.25H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h7.25a2 2 0 0 1 2 2v.75",
    ]);
    const openButton = document.createElement("button");
    openButton.className = "button secondary icon-button";
    openButton.type = "button";
    openButton.setAttribute("aria-label", "Open preview");
    openButton.setAttribute("title", "Open preview");
    appendButtonIcon(openButton, ["M7 17 17 7", "M9 7h8v8"]);
    actions.append(copyButton);
    if (note.dataset.terminalNoteOpen !== "false") {
      actions.append(openButton);
    }
    note.prepend(actions);
    copyButton.addEventListener("click", async () => {
      try {
        await copyTextToClipboard(code.textContent || "");
      } catch {
        showTransientGridStatus("Copy failed");
      }
    });
    if (note.dataset.terminalNoteOpen !== "false") {
      openButton.addEventListener("click", () => openPreviewModal(terminalNoteTitle(note), code.textContent || "", code));
    }
  });
}

function rememberDnsActiveZone(domain) {
  if (!domain) {
    return;
  }
  try {
    window.localStorage.setItem(DNS_ACTIVE_ZONE_STORAGE_KEY, domain);
  } catch {
    // Tab persistence is a convenience only; private browsing can disable it.
  }
}

function storedDnsActiveZone() {
  try {
    return window.localStorage.getItem(DNS_ACTIVE_ZONE_STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

function dnsZoneTabButtonForDomain(domain) {
  if (!domain) {
    return null;
  }
  return Array.from(document.querySelectorAll(".zone-tabs [data-domain]")).find(
    (item) => item instanceof HTMLButtonElement && item.dataset.domain === domain,
  );
}

function showTableMessage(message, type = "error") {
  const element = document.getElementById("dns-record-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function showTableError(message) {
  showTableMessage(message, "error");
}

function showTableSuccess(message) {
  showTransientGridStatus(message);
}

function clearTableError() {
  const element = document.getElementById("dns-record-error");
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
}

function redrawDnsRecordTables(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) {
    return;
  }
  window.requestAnimationFrame(() => {
    root.querySelectorAll(".dns-records-table").forEach((tableElement) => {
      const table = atlasoDnsRecordTables.get(tableElement);
      if (table && typeof table.redraw === "function") {
        table.redraw(true);
      }
    });
  });
}

async function postDnsRecordAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (key === "id") {
      continue;
    }
    if (key === "host_label") {
      body.set("hostname", value ?? "");
      continue;
    }
    if (key === "enabled" || key === "masquerade") {
      if (value) {
        body.set(key, "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text.match(/DNS .* already exists[^<]*/)?.[0] || "The DNS record could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newDnsRecordRow(domain, suggestedAddress = "") {
  return {
    id: "__new__",
    hostname: "",
    host_label: "",
    domain,
    record_type: "A",
    address: suggestedAddress,
    suggested_ipv4: suggestedAddress,
    description: "",
    enabled: true,
    is_new: true,
    ...dnsRecordReverseStatus({
      record_type: "A",
      address: suggestedAddress,
      enabled: true,
    }),
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function atlasoBooleanFormatter(cell) {
  const enabled = Boolean(cell.getValue());
  const label = enabled ? "true" : "false";
  const glyph = enabled ? "✓" : "✕";
  const tone = enabled ? "good" : "bad";
  return `<span class="boolean-glyph ${tone}" aria-label="${label}" title="${label}">${glyph}</span>`;
}

function dnsRecordTypeLabel(value) {
  const labels = {
    A: "A (IPv4)",
    AAAA: "AAAA (IPv6)",
    CNAME: "CNAME (alias)",
    TXT: "TXT",
    SRV: "SRV",
    MX: "MX",
    CAA: "CAA",
    PTR: "PTR",
  };
  if (labels[value]) {
    return labels[value];
  }
  return String(value || "A");
}

function dnsRecordTypeOptions() {
  return {
    A: "A (IPv4)",
    AAAA: "AAAA (IPv6)",
    CNAME: "CNAME (alias)",
    TXT: "TXT",
    SRV: "SRV",
    MX: "MX",
    CAA: "CAA",
    PTR: "PTR",
  };
}

function dnsRecordValueHint(recordType) {
  if (recordType === "SRV") {
    return "target port priority weight";
  }
  if (recordType === "MX") {
    return "target preference";
  }
  if (recordType === "CAA") {
    return '0 issue "ca.example"';
  }
  if (recordType === "PTR") {
    return "target hostname";
  }
  if (recordType === "TXT") {
    return "text value";
  }
  if (recordType === "CNAME") {
    return "target hostname";
  }
  return "enter value...";
}

function legacyDnsRecordTypeLabel(value) {
  if (value === "AAAA") {
    return "AAAA (IPv6)";
  }
  if (value === "CNAME") {
    return "CNAME (alias)";
  }
  return "A (IPv4)";
}

function dnsAddRowHintFormatter(cell, emptyText) {
  const data = cell.getRow().getData();
  const value = cell.getValue();
  if (data.is_new && !String(value ?? "").trim()) {
    return `<span class="add-row-hint">${escapeHtml(emptyText)}</span>`;
  }
  return escapeHtml(value);
}

function newRecordRequiredValue(data, field) {
  return String(data?.[field] ?? "").trim();
}

function newRecordRequiredCellEditable(cell, requiredField) {
  const data = cell.getRow().getData();
  if (data.requires_activation && !data.is_activated) {
    return false;
  }
  return !data.is_new || data.is_activated || cell.getField() === requiredField || Boolean(newRecordRequiredValue(data, requiredField));
}

function markNewRecordRow(row, requiredField, actionField = "") {
  const data = row.getData();
  const isNew = Boolean(data.is_new);
  const isPending = isNew && !data.is_activated && !newRecordRequiredValue(data, requiredField);
  const element = row.getElement();
  element.classList.toggle("new-record-row", isNew);
  element.classList.toggle("new-record-row-pending", isPending);
  row.getCells().forEach((cell) => {
    cell.getElement().classList.toggle("new-record-primary-cell", cell.getField() === requiredField);
    cell.getElement().classList.toggle("new-record-action-cell", Boolean(actionField) && cell.getField() === actionField);
  });
}

function lockNewRecordColumns(columns, requiredField) {
  return columns.map((column) => {
    const originalEditable = column.editable;
    return {
      ...column,
      editable: (cell) => {
        const baseEditable = typeof originalEditable === "function" ? originalEditable(cell) : originalEditable !== false;
        return baseEditable && newRecordRequiredCellEditable(cell, requiredField);
      },
    };
  });
}

function reformatPendingNewRecord(cell) {
  const row = cell.getRow();
  if (row.getData().is_new) {
    row.reformat();
  }
}

function pendingNewDnsRecord(data) {
  return Boolean(data?.is_new && !String(data.host_label ?? "").trim());
}

function dnsRecordDomainFormatter(cell) {
  const data = cell.getRow().getData();
  if (pendingNewDnsRecord(data)) {
    return "";
  }
  return escapeHtml(cell.getValue());
}

let dhcpRangeTooltip = null;

function parseIpv4AddressParts(value) {
  const parts = String(value ?? "").trim().split(".");
  if (parts.length !== 4) {
    return null;
  }
  const octets = parts.map((part) => {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const number = Number(part);
    return number >= 0 && number <= 255 ? number : null;
  });
  return octets.some((part) => part === null) ? null : octets;
}

function parseCompactIpv4RangeEnd(value, startParts) {
  const parts = String(value ?? "").trim().split(".");
  if (!parts.length || parts.length > 4 || parts.some((part) => !/^\d+$/.test(part))) {
    return null;
  }
  const suffix = parts.map((part) => Number(part));
  if (suffix.some((part) => part < 0 || part > 255)) {
    return null;
  }
  return [...startParts.slice(0, 4 - suffix.length), ...suffix];
}

function ipv4PartsToText(parts) {
  return Array.isArray(parts) && parts.length === 4 ? parts.join(".") : "";
}

function dhcpRangeTooltipRows(data) {
  const expression = String(data?.range_expression ?? "").trim();
  if (!expression) {
    return [];
  }
  return expression
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [rawStart, rawEnd] = item.split("-", 2).map((part) => part.trim());
      if (!rawStart) {
        return null;
      }
      if (data?.address_family === "ipv6") {
        return { start: rawStart, end: rawEnd || rawStart };
      }
      const startParts = parseIpv4AddressParts(rawStart);
      if (!startParts) {
        return null;
      }
      const endParts = rawEnd ? parseCompactIpv4RangeEnd(rawEnd, startParts) : startParts;
      if (!endParts) {
        return null;
      }
      return { start: ipv4PartsToText(startParts), end: ipv4PartsToText(endParts) };
    })
    .filter(Boolean);
}

function ensureDhcpRangeTooltip() {
  if (!dhcpRangeTooltip) {
    dhcpRangeTooltip = document.createElement("div");
    dhcpRangeTooltip.className = "dhcp-range-tooltip hidden";
    document.body.appendChild(dhcpRangeTooltip);
  }
  return dhcpRangeTooltip;
}

function moveDhcpRangeTooltip(event) {
  if (!dhcpRangeTooltip || dhcpRangeTooltip.classList.contains("hidden")) {
    return;
  }
  const offset = 12;
  const width = dhcpRangeTooltip.offsetWidth || 240;
  const height = dhcpRangeTooltip.offsetHeight || 120;
  const x = Math.min(event.clientX + offset, window.innerWidth - width - offset);
  const y = Math.min(event.clientY + offset, window.innerHeight - height - offset);
  dhcpRangeTooltip.style.left = `${Math.max(offset, x)}px`;
  dhcpRangeTooltip.style.top = `${Math.max(offset, y)}px`;
}

function showDhcpRangeTooltip(event, data) {
  const rows = dhcpRangeTooltipRows(data);
  if (!rows.length) {
    return;
  }
  const tooltip = ensureDhcpRangeTooltip();
  tooltip.innerHTML = `
    <table>
      <thead><tr><th>Start</th><th>End</th></tr></thead>
      <tbody>
        ${rows.map((row) => `<tr><td>${escapeHtml(row.start)}</td><td>${escapeHtml(row.end)}</td></tr>`).join("")}
      </tbody>
    </table>
  `;
  tooltip.classList.remove("hidden");
  moveDhcpRangeTooltip(event);
}

function hideDhcpRangeTooltip() {
  if (dhcpRangeTooltip) {
    dhcpRangeTooltip.classList.add("hidden");
  }
}

function dhcpRangeFormatter(cell) {
  const data = cell.getRow().getData();
  const value = String(cell.getValue() ?? "").trim();
  if (data.is_new && !value) {
    if (!String(data.name ?? "").trim()) {
      return "";
    }
    if (data.address_family === "ipv6") {
      return "";
    }
    return dnsAddRowHintFormatter(cell, "192.168.87.100-192.168.87.200, 192.168.87.222");
  }
  const element = document.createElement("span");
  element.className = "dhcp-range-value";
  element.textContent = value;
  if (dhcpRangeTooltipRows(data).length) {
    element.addEventListener("mouseenter", (event) => showDhcpRangeTooltip(event, data));
    element.addEventListener("mousemove", moveDhcpRangeTooltip);
    element.addEventListener("mouseleave", hideDhcpRangeTooltip);
  }
  return element;
}

function dnsRecordCellEditable(cell) {
  const data = cell.getRow().getData();
  if (!data.is_new) {
    return true;
  }
  if (cell.getField() === "host_label") {
    return true;
  }
  return Boolean(String(data.host_label ?? "").trim());
}

function ipv4ReversePointer(value) {
  const parts = String(value ?? "").trim().split(".");
  if (parts.length !== 4) {
    return "";
  }
  const octets = parts.map((part) => {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const number = Number(part);
    return number >= 0 && number <= 255 ? String(number) : null;
  });
  if (octets.some((part) => part === null)) {
    return "";
  }
  return `${octets.reverse().join(".")}.in-addr.arpa`;
}

function expandIpv6(value) {
  const address = String(value ?? "").trim().toLowerCase();
  if (!address || address.includes(".")) {
    return null;
  }
  const doubleColonParts = address.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }
  const head = doubleColonParts[0] ? doubleColonParts[0].split(":") : [];
  const tail = doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(":") : [];
  const explicitGroups = [...head, ...tail];
  if (explicitGroups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }
  const missingGroups = 8 - explicitGroups.length;
  if ((doubleColonParts.length === 1 && missingGroups !== 0) || missingGroups < 0) {
    return null;
  }
  const groups = doubleColonParts.length === 2 ? [...head, ...Array(missingGroups).fill("0"), ...tail] : explicitGroups;
  return groups.length === 8 ? groups.map((group) => group.padStart(4, "0")).join("") : null;
}

function ipv6ReversePointer(value) {
  const expanded = expandIpv6(value);
  return expanded ? `${expanded.split("").reverse().join(".")}.ip6.arpa` : "";
}

function dnsRecordReverseStatus(data) {
  const type = String(data.record_type || "A").toUpperCase();
  if (type !== "A" && type !== "AAAA") {
    return {
      reverse_status: "not-applicable",
      reverse_label: "not applicable",
      reverse_ptr: "",
      reverse_zone: "",
    };
  }
  if (!data.enabled) {
    return {
      reverse_status: "disabled",
      reverse_label: "disabled",
      reverse_ptr: "",
      reverse_zone: "",
    };
  }
  const ptrName = type === "AAAA" ? ipv6ReversePointer(data.address) : ipv4ReversePointer(data.address);
  if (!ptrName) {
    return {
      reverse_status: data.address ? "invalid" : "pending",
      reverse_label: data.address ? "invalid address" : "",
      reverse_ptr: "",
      reverse_zone: "",
    };
  }
  return {
    reverse_status: "generated",
    reverse_label: ptrName,
    reverse_ptr: ptrName,
    reverse_zone: type === "AAAA" ? ptrName.split(".").slice(16).join(".") : ptrName.split(".").slice(1).join("."),
  };
}

function reverseStatusFormatter(cell) {
  const data = cell.getRow().getData();
  const status = data.reverse_status || "pending";
  const label = data.reverse_label || "";
  if (status === "generated") {
    return `<span class="reverse-status good" title="${escapeHtml(label)}">${escapeHtml(label)}</span>`;
  }
  if (status === "invalid") {
    return '<span class="reverse-status warn">invalid address</span>';
  }
  if (status === "disabled") {
    return '<span class="reverse-status muted">disabled</span>';
  }
  if (status === "not-applicable") {
    return '<span class="reverse-status muted">not applicable</span>';
  }
  return '<span class="reverse-status muted">waiting for value</span>';
}

function hasRequiredDnsRecordFields(data) {
  return Boolean((data.host_label || "").trim() && (data.address || "").trim());
}

async function autoSaveDnsRecord(cell, csrf) {
  clearTableError();
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    const field = cell.getField();
    if (field === "host_label") {
      row.reformat();
    }
    if (field === "record_type" && data.suggested_ipv4) {
      if (data.record_type !== "A" && data.address === data.suggested_ipv4) {
        await row.update({ address: "", ...dnsRecordReverseStatus({ ...data, address: "" }) });
        return;
      }
      if (data.record_type === "A" && !data.address) {
        await row.update({ address: data.suggested_ipv4, ...dnsRecordReverseStatus({ ...data, address: data.suggested_ipv4 }) });
        return;
      }
    }
    if (["record_type", "address", "enabled"].includes(field)) {
      await row.update(dnsRecordReverseStatus(row.getData()));
    }
    if (!hasRequiredDnsRecordFields(data)) {
      return;
    }
    try {
      await postDnsRecordAction("/dns/records", data, csrf, { reload: false });
      rememberDnsActiveZone(data.domain);
      showTableSuccess("Added");
      window.location.reload();
    } catch (error) {
      showTableError(error instanceof Error ? error.message : "The DNS record could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postDnsRecordAction(`/dns/records/${data.id}/edit`, data, csrf, { reload: false });
    row.update(dnsRecordReverseStatus(row.getData()));
    showTableSuccess("Saved");
  } catch (error) {
    showTableError(error instanceof Error ? error.message : "The DNS record could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteDnsRecordFromMenu(row, csrf) {
  clearTableError();
  const data = row.getData();
  try {
    rememberDnsActiveZone(data.domain);
    await postDnsRecordAction(`/dns/records/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showTableError(error instanceof Error ? error.message : "The DNS record could not be deleted.");
  }
}

function showDhcpReservationMessage(message, type = "error") {
  const element = document.getElementById("dhcp-reservation-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function showTransientGridStatus(message) {
  let toast = document.getElementById("grid-status-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "grid-status-toast";
    toast.className = "grid-status-toast";
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(showTransientGridStatus.timeoutId);
  showTransientGridStatus.timeoutId = window.setTimeout(() => {
    toast.classList.remove("visible");
  }, 1400);
}

async function atlasoGridWizardRequest(url, formData, { expectJson = true } = {}) {
  const response = await fetch(url, {
    method: "POST",
    body: formData,
    credentials: "same-origin",
    headers: { Accept: "application/json", "X-Atlaso-Grid": "1" },
  });
  const responseText = await response.text();
  if (!response.ok) {
    let detail = "";
    try {
      const payload = JSON.parse(responseText);
      detail = payload.detail || payload.message || "";
    } catch (_error) {
      detail = responseText.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    }
    throw new Error(detail || "The resource could not be saved.");
  }
  return expectJson && responseText ? JSON.parse(responseText) : null;
}

function populateAtlasoWizardForm(form, data = {}, { recordField = "record_id", defaults = {} } = {}) {
  const values = { ...defaults, ...(data || {}) };
  const recordControl = form.elements.namedItem(recordField);
  if (recordControl) {
    recordControl.value = data?.is_new ? "" : (data?.id ?? "");
  }
  const names = new Set(
    [...form.elements]
      .map((control) => control.name)
      .filter((name) => name && name !== "csrf" && name !== recordField),
  );
  names.forEach((name) => {
    const controls = [...form.querySelectorAll(`[name="${CSS.escape(name)}"]`)];
    const value = values[name];
    if (!controls.length) return;
    if (controls[0].type === "radio") {
      controls.forEach((control) => {
        control.checked = String(control.value) === String(value ?? "");
      });
      return;
    }
    if (controls[0].type === "checkbox") {
      if (controls.length === 1) {
        controls[0].checked = Boolean(value);
        return;
      }
      const selected = new Set(
        Array.isArray(value)
          ? value.map(String)
          : String(value || "").split(/[\s,\n]+/).filter(Boolean),
      );
      controls.forEach((control) => {
        control.checked = selected.has(String(control.value));
      });
      return;
    }
    if (controls[0] instanceof HTMLSelectElement && controls[0].multiple) {
      const selected = new Set(
        Array.isArray(value)
          ? value.map(String)
          : String(value || "").split(/[\s,\n]+/).filter(Boolean),
      );
      [...controls[0].options].forEach((option) => {
        option.selected = selected.has(String(option.value));
      });
      return;
    }
    controls[0].value = Array.isArray(value) ? value.join("\n") : (value ?? "");
  });
}

function atlasoWizardReviewValue(form, item) {
  if (typeof item.value === "function") {
    return item.value(form);
  }
  const controls = [...form.querySelectorAll(`[name="${CSS.escape(item.field)}"]`)];
  if (!controls.length) return "";
  if (controls[0].type === "checkbox") {
    if (controls.length === 1) return controls[0].checked ? "Enabled" : "Disabled";
    return controls.filter((control) => control.checked).map((control) => control.value).join(", ");
  }
  if (controls[0].type === "radio") {
    return controls.find((control) => control.checked)?.value || "";
  }
  if (controls[0] instanceof HTMLSelectElement) {
    return [...controls[0].selectedOptions].map((option) => option.textContent?.trim() || "").filter(Boolean).join(", ");
  }
  return controls[0].value.trim() || "Not set";
}

function renderAtlasoWizardReview(form, reviewItems = []) {
  const review = form.querySelector("[data-atlaso-resource-review]");
  if (!(review instanceof HTMLElement)) return;
  review.innerHTML = reviewItems.map((item) => (
    `<div><span>${escapeHtml(item.label)}</span><strong>${escapeHtml(atlasoWizardReviewValue(form, item))}</strong></div>`
  )).join("");
}

function validateAtlasoWizardStep({ form, step }) {
  const page = form.querySelector(`[data-atlaso-wizard-step="${CSS.escape(step.id)}"]`);
  if (!(page instanceof HTMLElement)) return { valid: true };
  const invalid = [...page.querySelectorAll("input, select, textarea")]
    .find((control) => !control.disabled && typeof control.checkValidity === "function" && !control.checkValidity());
  if (!invalid) return { valid: true };
  invalid.reportValidity?.();
  return {
    valid: false,
    field: invalid.name || undefined,
    message: "Complete the required fields in this step before continuing.",
  };
}

function initializeAtlasoResourceWizard(config) {
  const element = document.getElementById(config.elementId);
  const form = document.querySelector(config.formSelector);
  const dialog = document.getElementById(config.dialogId);
  if (!(element instanceof HTMLElement) || !(form instanceof HTMLFormElement) || !(dialog instanceof HTMLDialogElement)) {
    return null;
  }
  const csrf = element.dataset.csrf || form.elements.namedItem("csrf")?.value || "";
  let table = null;
  let wizard = null;
  const rows = config.includeNewRow === false ? [...config.rows] : [...config.rows, config.newRow];
  const reportActionError = (error) => {
    const message = error instanceof Error ? error.message : String(error || "The resource action failed.");
    const status = config.actionErrorSelector
      ? document.querySelector(config.actionErrorSelector)
      : null;
    if (status instanceof HTMLElement) {
      status.textContent = message;
      status.classList.add("error");
      status.classList.remove("hidden");
      status.setAttribute("role", "alert");
      return;
    }
    showTransientGridStatus(message);
  };
  const wrapRowAction = (action) => ({
    ...action,
    ...(typeof action.action === "function"
      ? {
        action: (event, row) => Promise.resolve()
          .then(() => action.action(event, row))
          .catch(reportActionError),
      }
      : {}),
    ...(Array.isArray(action.menu) ? { menu: action.menu.map(wrapRowAction) } : {}),
  });

  const canEdit = (data) => !data.is_new && (typeof config.canEdit !== "function" || config.canEdit(data));
  const canDelete = (data) => !data.is_new && Boolean(config.deleteResource)
    && (typeof config.canDelete !== "function" || config.canDelete(data));
  const supportsInlineEnabled = config.inlineEnabled !== false
    && form.elements.namedItem("enabled") instanceof HTMLInputElement;
  const saveInlineEnabled = async (cell) => {
    const data = cell.getRow().getData();
    if (!canEdit(data)) {
      cell.restoreOldValue?.();
      return;
    }
    try {
      populateAtlasoWizardForm(form, data, {
        recordField: config.recordField || "record_id",
        defaults: config.defaults || {},
      });
      const enabledControl = form.elements.namedItem("enabled");
      if (!(enabledControl instanceof HTMLInputElement)) {
        throw new Error("This resource does not expose direct enablement.");
      }
      enabledControl.checked = Boolean(cell.getValue());
      const body = new FormData(form);
      config.prepareFormData?.({ body, form });
      const payload = await atlasoGridWizardRequest(config.editUrl(data.id), body);
      const resource = config.normalizeResource?.(payload[config.resourceName], payload) || payload[config.resourceName];
      if (!resource) throw new Error("The server did not return the saved resource.");
      await cell.getRow().update(resource);
      await Promise.resolve(config.onSaved?.({ payload, resource, form, table }));
      await refreshNetworkSideStack();
      showTransientGridStatus(resource.enabled ? "Enabled" : "Disabled");
    } catch (error) {
      cell.restoreOldValue?.();
      reportActionError(error);
    }
  };
  const openResource = (data, launcher) => {
    if (!data?.is_new && !canEdit(data)) return;
    wizard?.open({ launcher, context: data?.is_new ? null : data });
  };
  const deleteResource = async (row) => {
    const data = row.getData();
    const confirmation = config.deleteConfirmation(data);
    const confirmed = await requestConfirmation(confirmation);
    if (!confirmed) return;
    const body = new FormData();
    body.set("csrf", csrf);
    await atlasoGridWizardRequest(config.deleteUrl(data.id), body, { expectJson: false });
    await row.delete();
    await Promise.resolve(config.onDeleted?.({ data, table }));
    await refreshNetworkSideStack();
    showTransientGridStatus("Deleted");
  };
  const rowActions = [];
  if (config.editResource !== false) {
    rowActions.push({
      label: config.editLabel || "Edit",
      disabled: (row) => !canEdit(row.getData()),
      action: (_event, row) => openResource(row.getData(), row.getElement()),
    });
  }
  rowActions.push(...(config.extraActions || []).map(wrapRowAction));
  if (config.deleteResource) {
    rowActions.push({
      label: config.deleteLabel || "Delete",
      disabled: (row) => !canDelete(row.getData()),
      action: (_event, row) => deleteResource(row).catch(reportActionError),
    });
  }
  const configuredColumns = (config.options.columns || []).map((column) => (
    supportsInlineEnabled && column.field === "enabled"
      ? {
        ...column,
        editor: "tickCross",
        editable: (cell) => canEdit(cell.getRow().getData()),
        cellEdited: saveInlineEnabled,
        headerSort: false,
      }
      : column
  ));
  const options = {
    ...config.options,
    columns: configuredColumns,
    data: rows,
    index: "id",
  };
  const grid = window.AtlasoUiPatterns.createGrid({
    element,
    fallback: `#${element.dataset.fallbackId}`,
    status: config.statusSelector,
    pattern: "wizard-backed",
    emptyMessage: config.emptyMessage,
    onOpenRow: (data, row, event) => openResource(data, event?.currentTarget || row?.getElement?.()),
    rowActions,
    options,
  });
  table = grid.table;
  if (!table) {
    grid.setError(config.gridError || "Resource changes are unavailable because the interactive grid could not initialize.");
    return { grid, table: null, wizard: null };
  }
  element.atlasoTabulator = table;

  wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: config.steps,
    discardTitle: config.discardTitle,
    discardMessage: config.discardMessage,
    onOpen: ({ context }) => {
      populateAtlasoWizardForm(form, context || {}, {
        recordField: config.recordField || "record_id",
        defaults: config.defaults || {},
      });
      const submit = form.querySelector("[data-atlaso-wizard-submit]");
      if (submit) submit.textContent = context ? config.updateLabel : config.createLabel;
      config.onOpen?.({ form, context });
    },
    validateStep: async (state) => {
      const requiredFields = validateAtlasoWizardStep(state);
      if (!requiredFields.valid || typeof config.validateStep !== "function") return requiredFields;
      return config.validateStep(state);
    },
    onStepChange: (state) => config.onStepChange?.(state),
    prepareReview: () => {
      renderAtlasoWizardReview(form, config.reviewItems);
      config.prepareReview?.({ form });
    },
    onSubmit: async () => {
      const body = new FormData(form);
      config.prepareFormData?.({ body, form });
      const recordId = body.get(config.recordField || "record_id");
      const url = recordId ? config.editUrl(recordId) : config.createUrl;
      const payload = await atlasoGridWizardRequest(url, body);
      const resource = config.normalizeResource?.(payload[config.resourceName], payload) || payload[config.resourceName];
      if (!resource) throw new Error("The server did not return the saved resource.");
      if (recordId) {
        const existingRow = table.getRow(recordId) || table.getRow(Number(recordId));
        await existingRow?.update(resource);
      } else if (config.includeNewRow === false) {
        await table.addRow(resource, true);
      } else {
        await table.addRow(resource, true, config.newRow.id);
      }
      await Promise.resolve(config.onSaved?.({ payload, resource, form, table }));
      await refreshNetworkSideStack();
      showTransientGridStatus(recordId ? "Updated" : "Created");
      return { valid: true };
    },
  });
  if (config.addLauncherSelector) {
    document.querySelectorAll(config.addLauncherSelector).forEach((launcher) => {
      if (!(launcher instanceof HTMLButtonElement)) return;
      launcher.addEventListener("click", () => openResource(config.newRow, launcher));
    });
  } else {
    element.addEventListener("click", (event) => {
      const launcher = event.target.closest("[data-atlaso-wizard-add]");
      if (launcher instanceof HTMLButtonElement) openResource(config.newRow, launcher);
    });
  }
  return { grid, table, wizard };
}

function selectElementText(element) {
  const selection = window.getSelection();
  if (!selection || !(element instanceof HTMLElement)) {
    return false;
  }
  const range = document.createRange();
  range.selectNodeContents(element);
  selection.removeAllRanges();
  selection.addRange(range);
  return !selection.isCollapsed;
}

function copyTextWithTextareaFallback(value) {
  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  document.body.appendChild(textarea);
  textarea.focus({ preventScroll: true });
  textarea.select();
  textarea.setSelectionRange(0, value.length);
  const copied = document.execCommand("copy");
  textarea.remove();
  return copied;
}

async function copyTextToClipboard(text, successMessage = "Copied", fallbackSelectionElement = null) {
  const value = String(text || "");
  if (!value) {
    return;
  }
  let copied = false;
  if (window.isSecureContext && window.navigator?.clipboard && typeof window.navigator.clipboard.writeText === "function") {
    try {
      await window.navigator.clipboard.writeText(value);
      copied = true;
    } catch {
      copied = copyTextWithTextareaFallback(value);
    }
  } else {
    copied = copyTextWithTextareaFallback(value);
  }
  if (copied) {
    showTransientGridStatus(successMessage);
    return;
  }
  if (selectElementText(fallbackSelectionElement)) {
    showTransientGridStatus("Selected");
    return;
  }
  throw new Error("Copy command failed.");
}

function selectCopyButtonFallbackText(button) {
  const valueElement = button.closest(".ca-fingerprint-value")?.querySelector("strong") || button;
  const selection = window.getSelection();
  if (!selection || !valueElement) {
    return false;
  }
  const range = document.createRange();
  range.selectNodeContents(valueElement);
  selection.removeAllRanges();
  selection.addRange(range);
  return !selection.isCollapsed;
}

async function copyValueButtonText(button) {
  try {
    await copyTextToClipboard(button.dataset.copyValue || button.textContent || "");
  } catch {
    showTransientGridStatus(selectCopyButtonFallbackText(button) ? "Selected" : "Copy failed");
  }
}

function initializeCopyValueButtons(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) {
    return;
  }
  root.querySelectorAll("[data-copy-value]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement) || button.dataset.copyInitialized === "1") {
      return;
    }
    button.dataset.copyInitialized = "1";
    button.addEventListener("click", () => copyValueButtonText(button));
  });
}

function downloadValueButtonText(button) {
  const value = button.dataset.downloadValue || "";
  const filename = button.dataset.downloadFilename || "atlaso.txt";
  const mime = button.dataset.downloadMime || "text/plain;charset=utf-8";
  const objectUrl = URL.createObjectURL(new Blob([value], { type: mime }));
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
  showTransientGridStatus("Saved");
}

function initializeDownloadValueButtons(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) {
    return;
  }
  root.querySelectorAll("[data-download-value]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement) || button.dataset.downloadInitialized === "1") {
      return;
    }
    button.dataset.downloadInitialized = "1";
    button.addEventListener("click", () => downloadValueButtonText(button));
  });
}

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) {
    return;
  }
  const button = target.closest("[data-copy-value]");
  if (!(button instanceof HTMLButtonElement) || button.dataset.copyInitialized === "1") {
    return;
  }
  event.preventDefault();
  copyValueButtonText(button);
});

document.addEventListener("click", (event) => {
  const target = event.target;
  if (!(target instanceof Element)) {
    return;
  }
  const button = target.closest("[data-download-value]");
  if (!(button instanceof HTMLButtonElement) || button.dataset.downloadInitialized === "1") {
    return;
  }
  event.preventDefault();
  downloadValueButtonText(button);
});

function showDhcpReservationError(message) {
  showDhcpReservationMessage(message, "error");
}

function showDhcpReservationSuccess(message) {
  showTransientGridStatus(message);
}

function clearDhcpReservationError() {
  const element = document.getElementById("dhcp-reservation-error");
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
}

function showDhcpScopeMessage(message, type = "error") {
  const element = document.getElementById("dhcp-scope-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function showDhcpScopeError(message) {
  showDhcpScopeMessage(message, "error");
}

function showDhcpScopeSuccess(message) {
  showTransientGridStatus(message);
}

function clearDhcpScopeError() {
  const element = document.getElementById("dhcp-scope-error");
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
}

function showDhcpOptionMessage(message, type = "error") {
  const element = document.getElementById("dhcp-option-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function showDhcpOptionError(message) {
  showDhcpOptionMessage(message, "error");
}

function showDhcpOptionSuccess(message) {
  showTransientGridStatus(message);
}

function clearDhcpOptionError() {
  const element = document.getElementById("dhcp-option-error");
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
}

async function postDhcpScopeAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (key === "id" || key === "is_new") {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text.match(/DHCP IP zone .*?(?:already exists|family cannot be changed after it is created)[^<]*/)?.[0] || "The DHCP IP zone could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

async function postDhcpOptionAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (key === "id" || key === "is_new") {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw new Error("The DHCP option could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function normalizeDhcpZoneName(value) {
  return String(value || "").trim().toLowerCase();
}

function dhcpInterfaceDefaults(defaults, interfaceName) {
  const entries = Array.isArray(defaults.interfaces) ? defaults.interfaces : [];
  return entries.find((item) => item.name === interfaceName) || entries[0] || {};
}

function dhcpDefaultFamilyForInterface(defaults, interfaceName) {
  const interfaceDefaults = dhcpInterfaceDefaults(defaults, interfaceName);
  if (interfaceDefaults.ipv4_address) {
    return "ipv4";
  }
  if (interfaceDefaults.ipv6_address) {
    return "ipv6";
  }
  return "ipv4";
}

function applyDhcpScopeInterfaceDefaults(rowData, defaults, options = {}) {
  const overwrite = options.overwrite ?? false;
  const interfaceDefaults = dhcpInterfaceDefaults(defaults, rowData.interface_name);
  const family = rowData.address_family === "ipv6" ? "ipv6" : "ipv4";
  const gateway = family === "ipv6" ? interfaceDefaults.ipv6_address : interfaceDefaults.ipv4_address;
  const prefix = family === "ipv6" ? interfaceDefaults.ipv6_prefix : interfaceDefaults.ipv4_prefix;
  const dnsDefault = family === "ipv6" ? interfaceDefaults.ipv6_dns_default : interfaceDefaults.ipv4_dns_default;
  const ntpDefault = family === "ipv6" ? interfaceDefaults.ipv6_ntp_default : interfaceDefaults.ipv4_ntp_default;
  if (overwrite) {
    rowData.site_address = gateway || "";
  } else if (!rowData.site_address && gateway) {
    rowData.site_address = gateway;
  }
  if (overwrite) {
    rowData.prefix_length = Number.isInteger(prefix) ? prefix : "";
  } else if (!rowData.prefix_length && Number.isInteger(prefix)) {
    rowData.prefix_length = prefix;
  }
  if (overwrite) {
    rowData.dns_server = dnsDefault || "";
  } else if (!rowData.dns_server && dnsDefault) {
    rowData.dns_server = dnsDefault;
  }
  if (overwrite) {
    rowData.ntp_server = ntpDefault || "";
  } else if (!rowData.ntp_server && ntpDefault) {
    rowData.ntp_server = ntpDefault;
  }
  if ((overwrite || !rowData.domain_name) && defaults.default_domain) {
    rowData.domain_name = defaults.default_domain;
  }
  return rowData;
}

function ipv4AddressToInteger(value) {
  const octets = String(value || "").trim().split(".");
  if (octets.length !== 4 || octets.some((part) => !/^\d+$/.test(part) || Number(part) > 255)) return null;
  return octets.reduce((result, part) => (result << 8n) + BigInt(part), 0n);
}

function integerToIpv4Address(value) {
  return [24n, 16n, 8n, 0n].map((shift) => Number((value >> shift) & 255n)).join(".");
}

function ipv6AddressToInteger(value) {
  const normalized = String(value || "").trim().toLowerCase().split("%", 1)[0];
  if (!normalized || (normalized.match(/::/g) || []).length > 1) return null;
  const [leftRaw, rightRaw = ""] = normalized.split("::");
  const left = leftRaw ? leftRaw.split(":") : [];
  const right = rightRaw ? rightRaw.split(":") : [];
  if (!normalized.includes("::") && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < (normalized.includes("::") ? 1 : 0)) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return groups.reduce((result, part) => (result << 16n) + BigInt(`0x${part}`), 0n);
}

function integerToIpv6Address(value) {
  const groups = Array.from({ length: 8 }, (_unused, index) => (
    Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16)
  ));
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== "0") {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === "0") end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestLength < 2) return groups.join(":");
  const before = groups.slice(0, bestStart).join(":");
  const after = groups.slice(bestStart + bestLength).join(":");
  return `${before}::${after}`;
}

function deriveDhcpLeaseRange(gateway, prefixValue, family = "ipv4") {
  const bits = family === "ipv6" ? 128 : 32;
  const prefix = Number(prefixValue);
  const address = family === "ipv6" ? ipv6AddressToInteger(gateway) : ipv4AddressToInteger(gateway);
  if (address === null || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) return "";
  const hostBits = BigInt(bits - prefix);
  const allBits = (1n << BigInt(bits)) - 1n;
  const hostMask = hostBits ? (1n << hostBits) - 1n : 0n;
  const network = address & (allBits ^ hostMask);
  const firstUsable = network + 1n;
  const lastUsable = network + hostMask - (family === "ipv4" ? 1n : 0n);
  if (lastUsable < firstUsable) return "";
  let start = network + 100n <= lastUsable ? network + 100n : firstUsable;
  let end = network + 200n <= lastUsable ? network + 200n : lastUsable;
  if (address >= start && address <= end) {
    const addressesBeforeGateway = address - start;
    const addressesAfterGateway = end - address;
    if (addressesAfterGateway > addressesBeforeGateway) {
      start = address + 1n;
    } else {
      end = address - 1n;
    }
  }
  if (end < start) return "";
  const format = family === "ipv6" ? integerToIpv6Address : integerToIpv4Address;
  return `${format(start)}-${format(end)}`;
}

function isUniqueNewDhcpScopeName(data, existingNames) {
  const name = normalizeDhcpZoneName(data.name);
  return Boolean(name) && !existingNames.has(name);
}

function dhcpScopeCellEditable(cell, existingNames) {
  const data = cell.getRow().getData();
  if (!data.is_new) {
    return true;
  }
  if (cell.getField() === "name") {
    return true;
  }
  return isUniqueNewDhcpScopeName(data, existingNames);
}

function dhcpScopeFamilyEditable(cell, existingNames) {
  const data = cell.getRow().getData();
  if (!data.is_new) {
    return false;
  }
  return dhcpScopeCellEditable(cell, existingNames);
}

function newDhcpScopeRow(defaultInterface = "eth2", defaults = {}) {
  return {
    id: "__new__",
    name: "",
    address_family: "",
    interface_name: "",
    site_address: "",
    prefix_length: "",
    range_expression: "",
    lease_time: "",
    domain_name: "",
    dns_server: "",
    ntp_server: "",
    enabled: true,
    description: "",
    is_new: true,
  };
}

function newDhcpOptionRow() {
  return {
    id: "__new__",
    scope_id: "__global__",
    option_code: "",
    value: "",
    description: "",
    enabled: true,
    is_new: true,
  };
}

function hasRequiredDhcpOptionFields(data) {
  return Boolean((data.option_code || "").trim() && (data.value || "").trim());
}

async function autoSaveDhcpOption(cell, csrf) {
  clearDhcpOptionError();
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredDhcpOptionFields(data)) {
      return;
    }
    try {
      await postDhcpOptionAction("/dhcp/options", data, csrf, { reload: false });
      showDhcpOptionSuccess("Added");
      window.location.reload();
    } catch (error) {
      showDhcpOptionError(error instanceof Error ? error.message : "The DHCP option could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postDhcpOptionAction(`/dhcp/options/${data.id}/edit`, data, csrf, { reload: false });
    showDhcpOptionSuccess("Saved");
  } catch (error) {
    showDhcpOptionError(error instanceof Error ? error.message : "The DHCP option could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteDhcpOptionFromMenu(row, csrf) {
  clearDhcpOptionError();
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete DHCP option ${data.option_code}?`,
    message: "This removes the DHCP option from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete option",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postDhcpOptionAction(`/dhcp/options/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showDhcpOptionError(error instanceof Error ? error.message : "The DHCP option could not be deleted.");
  }
}

function hasRequiredDhcpScopeFields(data) {
  return Boolean(
    (data.name || "").trim() &&
      (data.address_family || "").trim() &&
      (data.interface_name || "").trim() &&
      (data.site_address || "").trim() &&
      String(data.prefix_length ?? "").trim() &&
      (data.range_expression || "").trim() &&
      (data.lease_time || "").trim() &&
      (data.domain_name || "").trim(),
  );
}

async function autoSaveDhcpScope(cell, csrf) {
  clearDhcpScopeError();
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredDhcpScopeFields(data)) {
      return;
    }
    try {
      await postDhcpScopeAction("/dhcp/scopes", data, csrf, { reload: false });
      showDhcpScopeSuccess("Added");
      window.location.reload();
    } catch (error) {
      showDhcpScopeError(error instanceof Error ? error.message : "The DHCP IP zone could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postDhcpScopeAction(`/dhcp/scopes/${data.id}/edit`, data, csrf, { reload: false });
    showDhcpScopeSuccess("Saved");
  } catch (error) {
    showDhcpScopeError(error instanceof Error ? error.message : "The DHCP IP zone could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteDhcpScopeFromMenu(row, csrf) {
  clearDhcpScopeError();
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name} IP zone?`,
    message: `This removes DHCP IP zone ${data.name} from Atlaso desired state. It will not touch the appliance until global appliance apply runs.`,
    label: "Delete IP zone",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postDhcpScopeAction(`/dhcp/scopes/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showDhcpScopeError(error instanceof Error ? error.message : "The DHCP IP zone could not be deleted.");
  }
}

async function postDhcpReservationAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (key === "id" || key === "is_new") {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text.match(/DHCP reservation already exists[^<]*/)?.[0] || "The DHCP reservation could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newDhcpReservationRow() {
  return {
    id: "__new__",
    hostname: "",
    mac_address: "",
    ip_address: "",
    description: "",
    enabled: true,
    is_new: true,
  };
}

function hasRequiredDhcpReservationFields(data) {
  return Boolean((data.hostname || "").trim() && (data.mac_address || "").trim() && (data.ip_address || "").trim());
}

function dhcpReservationHasHostname(data) {
  return Boolean(String(data.hostname ?? "").trim());
}

function dhcpReservationCellEditable(cell) {
  const data = cell.getRow().getData();
  if (!data.is_new) {
    return true;
  }
  if (cell.getField() === "hostname") {
    return true;
  }
  return dhcpReservationHasHostname(data);
}

function dhcpReservationAddRowHintFormatter(cell, hint) {
  const data = cell.getRow().getData();
  if (data.is_new && !dhcpReservationHasHostname(data) && !String(cell.getValue() ?? "").trim()) {
    return "";
  }
  return dnsAddRowHintFormatter(cell, hint);
}

async function autoSaveDhcpReservation(cell, csrf) {
  clearDhcpReservationError();
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredDhcpReservationFields(data)) {
      return;
    }
    try {
      await postDhcpReservationAction("/dhcp/reservations", data, csrf, { reload: false });
      showDhcpReservationSuccess("Added");
      window.location.reload();
    } catch (error) {
      showDhcpReservationError(error instanceof Error ? error.message : "The DHCP reservation could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postDhcpReservationAction(`/dhcp/reservations/${data.id}/edit`, data, csrf, { reload: false });
    showDhcpReservationSuccess("Saved");
  } catch (error) {
    showDhcpReservationError(error instanceof Error ? error.message : "The DHCP reservation could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteDhcpReservationFromMenu(row, csrf) {
  clearDhcpReservationError();
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.hostname || data.mac_address} reservation?`,
    message: `This removes the DHCP reservation for ${data.mac_address} from Atlaso desired state. It will not touch the appliance until global appliance apply runs.`,
    label: "Delete reservation",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postDhcpReservationAction(`/dhcp/reservations/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showDhcpReservationError(error instanceof Error ? error.message : "The DHCP reservation could not be deleted.");
  }
}

function closeDhcpLeaseMenus(exceptMenu = null) {
  document.querySelectorAll("[data-lease-menu]").forEach((menu) => {
    if (menu !== exceptMenu) {
      menu.setAttribute("hidden", "");
    }
  });
}

function openDhcpLeaseReservationModal(source) {
  const modal = document.getElementById("dhcp-lease-reservation-modal");
  if (!(modal instanceof HTMLDialogElement)) {
    return;
  }
  const hostnameInput = modal.querySelector("[data-dhcp-lease-modal-hostname]");
  const macInput = modal.querySelector("[data-dhcp-lease-modal-mac-input]");
  const ipInput = modal.querySelector("[data-dhcp-lease-modal-ip-input]");
  const descriptionInput = modal.querySelector("[data-dhcp-lease-modal-description-input]");
  const macText = modal.querySelector("[data-dhcp-lease-modal-mac]");
  const ipText = modal.querySelector("[data-dhcp-lease-modal-ip]");
  const hostname = source instanceof HTMLElement ? source.dataset.hostname || "" : source?.hostname || "";
  const macAddress = source instanceof HTMLElement ? source.dataset.macAddress || "" : source?.mac_address || "";
  const ipAddress = source instanceof HTMLElement ? source.dataset.ipAddress || "" : source?.ip_address || "";
  if (hostnameInput instanceof HTMLInputElement) {
    hostnameInput.value = hostname;
  }
  if (macInput instanceof HTMLInputElement) {
    macInput.value = macAddress;
  }
  if (ipInput instanceof HTMLInputElement) {
    ipInput.value = ipAddress;
  }
  if (descriptionInput instanceof HTMLInputElement) {
    descriptionInput.value = `Created from live DHCP lease ${ipAddress}.`;
  }
  if (macText instanceof HTMLElement) {
    macText.textContent = macAddress;
  }
  if (ipText instanceof HTMLElement) {
    ipText.textContent = ipAddress;
  }
  closeDhcpLeaseMenus();
  if (typeof modal.showModal === "function") {
    modal.showModal();
  } else {
    modal.setAttribute("open", "");
  }
  if (hostnameInput instanceof HTMLInputElement) {
    hostnameInput.focus();
    hostnameInput.select();
  }
}

function dhcpLeaseHostname(source) {
  const hostname = source instanceof HTMLElement ? source.dataset.hostname || "" : source?.hostname || "";
  return String(hostname || "").trim().replace(/\.$/, "").toLowerCase();
}

function dhcpLeaseMacAddress(source) {
  return source instanceof HTMLElement ? source.dataset.macAddress || "" : source?.mac_address || "";
}

function dhcpLeaseIpAddress(source) {
  return source instanceof HTMLElement ? source.dataset.ipAddress || "" : source?.ip_address || "";
}

function defaultDhcpLeasePxeHostname(source) {
  const hostname = dhcpLeaseHostname(source);
  if (hostname && hostname !== "-") {
    return hostname;
  }
  const macSuffix = dhcpLeaseMacAddress(source).toLowerCase().replace(/[^0-9a-f]/g, "").slice(-6) || "host";
  return `esxi-${macSuffix}.atlaso.internal`;
}

function openDhcpLeasePxeModal(source) {
  const modal = document.getElementById("dhcp-lease-pxe-modal");
  if (!(modal instanceof HTMLDialogElement)) {
    return;
  }
  const hostnameInput = modal.querySelector("[data-dhcp-lease-pxe-hostname]");
  const macInput = modal.querySelector("[data-dhcp-lease-pxe-mac-input]");
  const ipInput = modal.querySelector("[data-dhcp-lease-pxe-ip-input]");
  const macText = modal.querySelector("[data-dhcp-lease-pxe-mac]");
  const ipText = modal.querySelector("[data-dhcp-lease-pxe-ip]");
  const macAddress = dhcpLeaseMacAddress(source);
  const ipAddress = dhcpLeaseIpAddress(source);
  if (hostnameInput instanceof HTMLInputElement) {
    hostnameInput.value = defaultDhcpLeasePxeHostname(source);
  }
  if (macInput instanceof HTMLInputElement) {
    macInput.value = macAddress;
  }
  if (ipInput instanceof HTMLInputElement) {
    ipInput.value = ipAddress;
  }
  if (macText instanceof HTMLElement) {
    macText.textContent = macAddress;
  }
  if (ipText instanceof HTMLElement) {
    ipText.textContent = ipAddress;
  }
  closeDhcpLeaseMenus();
  if (typeof modal.showModal === "function") {
    modal.showModal();
  } else {
    modal.setAttribute("open", "");
  }
  if (hostnameInput instanceof HTMLInputElement) {
    hostnameInput.focus();
    hostnameInput.select();
  }
}

function dhcpLeaseStatusFormatter(cell) {
  const status = String(cell.getValue() || "");
  return `<span class="status-pill ${status === "active" ? "good" : "muted"}">${escapeHtml(status || "unknown")}</span>`;
}

function submitDhcpLeaseAction(path, data, csrf) {
  const form = document.createElement("form");
  form.method = "post";
  form.action = path;
  const values = {
    csrf,
    hostname: data.hostname || "",
    mac_address: data.mac_address || "",
    ip_address: data.ip_address || "",
  };
  Object.entries(values).forEach(([name, value]) => {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.append(input);
  });
  document.body.append(form);
  form.requestSubmit();
}

function initializeDhcpLeasesTable() {
  const tableElement = document.getElementById("dhcp-leases-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showDhcpReservationError("Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const rows = JSON.parse(tableElement.dataset.leases || "[]");
  try {
    const atlasoGridOptions1 = {
      data: rows,
      layout: "fitColumns",
      height: "300px",
      rowHeight: 28,
      placeholder: "No DHCP leases reported.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Create reservation",
          action: (event, row) => openDhcpLeaseReservationModal(row.getData()),
        },
        {
          label: "Create PXE entry",
          action: (event, row) => openDhcpLeasePxeModal(row.getData()),
        },
        {
          label: "Deny DHCP for MAC",
          action: async (event, row) => {
            const data = row.getData();
            const confirmed = await requestConfirmation({
              title: `Deny DHCP for ${data.mac_address}?`,
              message: "This adds a Atlaso desired-state dnsmasq ignore rule for this MAC. It will not affect the appliance until global appliance apply runs.",
              label: "Deny DHCP",
            });
            if (confirmed) {
              submitDhcpLeaseAction("/dhcp/leases/deny", data, csrf);
            }
          },
        },
      ],
      columns: [
        { title: "Status", field: "status", formatter: dhcpLeaseStatusFormatter, width: 100 },
        { title: "DNS name / FQDN", field: "hostname", formatter: (cell) => escapeHtml(cell.getValue() || "-"), minWidth: 190 },
        { title: "IP", field: "ip_address", minWidth: 140 },
        { title: "Zone", field: "zone_name", formatter: (cell) => escapeHtml(cell.getValue() || "-"), minWidth: 120 },
        { title: "MAC", field: "mac_address", minWidth: 170 },
        { title: "Expires", field: "expires_at", minWidth: 210 },
        { title: "Client ID", field: "client_id", formatter: (cell) => escapeHtml(cell.getValue() || "-"), minWidth: 210 },
      ],
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "read-only",
      options: atlasoGridOptions1,
    }).table;
  } catch (error) {
    showDhcpReservationError(error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeDhcpLeaseReservationActions() {
  const reservationModal = document.getElementById("dhcp-lease-reservation-modal");
  if (reservationModal instanceof HTMLDialogElement && reservationModal.dataset.leaseReservationInitialized !== "1") {
    reservationModal.dataset.leaseReservationInitialized = "1";
    reservationModal.querySelectorAll("[data-dhcp-lease-modal-cancel]").forEach((button) => {
      if (button instanceof HTMLButtonElement) {
        button.addEventListener("click", () => reservationModal.close("cancel"));
      }
    });
    reservationModal.addEventListener("click", (event) => {
      if (event.target === reservationModal) {
        reservationModal.close("cancel");
      }
    });
  }
  const pxeModal = document.getElementById("dhcp-lease-pxe-modal");
  if (pxeModal instanceof HTMLDialogElement && pxeModal.dataset.leasePxeInitialized !== "1") {
    pxeModal.dataset.leasePxeInitialized = "1";
    pxeModal.querySelectorAll("[data-dhcp-lease-pxe-cancel]").forEach((button) => {
      if (button instanceof HTMLButtonElement) {
        button.addEventListener("click", () => pxeModal.close("cancel"));
      }
    });
    pxeModal.addEventListener("click", (event) => {
      if (event.target === pxeModal) {
        pxeModal.close("cancel");
      }
    });
  }
  document.querySelectorAll("[data-lease-menu-toggle]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement) || button.dataset.leaseMenuInitialized === "1") {
      return;
    }
    button.dataset.leaseMenuInitialized = "1";
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const menu = button.closest("[data-lease-action-menu]")?.querySelector("[data-lease-menu]");
      if (!(menu instanceof HTMLElement)) {
        return;
      }
      const isOpening = menu.hasAttribute("hidden");
      closeDhcpLeaseMenus(menu);
      menu.toggleAttribute("hidden", !isOpening);
    });
  });
  document.querySelectorAll("[data-dhcp-lease-reservation]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement) || button.dataset.leaseReservationButtonInitialized === "1") {
      return;
    }
    button.dataset.leaseReservationButtonInitialized = "1";
    button.addEventListener("click", () => openDhcpLeaseReservationModal(button));
  });
  document.querySelectorAll("[data-dhcp-lease-pxe-host]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement) || button.dataset.leasePxeButtonInitialized === "1") {
      return;
    }
    button.dataset.leasePxeButtonInitialized = "1";
    button.addEventListener("click", () => openDhcpLeasePxeModal(button));
  });
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof HTMLElement) || !event.target.closest("[data-lease-action-menu]")) {
      closeDhcpLeaseMenus();
    }
  });
}

function showEsxiHostMessage(message, type = "error") {
  const element = document.getElementById("esxi-pxe-host-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function showEsxiHostError(message) {
  showEsxiHostMessage(message, "error");
}

function showEsxiHostSuccess(message) {
  showTransientGridStatus(message);
}

function clearEsxiHostError() {
  const element = document.getElementById("esxi-pxe-host-error");
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
}

async function postEsxiHostAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (key === "id" || key === "is_new" || key === "is_default" || key === "variables" || key.endsWith("_name")) {
      continue;
    }
    if (key === "variables_json") {
      body.set("variables", value ?? "{}");
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }
  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text.match(/ESXi PXE host[^<]*/)?.[0] || text.match(/Default ESXi PXE[^<]*/)?.[0] || "The ESXi PXE host reference could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newEsxiHostRow(defaultIsoPath = "") {
  return {
    id: "new",
    hostname: "",
    mac_address: "",
    ip_address: "",
    kickstart_id: "",
    kickstart_name: "",
    installer_iso_path: defaultIsoPath,
    installer_iso_name: "",
    variables_json: "{}",
    enabled: true,
    is_new: true,
    is_default: false,
  };
}

function hasRequiredEsxiHostFields(data) {
  return Boolean((data.hostname || "").trim() && (data.mac_address || "").trim());
}

async function autoSaveEsxiHost(cell, csrf) {
  clearEsxiHostError();
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_default) {
    try {
      await postEsxiHostAction("/esxi-pxe/default-host", data, csrf, { reload: false });
      showEsxiHostSuccess("Saved");
    } catch (error) {
      showEsxiHostError(error instanceof Error ? error.message : "The default ESXi PXE host profile could not be saved.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  if (data.is_new) {
    if (!hasRequiredEsxiHostFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postEsxiHostAction("/esxi-pxe/hosts", data, csrf);
      showEsxiHostSuccess("Added");
    } catch (error) {
      showEsxiHostError(error instanceof Error ? error.message : "The ESXi PXE host reference could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postEsxiHostAction(`/esxi-pxe/hosts/${data.id}`, data, csrf, { reload: false });
    showEsxiHostSuccess("Saved");
  } catch (error) {
    showEsxiHostError(error instanceof Error ? error.message : "The ESXi PXE host reference could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteEsxiHost(row, csrf) {
  clearEsxiHostError();
  const data = row.getData();
  if (data.is_new || data.is_default) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.hostname} host reference?`,
    message: `This removes the ESXi PXE host reference for ${data.mac_address} from desired state. It will not touch generated PXE files until global appliance apply runs.`,
    label: "Delete host reference",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postEsxiHostAction(`/esxi-pxe/hosts/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showEsxiHostError(error instanceof Error ? error.message : "The ESXi PXE host reference could not be deleted.");
  }
}

function showCaMessage(elementId, message, type = "error") {
  const element = document.getElementById(elementId);
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function clearCaMessage(elementId) {
  const element = document.getElementById(elementId);
  if (!element) {
    return;
  }
  element.textContent = "";
  element.classList.add("hidden");
}

async function postCaAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (["id", "is_new", "profile_name", "managed_owner", "fingerprint", "cert_path", "has_certificate", "has_private_key"].includes(key)) {
      continue;
    }
    if (key === "enabled" || key === "san_required") {
      if (value) {
        body.set(key, "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    let message = text.match(/CA .* already exists[^<]*/)?.[0] || "The CA desired state could not be saved.";
    try {
      const payload = JSON.parse(text);
      if (Array.isArray(payload.detail)) {
        message = payload.detail.join(" ");
      } else if (typeof payload.detail === "string" && payload.detail.trim()) {
        message = payload.detail.trim();
      }
    } catch {
      // Non-JSON error responses keep the safe fallback above.
    }
    throw new Error(message);
  }
  if (reload) {
    window.location.reload();
  }
}

function newCaProfileRow() {
  return {
    id: "__new__",
    name: "",
    certificate_type: "server",
    validity_days: 825,
    key_algorithm: "RSA",
    key_size: 2048,
    key_usage: "digitalSignature,keyEncipherment",
    extended_key_usage: "serverAuth",
    san_required: true,
    enabled: true,
    description: "",
    is_new: true,
  };
}

function newCaCertificateRow(defaultProfileId = "") {
  return {
    id: "__new__",
    common_name: "",
    profile_id: defaultProfileId,
    profile_name: "",
    subject_alt_names: "",
    ip_addresses: "",
    status: "planned",
    serial_number: "",
    fingerprint: "",
    managed_owner: "manual",
    cert_path: "",
    has_certificate: false,
    has_private_key: false,
    can_edit: false,
    can_delete: false,
    can_export_certificate: false,
    can_export_chain: false,
    can_export_private_key: false,
    enabled: true,
    description: "",
    is_new: true,
  };
}

function hasRequiredCaProfileFields(data) {
  return Boolean((data.name || "").trim() && (data.certificate_type || "").trim());
}

async function autoSaveCaProfile(cell, csrf) {
  clearCaMessage("ca-profile-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredCaProfileFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postCaAction("/certificate-authority/profiles", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showCaMessage("ca-profile-error", error instanceof Error ? error.message : "The CA profile could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postCaAction(`/certificate-authority/profiles/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
  } catch (error) {
    showCaMessage("ca-profile-error", error instanceof Error ? error.message : "The CA profile could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteCaProfileFromMenu(row, csrf) {
  clearCaMessage("ca-profile-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name} profile?`,
    message: "This removes the CA profile from Atlaso desired state and unassigns requests using it. It will not touch the appliance until global appliance apply runs.",
    label: "Delete profile",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postCaAction(`/certificate-authority/profiles/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showCaMessage("ca-profile-error", error instanceof Error ? error.message : "The CA profile could not be deleted.");
  }
}

async function deleteCaCertificateFromMenu(row, csrf) {
  clearCaMessage("ca-certificate-error");
  const data = row.getData();
  if (data.is_new || !data.can_delete) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.common_name} certificate request?`,
    message: "This removes the certificate request from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete request",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postCaAction(`/certificate-authority/certificates/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showCaMessage("ca-certificate-error", error instanceof Error ? error.message : "The certificate request could not be deleted.");
  }
}

function caCertificateModalElements() {
  const modal = document.getElementById("ca-certificate-modal");
  const form = document.getElementById("ca-certificate-modal-form");
  if (!(modal instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement)) {
    return null;
  }
  return {
    modal,
    form,
    title: modal.querySelector("[data-ca-certificate-modal-title]"),
    message: modal.querySelector("[data-ca-certificate-modal-message]"),
    error: modal.querySelector("#ca-certificate-modal-error"),
    commonName: form.querySelector("[data-ca-certificate-common-name]"),
    profile: form.querySelector("[data-ca-certificate-profile]"),
    dnsSans: form.querySelector("[data-ca-certificate-dns-sans]"),
    ipSans: form.querySelector("[data-ca-certificate-ip-sans]"),
    description: form.querySelector("[data-ca-certificate-description]"),
    submit: form.querySelector("[data-ca-certificate-modal-submit]"),
  };
}

function selectedCaProfileRequiresSan(profileSelect) {
  if (!(profileSelect instanceof HTMLSelectElement)) {
    return false;
  }
  return profileSelect.selectedOptions[0]?.dataset.sanRequired === "true";
}

function validateCaCertificateModal(elements) {
  if (!elements) {
    return false;
  }
  if (elements.dnsSans instanceof HTMLTextAreaElement) {
    elements.dnsSans.setCustomValidity("");
  }
  const hasDnsSans = Boolean(elements.dnsSans instanceof HTMLTextAreaElement && elements.dnsSans.value.trim());
  const hasIpSans = Boolean(elements.ipSans instanceof HTMLTextAreaElement && elements.ipSans.value.trim());
  if (selectedCaProfileRequiresSan(elements.profile) && !hasDnsSans && !hasIpSans) {
    if (elements.dnsSans instanceof HTMLTextAreaElement) {
      elements.dnsSans.setCustomValidity("The selected profile requires at least one DNS name or IP SAN.");
      elements.dnsSans.reportValidity();
    }
    return false;
  }
  return elements.form.reportValidity();
}

function openCaCertificateModal(data = null) {
  const elements = caCertificateModalElements();
  if (!elements) {
    return;
  }
  const isEdit = Boolean(data && data.can_edit && !data.is_new);
  elements.form.reset();
  elements.form.action = isEdit ? `/certificate-authority/certificates/${data.id}/edit` : "/certificate-authority/certificates";
  elements.form.dataset.certificateId = isEdit ? String(data.id) : "";
  if (elements.title instanceof HTMLElement) {
    elements.title.textContent = isEdit ? "Edit certificate request" : "Create certificate request";
  }
  if (elements.message instanceof HTMLElement) {
    elements.message.textContent = isEdit
      ? "Update the complete unissued request before Atlaso signs it."
      : "Complete the certificate identity before Atlaso creates and issues it.";
  }
  if (elements.submit instanceof HTMLButtonElement) {
    elements.submit.textContent = isEdit ? "Save certificate request" : "Create certificate request";
    elements.submit.disabled = false;
  }
  if (elements.error instanceof HTMLElement) {
    elements.error.textContent = "";
    elements.error.classList.add("hidden");
  }
  if (elements.commonName instanceof HTMLInputElement) {
    elements.commonName.value = isEdit ? data.common_name || "" : "";
  }
  if (elements.profile instanceof HTMLSelectElement && isEdit) {
    elements.profile.value = String(data.profile_id || "");
  }
  if (elements.dnsSans instanceof HTMLTextAreaElement) {
    elements.dnsSans.value = isEdit ? data.subject_alt_names || "" : "";
    elements.dnsSans.setCustomValidity("");
  }
  if (elements.ipSans instanceof HTMLTextAreaElement) {
    elements.ipSans.value = isEdit ? data.ip_addresses || "" : "";
  }
  if (elements.description instanceof HTMLInputElement) {
    elements.description.value = isEdit ? data.description || "" : "";
  }
  if (typeof elements.modal.showModal === "function") {
    elements.modal.showModal();
  } else {
    elements.modal.setAttribute("open", "");
  }
  if (elements.commonName instanceof HTMLInputElement) {
    elements.commonName.focus();
    elements.commonName.select();
  }
}

function initializeCaCertificateModal() {
  const elements = caCertificateModalElements();
  if (!elements || elements.form.dataset.caCertificateModalInitialized === "1") {
    return;
  }
  elements.form.dataset.caCertificateModalInitialized = "1";
  const cancelButton = elements.modal.querySelector("[data-ca-certificate-modal-cancel]");
  cancelButton?.addEventListener("click", () => elements.modal.close());
  elements.profile?.addEventListener("change", () => {
    if (elements.dnsSans instanceof HTMLTextAreaElement) {
      elements.dnsSans.setCustomValidity("");
    }
  });
  elements.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!validateCaCertificateModal(elements)) {
      return;
    }
    if (elements.submit instanceof HTMLButtonElement) {
      elements.submit.disabled = true;
    }
    if (elements.error instanceof HTMLElement) {
      elements.error.textContent = "";
      elements.error.classList.add("hidden");
    }
    const formData = new FormData(elements.form);
    const data = Object.fromEntries(formData.entries());
    const csrf = String(formData.get("csrf") || "");
    try {
      await postCaAction(elements.form.action, data, csrf, { reload: false });
      showTransientGridStatus(elements.form.dataset.certificateId ? "Saved" : "Added");
      window.location.reload();
    } catch (error) {
      if (elements.error instanceof HTMLElement) {
        elements.error.textContent = error instanceof Error ? error.message : "The certificate request could not be saved.";
        elements.error.classList.remove("hidden");
      }
      if (elements.submit instanceof HTMLButtonElement) {
        elements.submit.disabled = false;
      }
    }
  });
}

function downloadCaCertificateArtifact(row, artifact) {
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const capability = {
    "certificate.pem": "can_export_certificate",
    "chain.pem": "can_export_chain",
    "private-key.pem": "can_export_private_key",
  }[artifact];
  if (!capability || !data[capability]) {
    return;
  }
  window.location.assign(`/certificate-authority/certificates/${data.id}/downloads/${artifact}`);
}

async function copyCaCertificateFingerprint(row) {
  const fingerprint = row.getData().fingerprint || "";
  if (!fingerprint) {
    return;
  }
  try {
    await copyTextToClipboard(fingerprint, "Fingerprint copied");
  } catch {
    showTransientGridStatus("Copy failed");
  }
}

function initializeCaProfilesTable() {
  const element = document.getElementById("ca-profiles-table");
  if (!(element instanceof HTMLElement)) return;
  initializeAtlasoResourceWizard({
    elementId: "ca-profiles-table",
    formSelector: "[data-ca-profile-form]",
    dialogId: "ca-profile-dialog",
    rows: JSON.parse(element.dataset.profiles || "[]"),
    newRow: newCaProfileRow(),
    resourceName: "profile",
    createUrl: "/certificate-authority/profiles",
    editUrl: (id) => `/certificate-authority/profiles/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/certificate-authority/profiles/${id}/delete`,
    editLabel: "Edit profile",
    deleteLabel: "Delete profile",
    createLabel: "Create profile",
    updateLabel: "Update profile",
    emptyMessage: "No CA profiles configured.",
    actionErrorSelector: "#ca-profile-error",
    defaults: newCaProfileRow(),
    steps: [
      { id: "identity", title: "Define the certificate profile", description: "Name the reusable certificate policy and choose its certificate type." },
      { id: "policy", title: "Set certificate policy", description: "Choose validity, key generation, usages, and SAN requirements." },
      { id: "enablement", title: "Choose profile availability", description: "Control whether new certificate requests may select this profile." },
      { id: "review", title: "Review CA desired state", description: "Confirm the profile and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Profile", field: "name" },
      { label: "Certificate type", field: "certificate_type" },
      { label: "Validity", value: (form) => `${form.elements.validity_days.value} days` },
      { label: "Key", value: (form) => `${form.elements.key_algorithm.value} ${form.elements.key_size.value}` },
      { label: "SAN required", field: "san_required" },
      { label: "State", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name} profile?`,
      message: "This removes the CA profile from Atlaso desired state and unassigns requests using it. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete profile",
      tone: "danger",
    }),
    onSaved: ({ resource }) => {
      const select = document.querySelector("[data-ca-certificate-form] select[name='profile_id']");
      if (!(select instanceof HTMLSelectElement)) return;
      let option = [...select.options].find((item) => item.value === String(resource.id));
      if (!resource.enabled) {
        option?.remove();
        return;
      }
      if (!option) {
        option = document.createElement("option");
        option.value = String(resource.id);
        select.append(option);
      }
      option.textContent = resource.name;
      option.dataset.sanRequired = String(Boolean(resource.san_required));
    },
    onDeleted: ({ data }) => {
      const select = document.querySelector("[data-ca-certificate-form] select[name='profile_id']");
      if (select instanceof HTMLSelectElement) {
        [...select.options].find((option) => option.value === String(data.id))?.remove();
      }
    },
    options: {
      height: "360px",
      rowHeight: 28,
      placeholder: "No CA profiles configured.",
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 170,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add profile here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Type", field: "certificate_type", width: 130 },
        { title: "Validity", field: "validity_days", width: 100, formatter: (cell) => cell.getRow().getData().is_new ? "" : `${escapeHtml(cell.getValue())} days` },
        { title: "Key", field: "key_algorithm", width: 110, formatter: (cell) => cell.getRow().getData().is_new ? "" : `${escapeHtml(cell.getValue())} ${escapeHtml(cell.getRow().getData().key_size)}` },
        { title: "EKU", field: "extended_key_usage", minWidth: 160 },
        { title: "SAN", field: "san_required", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 80, headerSort: false },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 100, headerSort: false },
        { title: "Description", field: "description", minWidth: 220 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function initializeCaCertificatesTable() {
  const element = document.getElementById("ca-certificates-table");
  if (!(element instanceof HTMLElement)) return;
  const profileOptions = JSON.parse(element.dataset.profileOptions || "[]");
  const defaultProfileId = profileOptions[0]?.id || "";
  initializeAtlasoResourceWizard({
    elementId: "ca-certificates-table",
    formSelector: "[data-ca-certificate-form]",
    dialogId: "ca-certificate-dialog",
    rows: JSON.parse(element.dataset.certificates || "[]"),
    newRow: newCaCertificateRow(defaultProfileId),
    resourceName: "certificate",
    createUrl: "/certificate-authority/certificates",
    editUrl: (id) => `/certificate-authority/certificates/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/certificate-authority/certificates/${id}/delete`,
    canEdit: (data) => Boolean(data.can_edit),
    canDelete: (data) => Boolean(data.can_delete),
    editLabel: "Edit request",
    deleteLabel: "Delete request",
    createLabel: "Create certificate request",
    updateLabel: "Update certificate request",
    emptyMessage: "No certificate requests configured.",
    actionErrorSelector: "#ca-certificate-error",
    defaults: newCaCertificateRow(defaultProfileId),
    steps: [
      { id: "identity", title: "Define the certificate request", description: "Choose the common name and enabled certificate profile." },
      { id: "names", title: "Register certificate names", description: "Enter every DNS name and IP address clients will use." },
      { id: "enablement", title: "Choose request availability", description: "Control whether the request participates in rendered CA desired state." },
      { id: "review", title: "Review certificate desired state", description: "Confirm the request and global appliance-apply boundary." },
    ],
    validateStep: ({ form, step }) => {
      if (step.id !== "names") return { valid: true };
      const profile = form.elements.profile_id;
      const requiresSan = profile instanceof HTMLSelectElement
        && profile.selectedOptions[0]?.dataset.sanRequired === "true";
      if (requiresSan && !form.elements.subject_alt_names.value.trim() && !form.elements.ip_addresses.value.trim()) {
        return {
          valid: false,
          field: "subject_alt_names",
          message: "The selected profile requires at least one DNS name or IP SAN.",
        };
      }
      return { valid: true };
    },
    reviewItems: [
      { label: "Common name", field: "common_name" },
      { label: "Profile", field: "profile_id" },
      { label: "DNS SANs", field: "subject_alt_names" },
      { label: "IP SANs", field: "ip_addresses" },
      { label: "State", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.common_name} certificate request?`,
      message: "This removes the certificate request from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete request",
      tone: "danger",
    }),
    extraActions: [
      {
        label: "Copy fingerprint",
        disabled: (row) => !row.getData().fingerprint,
        action: (_event, row) => copyCaCertificateFingerprint(row),
      },
      {
        label: "Export",
        disabled: (row) => {
          const data = row.getData();
          return !data.can_export_certificate && !data.can_export_chain && !data.can_export_private_key;
        },
        menu: [
          { label: "Certificate", disabled: (row) => !row.getData().can_export_certificate, action: (_event, row) => downloadCaCertificateArtifact(row, "certificate.pem") },
          { label: "Certificate chain", disabled: (row) => !row.getData().can_export_chain, action: (_event, row) => downloadCaCertificateArtifact(row, "chain.pem") },
          { label: "Private key", disabled: (row) => !row.getData().can_export_private_key, action: (_event, row) => downloadCaCertificateArtifact(row, "private-key.pem") },
        ],
      },
    ],
    options: {
      height: "420px",
      rowHeight: 28,
      placeholder: "No certificate requests configured.",
      columns: [
        {
          title: "Common name",
          field: "common_name",
          minWidth: 210,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add certificate here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Owner", field: "managed_owner", formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "manual"), minWidth: 150 },
        { title: "Profile", field: "profile_name", formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "Unassigned"), minWidth: 160 },
        { title: "DNS SANs", field: "subject_alt_names", minWidth: 220 },
        { title: "IP SANs", field: "ip_addresses", minWidth: 170 },
        { title: "Status", field: "status", width: 100 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 100, headerSort: false },
        { title: "Fingerprint", field: "fingerprint", formatter: (cell) => escapeHtml(cell.getValue() || ""), cssClass: "mono-text", width: 480, headerSort: false },
        { title: "Description", field: "description", minWidth: 220 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "common_name"),
    },
  });
}

async function postKmsAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (key === "id" || key === "is_new" || key === "owner_client_name") {
      continue;
    }
    if (key === "enabled" || key === "exportable") {
      if (value) {
        body.set(key, "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text.match(/KMS .* already exists[^<]*/)?.[0] || "The KMS desired state could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newKmsClientRow() {
  return {
    id: "__new__",
    name: "",
    certificate_subject: "",
    role: "service",
    allowed_operations: "locate,get,create,activate,get-attributes,get-attribute-list,query,discover-versions",
    enabled: true,
    description: "",
    is_new: true,
  };
}

function newKmsKeyRow(defaultClientId = "") {
  return {
    id: "__new__",
    name: "",
    algorithm: "AES",
    length: 256,
    usage: "encrypt,decrypt",
    state: "active",
    owner_client_id: defaultClientId,
    owner_client_name: "",
    exportable: false,
    enabled: true,
    description: "",
    is_new: true,
  };
}

function hasRequiredKmsClientFields(data) {
  return Boolean((data.name || "").trim() && (data.certificate_subject || "").trim());
}

function hasRequiredKmsKeyFields(data) {
  return Boolean((data.name || "").trim());
}

async function postFirewallRuleAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (["id", "is_new", "created_at", "updated_at"].includes(key)) {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    const plainText = text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    throw new Error(plainText || "The firewall rule could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newFirewallRuleRow(defaultInterface = "") {
  return {
    id: "__new__",
    name: "",
    direction: "input",
    action: "accept",
    protocol: "tcp",
    source: "any",
    destination: "any",
    destination_port: "",
    interface_name: defaultInterface,
    priority: 100,
    enabled: true,
    description: "",
    is_new: true,
  };
}

function firewallGroupOptions(groups = []) {
  const options = { any: "Any" };
  groups.forEach((group) => {
    if (!group || !group.id || group.id === "any") {
      return;
    }
    options[`group:${group.id}`] = group.name || group.id;
  });
  return options;
}

function firewallGroupFormatter(groupOptions) {
  return (cell) => {
    const value = String(cell.getValue() || "any");
    return escapeHtml(groupOptions[value] || value);
  };
}

function hasRequiredFirewallRuleFields(data) {
  return Boolean((data.name || "").trim());
}

async function autoSaveFirewallRule(cell, csrf) {
  clearCaMessage("firewall-rule-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredFirewallRuleFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postFirewallRuleAction("/firewall/rules", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showCaMessage("firewall-rule-error", error instanceof Error ? error.message : "The firewall rule could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postFirewallRuleAction(`/firewall/rules/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showCaMessage("firewall-rule-error", error instanceof Error ? error.message : "The firewall rule could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteFirewallRuleFromMenu(row, csrf) {
  clearCaMessage("firewall-rule-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name}?`,
    message: "This removes the firewall rule from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete rule",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postFirewallRuleAction(`/firewall/rules/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showCaMessage("firewall-rule-error", error instanceof Error ? error.message : "The firewall rule could not be deleted.");
  }
}

function initializeFirewallRulesTable() {
  const element = document.getElementById("firewall-rules-table");
  if (!(element instanceof HTMLElement)) return;
  const interfaces = JSON.parse(element.dataset.interfaces || "[]");
  const groupOptions = firewallGroupOptions(JSON.parse(element.dataset.groups || "[]"));
  const groupValueFormatter = firewallGroupFormatter(groupOptions);
  const existingRows = JSON.parse(element.dataset.rules || "[]");
  initializeAtlasoResourceWizard({
    elementId: "firewall-rules-table",
    formSelector: "[data-firewall-rule-form]",
    dialogId: "firewall-rule-dialog",
    rows: existingRows,
    newRow: newFirewallRuleRow(interfaces[0] || ""),
    resourceName: "rule",
    createUrl: "/firewall/rules",
    editUrl: (id) => `/firewall/rules/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/firewall/rules/${id}/delete`,
    editLabel: "Edit rule",
    deleteLabel: "Delete rule",
    createLabel: "Create firewall rule",
    updateLabel: "Update firewall rule",
    emptyMessage: "No operator firewall rules configured.",
    actionErrorSelector: "#firewall-rule-error",
    defaults: newFirewallRuleRow(interfaces[0] || ""),
    steps: [
      { id: "policy", title: "Define the firewall rule", description: "Name the operator rule and choose its nftables direction and action." },
      { id: "match", title: "Match network traffic", description: "Choose protocol, source, destination, ports, and optional interface." },
      { id: "state", title: "Set rule priority and notes", description: "Choose evaluation priority and record the rule's operator purpose." },
      { id: "enablement", title: "Choose rule enablement", description: "Choose whether the rule enters rendered desired state." },
      { id: "review", title: "Review firewall desired state", description: "Confirm the rule and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Rule", field: "name" },
      { label: "Policy", value: (form) => `${form.elements.direction.value} / ${form.elements.action.value}` },
      { label: "Protocol", field: "protocol" },
      { label: "Source", field: "source" },
      { label: "Destination", field: "destination" },
      { label: "Ports", field: "destination_port" },
      { label: "Interface", field: "interface_name" },
      { label: "Priority", field: "priority" },
      { label: "State", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name}?`,
      message: "This removes the firewall rule from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete rule",
      tone: "danger",
    }),
    options: {
      height: `${Math.min(Math.max((existingRows.length + 1) * 28 + 34, 90), 240)}px`,
      rowHeight: 28,
      placeholder: "No operator firewall rules configured.",
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 170,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add rule here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Direction", field: "direction", width: 120 },
        { title: "Action", field: "action", width: 105 },
        { title: "Protocol", field: "protocol", width: 110 },
        { title: "Source", field: "source", formatter: (cell) => cell.getRow().getData().is_new ? "" : groupValueFormatter(cell), minWidth: 150 },
        { title: "Destination", field: "destination", formatter: (cell) => cell.getRow().getData().is_new ? "" : groupValueFormatter(cell), minWidth: 150 },
        { title: "Ports", field: "destination_port", width: 120 },
        { title: "Interface", field: "interface_name", formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "any"), width: 120 },
        { title: "Priority", field: "priority", width: 100 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 95 },
        { title: "Description", field: "description", minWidth: 180 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function managedFirewallStatusFormatter(cell) {
  const value = String(cell.getValue() || "managed");
  const style = value === "generated" ? "good" : value === "replaced" ? "warn" : "muted";
  return `<span class="status-pill ${style}">${escapeHtml(value)}</span>`;
}

async function updateManagedFirewallSourceGroup(cell, csrf) {
  const data = cell.getRow().getData();
  if (data.managed_state !== "generated") {
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
    return;
  }
  const body = new FormData();
  body.set("csrf", csrf);
  body.set("rule_name", data.name || "");
  body.set("source_group_id", data.source_group_id || "");
  const response = await fetch("/firewall/managed-rules/source-group", {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
    const text = await response.text();
    showCaMessage("firewall-rule-error", text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ") || "The managed firewall group could not be saved.");
    return;
  }
  showTransientGridStatus("Saved");
  window.location.reload();
}

function initializeManagedFirewallRulesTable() {
  const tableElement = document.getElementById("managed-firewall-rules-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    return;
  }
  const rows = JSON.parse(tableElement.dataset.rules || "[]");
  const csrf = tableElement.dataset.csrf || "";
  const sourceGroups = JSON.parse(tableElement.dataset.sourceGroups || "[]");
  const sourceGroupOptions = Object.fromEntries(sourceGroups.map((group) => [group.id, group.name]));
  try {
    const atlasoGridOptions5 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "100%",
      rowHeight: 28,
      placeholder: "No managed service rules.",
      reactiveData: false,
      columns: [
        { title: "Status", field: "managed_status", formatter: managedFirewallStatusFormatter, width: 120 },
        { title: "Name", field: "name" },
        {
          title: "Source",
          field: "source_group_id",
          editor: "list",
          editorParams: { values: sourceGroupOptions },
          formatter: (cell) => escapeHtml(cell.getRow().getData().source_group_name || cell.getValue() || ""),
          width: 170,
          cellEdited: (cell) => updateManagedFirewallSourceGroup(cell, csrf),
          editable: (cell) => cell.getRow().getData().managed_state === "generated" && Boolean(cell.getRow().getData().source_group_id),
        },
        { title: "Direction", field: "direction", width: 120 },
        { title: "Action", field: "action", width: 105 },
        { title: "Protocol", field: "protocol", width: 110 },
        { title: "Ports", field: "destination_port", width: 120 },
        { title: "Interface", field: "interface_name", width: 120 },
        { title: "Priority", field: "priority", width: 100 },
        { title: "Enabled", field: "enabled", formatter: atlasoBooleanFormatter, hozAlign: "center", width: 95 },
        { title: "Description", field: "description" },
      ],
      rowFormatter: (row) => {
        const data = row.getData();
        row.getElement().classList.toggle("managed-rule-generated", data.managed_state === "generated");
        row.getElement().classList.toggle("managed-rule-replaced", data.managed_state === "replaced");
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions5,
    }).table;
  } catch (_error) {
    if (fallback) {
      fallback.classList.remove("hidden");
    }
  }
}

function serviceRuntimeFormatter(cell) {
  const running = Boolean(cell.getValue());
  const data = cell.getRow().getData() || {};
  if (!running && data.enabled === false) {
    return '<span class="service-state muted">disabled</span>';
  }
  return `<span class="service-state ${running ? "good" : "muted"}">${running ? "running" : "stopped"}</span>`;
}

function serviceNameFormatter(cell) {
  const data = cell.getRow().getData();
  return `<span class="service-name-cell"><strong>${escapeHtml(data.display_name)}</strong><small>${escapeHtml(data.service)}</small></span>`;
}

function submitServiceAction(service, action, csrf) {
  const form = document.createElement("form");
  form.method = "post";
  form.action = `/services/${encodeURIComponent(service)}/${encodeURIComponent(action)}`;
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "csrf";
  input.value = csrf;
  form.append(input);
  document.body.append(form);
  form.requestSubmit();
}

function autoToggleServiceEnabled(cell, csrf) {
  const data = cell.getRow().getData();
  submitServiceAction(data.service, data.enabled ? "enable" : "disable", csrf);
}

function initializeServicesTable() {
  const tableElement = document.getElementById("services-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showCaMessage("services-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const rows = JSON.parse(tableElement.dataset.services || "[]");
  try {
    const atlasoGridOptions6 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "100%",
      rowHeight: 42,
      placeholder: "No allowlisted services configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Start",
          action: (_event, row) => submitServiceAction(row.getData().service, "start", csrf),
        },
        {
          label: "Stop",
          action: (_event, row) => submitServiceAction(row.getData().service, "stop", csrf),
        },
        {
          label: "Restart",
          action: (_event, row) => submitServiceAction(row.getData().service, "restart", csrf),
        },
        {
          label: "Enable",
          action: (_event, row) => submitServiceAction(row.getData().service, "enable", csrf),
          disabled: (component) => component.getData().enabled,
        },
        {
          label: "Disable",
          action: (_event, row) => submitServiceAction(row.getData().service, "disable", csrf),
          disabled: (component) => !component.getData().enabled,
        },
        {
          label: "Open logs",
          action: (_event, row) => {
            window.location.href = `/services/${encodeURIComponent(row.getData().service)}/logs`;
          },
        },
        {
          label: "Check NTPsec source health",
          action: () => openNTPsecSourceHealthModal(),
          disabled: (component) => component.getData().service !== "ntpd",
        },
      ],
      columns: [
        {
          title: "Service",
          field: "display_name",
          formatter: serviceNameFormatter,
          minWidth: 310,
        },
        {
          title: "Runtime",
          field: "running",
          formatter: serviceRuntimeFormatter,
          width: 125,
          hozAlign: "center",
        },
        {
          title: "Startup",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          width: 125,
          hozAlign: "center",
          cellEdited: (cell) => autoToggleServiceEnabled(cell, csrf),
        },
        {
          title: "Boundary",
          field: "detail",
          formatter: (cell) => escapeHtml(cell.getValue() || "native host service"),
          minWidth: 260,
        },
      ],
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions6,
    }).table;
  } catch (error) {
    showCaMessage("services-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

async function postUserAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (
      [
        "id",
        "is_new",
        "is_current",
        "created_at",
        "enabled",
        "os_sync_status",
        "os_password_pending",
        "os_account_state",
        "os_account_detail",
        "os_unlock_available",
        "unlock_requested",
      ].includes(key)
    ) {
      continue;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => body.append(key, item ?? ""));
    } else {
      body.set(key, value ?? "");
    }
  }

  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    const text = await response.text();
    const plainText = text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    throw new Error(plainText || "The user could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function openUserPasswordModal(data) {
  const modal = document.getElementById("user-password-modal");
  const form = document.getElementById("user-password-form");
  const title = document.getElementById("user-password-modal-title");
  const message = document.getElementById("user-password-modal-message");
  if (!(modal instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement)) {
    return;
  }
  form.action = `/users/${data.id}/password`;
  form.reset();
  form.querySelectorAll('input[type="text"][data-password-visible]').forEach((input) => {
    if (input instanceof HTMLInputElement) {
      input.type = "password";
      input.removeAttribute("data-password-visible");
    }
  });
  form.querySelectorAll("[data-password-toggle]").forEach((button) => {
    if (button instanceof HTMLButtonElement) {
      button.setAttribute("aria-pressed", "false");
      button.setAttribute("aria-label", button.getAttribute("aria-label")?.replace("Hide", "Show") || "Show password");
    }
  });
  form.querySelectorAll("input").forEach((input) => {
    if (input instanceof HTMLInputElement) {
      input.setCustomValidity("");
    }
  });
  if (title instanceof HTMLElement) {
    title.textContent = `Reset ${data.username} password`;
  }
  if (message instanceof HTMLElement) {
    message.textContent = "Set/reset the Photon OS password. The password is held only until global Local Users apply.";
  }
  modal.showModal();
  const passwordInput = form.querySelector('input[name="password"]');
  if (passwordInput instanceof HTMLInputElement) {
    passwordInput.focus();
  }
}

async function unlockUserFromMenu(row, csrf) {
  clearCaMessage("users-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  try {
    await postUserAction(`/users/${data.id}/unlock`, {}, csrf, { reload: false });
    showTransientGridStatus("Unlock pending");
    window.location.reload();
  } catch (error) {
    showCaMessage("users-error", error instanceof Error ? error.message : "The unlock request could not be staged.");
  }
}

async function disableUserFromMenu(row, csrf) {
  clearCaMessage("users-error");
  const data = row.getData();
  if (data.is_new || !data.enabled) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Disable ${data.username}?`,
    message: "This marks the Atlaso user disabled, revokes its API tokens, and removes the managed Photon OS account on the next global appliance apply.",
    label: "Disable user",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postUserAction(`/users/${data.id}/disable`, {}, csrf, { reload: false });
    showTransientGridStatus("Disabled");
    window.location.reload();
  } catch (error) {
    showCaMessage("users-error", error instanceof Error ? error.message : "The user could not be disabled.");
  }
}

function newUserRow() {
  return {
    id: "__new__",
    username: "",
    description: "",
    role: "viewer",
    roles: ["viewer"],
    roles_label: "viewer",
    roles_text: "viewer",
    shell: "/sbin/nologin",
    web_terminal_access: false,
    enabled: false,
    created_at: "",
    os_sync_status: "password not staged; reset to sync",
    os_password_pending: false,
    os_account_state: "absent",
    os_account_detail: "",
    os_unlock_available: false,
    unlock_requested: false,
    is_current: false,
    is_new: true,
  };
}

function userRolesFormatter(cell) {
  const data = cell.getRow().getData();
  const roles = Array.isArray(data.roles) && data.roles.length ? data.roles : String(data.roles_text || data.role || "viewer").split(",");
  return escapeHtml(roles.map((role) => String(role).trim()).filter(Boolean).join(", ") || "viewer");
}

function initializeUsersTable() {
  const element = document.getElementById("users-table");
  if (!(element instanceof HTMLElement)) return;
  const csrf = element.dataset.csrf || "";
  const existingRows = JSON.parse(element.dataset.users || "[]");
  initializeAtlasoResourceWizard({
    elementId: "users-table",
    formSelector: "[data-user-account-form]",
    dialogId: "user-account-dialog",
    rows: existingRows,
    newRow: newUserRow(),
    resourceName: "user",
    createUrl: "/users",
    editUrl: (id) => `/users/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/users/${id}/delete`,
    editLabel: "Edit user",
    deleteLabel: "Remove user",
    createLabel: "Create local user",
    updateLabel: "Update local user",
    emptyMessage: "No local users configured.",
    gridError: "Local-user changes are unavailable because the interactive grid could not initialize.",
    actionErrorSelector: "#users-error",
    defaults: newUserRow(),
    steps: [
      { id: "identity", title: "Define the local identity", description: "Choose the username and Atlaso authorization roles." },
      { id: "access", title: "Choose Photon access", description: "Set the desired login shell and optional Web SSH access." },
      { id: "password", title: "Set or postpone the Photon password", description: "Stage a policy-compliant password now or leave both fields blank to postpone." },
      { id: "enablement", title: "Choose user enablement", description: "Choose whether the account enters enabled Atlaso and Photon desired state." },
      { id: "review", title: "Review local-user desired state", description: "Confirm the account and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Username", field: "username" },
      { label: "Description", field: "description" },
      {
        label: "Roles",
        value: (form) => [...form.querySelectorAll('input[name="roles"]:checked')].map((input) => input.value).join(", "),
      },
      { label: "Photon shell", field: "shell" },
      { label: "Web SSH", field: "web_terminal_access" },
      { label: "Photon password", value: (form) => form.elements.password.value ? "Staged securely" : "Postponed" },
      { label: "Enabled", field: "enabled" },
    ],
    onOpen: ({ form }) => {
      form.elements.password.value = "";
      form.elements.confirm_password.value = "";
    },
    validateStep: ({ form, step }) => {
      if (step.id === "identity" && !form.querySelector('input[name="roles"]:checked')) {
        return {
          valid: false,
          message: "Select at least one Atlaso role.",
          field: form.querySelector('input[name="roles"]'),
        };
      }
      if (
        step.id === "access"
        && form.elements.web_terminal_access.checked
        && form.elements.shell.value === "/sbin/nologin"
      ) {
        return { valid: false, message: "Web SSH access requires an interactive Photon shell.", field: "shell" };
      }
      if (
        step.id === "password"
        && (form.elements.password.value || form.elements.confirm_password.value)
        && form.elements.password.value !== form.elements.confirm_password.value
      ) {
        return { valid: false, message: "Password confirmation does not match.", field: "confirm_password" };
      }
      if (
        step.id === "enablement"
        && !form.elements.record_id.value
        && form.elements.enabled.checked
        && !form.elements.password.value
      ) {
        return { valid: false, message: "Set a Photon password before enabling a new user, or leave the user disabled.", field: "enabled" };
      }
      return { valid: true };
    },
    deleteConfirmation: (data) => ({
      title: `Remove ${data.username}?`,
      message: "This removes the local Atlaso account, revokes its API tokens, and removes the managed Photon OS account on the next global appliance apply.",
      confirmLabel: "Remove user",
      tone: "danger",
    }),
    canDelete: (data) => !data.is_current,
    extraActions: [
      {
        label: "Set/reset Photon OS password",
        disabled: (row) => row.getData().is_new,
        action: (_event, row) => openUserPasswordModal(row.getData()),
      },
      {
        label: "Unlock OS account",
        disabled: (row) => {
          const data = row.getData();
          return data.is_new || !data.enabled || !data.os_unlock_available || data.unlock_requested;
        },
        action: (_event, row) => unlockUserFromMenu(row, csrf),
      },
      {
        label: "Disable user",
        disabled: (row) => {
          const data = row.getData();
          return data.is_new || data.is_current || !data.enabled;
        },
        action: (_event, row) => disableUserFromMenu(row, csrf),
      },
    ],
    options: {
      height: "420px",
      rowHeight: 28,
      placeholder: "No local users configured.",
      reactiveData: false,
      columns: [
        {
          title: "Username",
          field: "username",
          minWidth: 170,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add user here</button>'
            : escapeHtml(cell.getValue()),
        },
        {
          title: "Roles",
          field: "roles",
          formatter: userRolesFormatter,
          minWidth: 190,
        },
        { title: "Description", field: "description", minWidth: 220 },
        {
          title: "Shell",
          field: "shell",
          minWidth: 145,
        },
        {
          title: "Web SSH",
          field: "web_terminal_access",
          formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell),
          hozAlign: "center",
          width: 105,
          headerTooltip: "Allows this enabled local user to open the appliance web terminal. An interactive shell is also required.",
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell),
          hozAlign: "center",
          width: 110,
        },
        {
          title: "OS account",
          field: "os_account_state",
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.is_new) return "";
            const value = String(cell.getValue() || "");
            const pill = value === "present" ? "good" : ["locked", "faillock blocked", "password not set"].includes(value) ? "warn" : "muted";
            const pending = data.unlock_requested ? ' <span class="status-pill warn">unlock pending</span>' : "";
            const title = data.os_account_detail ? ` title="${escapeHtml(data.os_account_detail)}"` : "";
            return `<span class="status-pill ${pill}"${title}>${escapeHtml(value)}</span>${pending}`;
          },
          minWidth: 190,
        },
        { title: "Created", field: "created_at", formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue()), width: 120 },
        {
          title: "Session",
          field: "is_current",
          formatter: (cell) => (cell.getValue() ? '<span class="status-pill good">current</span>' : ""),
          width: 110,
        },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "username"),
    },
  });
}

function initializeUserPasswordForm() {
  const modal = document.getElementById("user-password-modal");
  const form = document.getElementById("user-password-form");
  const cancel = document.querySelector("[data-user-password-cancel]");
  document.querySelectorAll("[data-reset-user-button]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      openUserPasswordModal({ id: button.dataset.userId, username: button.dataset.username || "user" });
    });
  });
  if (cancel instanceof HTMLButtonElement && modal instanceof HTMLDialogElement) {
    cancel.addEventListener("click", () => modal.close("cancel"));
  }
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  const password = form.querySelector('input[name="password"]');
  const confirmation = form.querySelector('input[name="confirm_password"]');
  const validatePasswordMatch = (report = false) => {
    if (!(password instanceof HTMLInputElement) || !(confirmation instanceof HTMLInputElement)) {
      return true;
    }
    if (!password.value || !confirmation.value || password.value === confirmation.value) {
      confirmation.setCustomValidity("");
      return true;
    }
    confirmation.setCustomValidity("Password confirmation does not match.");
    if (report) {
      confirmation.reportValidity();
    }
    return false;
  };
  [password, confirmation].forEach((input) => {
    if (!(input instanceof HTMLInputElement)) {
      return;
    }
    input.addEventListener("input", () => validatePasswordMatch(false));
  });
  form.querySelectorAll("[data-password-toggle]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    const input = button.closest(".password-input-wrap")?.querySelector("input");
    if (!(input instanceof HTMLInputElement)) {
      return;
    }
    button.addEventListener("click", () => {
      const nextVisible = input.type === "password";
      input.type = nextVisible ? "text" : "password";
      input.toggleAttribute("data-password-visible", nextVisible);
      button.setAttribute("aria-pressed", nextVisible ? "true" : "false");
      button.setAttribute("aria-label", `${nextVisible ? "Hide" : "Show"} ${input.name === "confirm_password" ? "confirmation password" : "new password"}`);
      input.focus();
    });
  });
  form.addEventListener("submit", (event) => {
    if (!validatePasswordMatch(true)) {
      event.preventDefault();
    }
  });
}

async function autoSaveKmsClient(cell, csrf) {
  clearCaMessage("kms-client-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredKmsClientFields(data)) {
      return;
    }
    try {
      await postKmsAction("/kms/clients", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showCaMessage("kms-client-error", error instanceof Error ? error.message : "The KMS client could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postKmsAction(`/kms/clients/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
  } catch (error) {
    showCaMessage("kms-client-error", error instanceof Error ? error.message : "The KMS client could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function autoSaveKmsKey(cell, csrf) {
  clearCaMessage("kms-key-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredKmsKeyFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postKmsAction("/kms/keys", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showCaMessage("kms-key-error", error instanceof Error ? error.message : "The KMS key could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postKmsAction(`/kms/keys/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
  } catch (error) {
    showCaMessage("kms-key-error", error instanceof Error ? error.message : "The KMS key could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteKmsClientFromMenu(row, csrf) {
  clearCaMessage("kms-client-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name} client?`,
    message: "This removes the KMS client from Atlaso desired state and unassigns any keys owned by it. It will not touch the appliance until global appliance apply runs.",
    label: "Delete client",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postKmsAction(`/kms/clients/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showCaMessage("kms-client-error", error instanceof Error ? error.message : "The KMS client could not be deleted.");
  }
}

async function deleteKmsKeyFromMenu(row, csrf) {
  clearCaMessage("kms-key-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name} key?`,
    message: "This removes the KMS key from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete key",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postKmsAction(`/kms/keys/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showCaMessage("kms-key-error", error instanceof Error ? error.message : "The KMS key could not be deleted.");
  }
}

function initializeKmsClientsTable() {
  const element = document.getElementById("kms-clients-table");
  if (!(element instanceof HTMLElement)) return;
  const updateOwnerOption = (resource) => {
    const select = document.querySelector("[data-kms-key-form] select[name='owner_client_id']");
    if (!(select instanceof HTMLSelectElement)) return;
    let option = [...select.options].find((item) => item.value === String(resource.id));
    if (!resource.enabled) {
      option?.remove();
      return;
    }
    if (!option) {
      option = document.createElement("option");
      option.value = String(resource.id);
      select.append(option);
    }
    option.textContent = resource.name;
  };
  const retirePreviousCertificate = async (row) => {
    const data = row.getData();
    const confirmed = await requestConfirmation({
      title: `Retire previous ${data.name} certificate?`,
      message: "Confirm vCenter is using the current CA-issued certificate. This removes every previous fingerprint from KMS desired state after the next global appliance apply.",
      confirmLabel: "Retire previous certificate",
      tone: "danger",
    });
    if (!confirmed) return;
    const body = new FormData();
    body.set("csrf", element.dataset.csrf || "");
    const payload = await atlasoGridWizardRequest(
      `/kms/clients/${data.id}/retire-previous-certificate`,
      body,
    );
    await row.update(payload.client);
    showTransientGridStatus("Previous certificate retired");
  };
  initializeAtlasoResourceWizard({
    elementId: "kms-clients-table",
    formSelector: "[data-kms-client-form]",
    dialogId: "kms-client-dialog",
    rows: JSON.parse(element.dataset.clients || "[]"),
    newRow: newKmsClientRow(),
    resourceName: "client",
    createUrl: "/kms/clients",
    editUrl: (id) => `/kms/clients/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/kms/clients/${id}/delete`,
    editLabel: "Edit client",
    deleteLabel: "Delete client",
    createLabel: "Create KMIP client",
    updateLabel: "Update KMIP client",
    emptyMessage: "No KMIP clients configured.",
    actionErrorSelector: "#kms-client-error",
    extraActions: [
      {
        label: "Retire previous certificate",
        disabled: (row) => Number(row.getData().certificate_fingerprint_count || 0) < 2,
        action: (_event, row) => retirePreviousCertificate(row),
      },
    ],
    defaults: newKmsClientRow(),
    steps: [
      { id: "identity", title: "Define the KMIP client", description: "Name the client and bind it to the exact certificate subject used for mutual TLS." },
      { id: "access", title: "Grant KMIP access", description: "Choose the lab authorization role and allowlisted operations." },
      { id: "state", title: "Choose client state", description: "Enable the client and record the workload that owns it." },
      { id: "review", title: "Review KMS desired state", description: "Confirm the client and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Client", field: "name" },
      { label: "Certificate subject", field: "certificate_subject" },
      { label: "Role", field: "role" },
      { label: "Operations", field: "allowed_operations" },
      { label: "State", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name} client?`,
      message: "This removes the KMS client from Atlaso desired state and unassigns any keys owned by it. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete client",
      tone: "danger",
    }),
    onSaved: ({ resource }) => updateOwnerOption(resource),
    onDeleted: ({ data }) => {
      const select = document.querySelector("[data-kms-key-form] select[name='owner_client_id']");
      if (select instanceof HTMLSelectElement) {
        [...select.options].find((option) => option.value === String(data.id))?.remove();
      }
      const keysTable = document.getElementById("kms-keys-table")?.atlasoTabulator;
      keysTable?.getRows?.().forEach((row) => {
        if (String(row.getData().owner_client_id) === String(data.id)) {
          row.update({ owner_client_id: "", owner_client_name: "Unassigned" });
        }
      });
    },
    options: {
      height: "420px",
      rowHeight: 28,
      placeholder: "No KMIP clients configured.",
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 170,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add client here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Certificate subject", field: "certificate_subject", minWidth: 300 },
        { title: "Role", field: "role", width: 120 },
        { title: "Operations", field: "allowed_operations", minWidth: 220 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 100, headerSort: false },
        { title: "Description", field: "description", minWidth: 220 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function initializeKmsKeysTable() {
  const element = document.getElementById("kms-keys-table");
  if (!(element instanceof HTMLElement)) return;
  const clientOptions = JSON.parse(element.dataset.clientOptions || "[]");
  const defaultClientId = clientOptions[0]?.id || "";
  initializeAtlasoResourceWizard({
    elementId: "kms-keys-table",
    formSelector: "[data-kms-key-form]",
    dialogId: "kms-key-dialog",
    rows: JSON.parse(element.dataset.keys || "[]"),
    newRow: newKmsKeyRow(defaultClientId),
    resourceName: "key",
    createUrl: "/kms/keys",
    editUrl: (id) => `/kms/keys/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/kms/keys/${id}/delete`,
    editLabel: "Edit key",
    deleteLabel: "Delete key",
    createLabel: "Create KMS key",
    updateLabel: "Update KMS key",
    emptyMessage: "No KMS keys configured.",
    actionErrorSelector: "#kms-key-error",
    defaults: newKmsKeyRow(defaultClientId),
    steps: [
      { id: "identity", title: "Define the KMS key", description: "Name the staged key, describe its purpose, and choose its algorithm and length." },
      { id: "policy", title: "Set key policy", description: "Choose usage, optional client ownership, and export behavior." },
      { id: "state", title: "Choose key lifecycle", description: "Set the KMIP lifecycle state and enablement." },
      { id: "review", title: "Review KMS desired state", description: "Confirm the key and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Key", field: "name" },
      { label: "Algorithm", value: (form) => `${form.elements.algorithm.value} ${form.elements.length.value}` },
      { label: "Usage", field: "usage" },
      { label: "Owner", field: "owner_client_id" },
      { label: "Exportable", field: "exportable" },
      { label: "Lifecycle", field: "state" },
      { label: "Enabled", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name} key?`,
      message: "This removes the KMS key from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete key",
      tone: "danger",
    }),
    options: {
      height: "420px",
      rowHeight: 28,
      placeholder: "No KMS keys configured.",
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 190,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add key here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Algorithm", field: "algorithm", width: 120 },
        { title: "Length", field: "length", width: 95 },
        { title: "Usage", field: "usage", minWidth: 150 },
        { title: "State", field: "state", minWidth: 140 },
        { title: "Owner client", field: "owner_client_name", formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "Unassigned"), minWidth: 170 },
        { title: "Exportable", field: "exportable", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 110, headerSort: false },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 100, headerSort: false },
        { title: "Description", field: "description", minWidth: 220 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function updateCaSettingsPreview(payload = {}) {
  const configPreview = document.querySelector("[data-ca-config-preview]");
  if (configPreview instanceof HTMLElement && payload.config_preview) {
    configPreview.textContent = payload.config_preview;
    highlightConfigPreviewElement(configPreview);
  }
}

function initializeCaSettings(root = document) {
  root.querySelectorAll("[data-ca-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.caSettingsInitialized === "1") return;
    form.dataset.caSettingsInitialized = "1";
    form.addEventListener("atlaso:autosave-success", (event) => {
      updateCaSettingsPreview(event.detail || {});
    });
  });
}

function initializeCaCsrWizard() {
  const dialog = document.getElementById("ca-csr-dialog");
  const form = document.querySelector("[data-ca-csr-form]");
  const launcher = document.querySelector("[data-ca-csr-open]");
  if (
    !(dialog instanceof HTMLDialogElement)
    || !(form instanceof HTMLFormElement)
    || !(launcher instanceof HTMLButtonElement)
    || !window.AtlasoUiPatterns
  ) return;
  const wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "identity", title: "Define the CSR request", description: "Choose its common name, certificate profile, and operator purpose." },
      { id: "names", title: "Register certificate names", description: "Enter the DNS names and IP addresses encoded by the client request." },
      { id: "csr", title: "Paste the CSR", description: "Provide the complete PEM certificate signing request." },
      { id: "review", title: "Review CSR intake", description: "Confirm the staged request and global appliance-apply boundary." },
    ],
    discardTitle: "Discard CSR intake?",
    discardMessage: "The request metadata and CSR entered in this wizard will be lost.",
    prepareReview: () => renderAtlasoWizardReview(form, [
      { label: "Common name", field: "common_name" },
      { label: "Profile", field: "profile_id" },
      { label: "Description", field: "description" },
      { label: "DNS SANs", field: "subject_alt_names" },
      { label: "IP SANs", field: "ip_addresses" },
      { label: "CSR", value: () => form.elements.csr_text.value.trim() ? "PEM supplied" : "Missing" },
    ]),
  });
  launcher.addEventListener("click", () => wizard.open({ launcher }));
}

function serviceBindSelection(form, payload = {}) {
  const interfaceEditor = form.querySelector(".tag-editor[data-service-bind-interface]");
  const addressEditor = form.querySelector(".tag-editor[data-service-bind-address]");
  const interfaces = Array.isArray(payload.listen_interfaces) ? payload.listen_interfaces : tagEditorValues(interfaceEditor);
  let addresses = Array.isArray(payload.listen_addresses) ? payload.listen_addresses : tagEditorValues(addressEditor);
  if (!addresses.length && interfaceEditor instanceof HTMLElement) {
    const options = Array.from(interfaceEditor.querySelectorAll("[data-tag-option]"));
    interfaces.forEach((interfaceName) => {
      const match = options.find((option) => option.getAttribute("data-tag-option") === interfaceName);
      const rawAddresses = match?.getAttribute("data-service-bind-addresses") || match?.getAttribute("data-service-bind-address") || "";
      rawAddresses
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)
        .forEach((address) => {
          if (!addresses.includes(address)) {
            addresses.push(address);
          }
        });
    });
  }
  const interfaceName = payload.listen_interface || interfaces[0] || "";
  const address = payload.listen_address || addresses[0] || "";
  return {
    interfaceName,
    address,
    interfaces,
    addresses,
    interfaceLabel: interfaces.length ? interfaces.join(", ") : interfaceName,
    addressLabel: addresses.length ? addresses.join(", ") : address,
  };
}

function updateDerivedListenAddressSummary(form, payload = {}) {
  if (!(form instanceof HTMLElement) || !Array.isArray(payload.listen_addresses)) {
    return;
  }
  const label = payload.listen_addresses.length ? payload.listen_addresses.join(", ") : "No interface address selected";
  form.querySelectorAll("[data-derived-listen-addresses]").forEach((element) => {
    if (element instanceof HTMLElement) {
      element.textContent = label;
    }
  });
}

function updateKmsDerivedAddress(form, payload = {}) {
  const portInput = form.querySelector('input[name="port"]');
  const port = payload.port || portInput?.value || "5696";
  const configPath = document.querySelector("[data-kms-config-path]");
  if (configPath instanceof HTMLElement && payload.config_path) {
    configPath.textContent = payload.config_path;
  }
  const configPreview = document.querySelector("[data-kms-config-preview]");
  if (configPreview instanceof HTMLElement && payload.config_preview) {
    configPreview.textContent = payload.config_preview;
    highlightConfigPreviewElement(configPreview);
  }
  const hostInput = form.querySelector('input[name="hostname"]');
  if (hostInput instanceof HTMLInputElement && payload.hostname) {
    hostInput.value = payload.hostname;
  }
  const certInput = form.querySelector('input[name="server_certificate"]');
  if (certInput instanceof HTMLInputElement && payload.server_certificate) {
    certInput.value = payload.server_certificate;
  }
  const portField = form.querySelector('input[name="port"]');
  if (portField instanceof HTMLInputElement && payload.port) {
    portField.value = String(port);
  }
}

function updateKmsValidation(payload = {}) {
  const status = document.querySelector("[data-kms-validation-status]");
  const validationPanel = status?.closest(".panel");
  if (!(status instanceof HTMLElement) || !(validationPanel instanceof HTMLElement)) {
    return;
  }
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  status.textContent = errors.length ? "needs attention" : "valid";
  status.classList.toggle("good", errors.length === 0);
  status.classList.toggle("warn", errors.length > 0);
  const previewAnchor = validationPanel.querySelector("[data-config-preview-row]");
  let errorBox = validationPanel.querySelector("[data-kms-validation-errors]");
  const validMessage = validationPanel.querySelector("[data-kms-validation-message]");
  if (errors.length === 0) {
    errorBox?.remove();
    if (!(validMessage instanceof HTMLElement)) {
      const message = document.createElement("p");
      message.className = "muted";
      message.setAttribute("data-kms-validation-message", "");
      message.textContent = "The desired KMS state passes Atlaso validation. Appliance validation still runs through the allowlisted KMS helper before atlaso-kmip changes are applied.";
      validationPanel.insertBefore(message, previewAnchor);
    }
    return;
  }
  validMessage?.remove();
  if (!(errorBox instanceof HTMLElement)) {
    errorBox = document.createElement("div");
    errorBox.className = "alert error";
    errorBox.setAttribute("data-kms-validation-errors", "");
    validationPanel.insertBefore(errorBox, previewAnchor);
  }
  if (errorBox instanceof HTMLElement) {
    errorBox.innerHTML = "";
    errors.forEach((error) => {
      const row = document.createElement("div");
      row.textContent = error;
      errorBox.appendChild(row);
    });
  }
}

function initializeKmsSettings(root = document) {
  root.querySelectorAll("[data-kms-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.kmsSettingsInitialized === "1") return;
    form.dataset.kmsSettingsInitialized = "1";
    const portInput = form.querySelector('input[name="port"]');
    const refresh = () => updateKmsDerivedAddress(form);
    if (portInput instanceof HTMLInputElement) {
      portInput.addEventListener("input", refresh);
    }
    form.addEventListener("atlaso:autosave-success", (event) => {
      const payload = event.detail || {};
      updateKmsDerivedAddress(form, payload);
      updateKmsValidation(payload);
    });
    refresh();
  });
}

function newLdapUserRow(organizationId) {
  return { id: "__new_ldap_user__", organization_id: organizationId, uid: "", given_name: "", surname: "", display_name: "", email: "", telephone: "", enabled: false, password_status: "", is_new: true };
}

function newLdapGroupRow(organizationId) {
  return { id: "__new_ldap_group__", organization_id: organizationId, name: "", description: "", enabled: false, members: [], member_count: 0, member_names: "", is_new: true };
}

function updateLdapSettingsStatus(payload = {}) {
  const enabled = Boolean(payload.settings?.enabled);
  const desired = document.querySelector("[data-ldap-desired-status]");
  if (desired instanceof HTMLElement) {
    desired.textContent = enabled ? "enabled" : "disabled";
    desired.className = `status-pill ${enabled ? "good" : "muted"}`;
  }
  const runtime = document.querySelector("[data-ldap-runtime-status]");
  const runtimeStatus = payload.service_status || {};
  if (runtime instanceof HTMLElement && runtimeStatus.label) {
    runtime.textContent = runtimeStatus.label;
    runtime.className = `status-pill ${runtimeStatus.pill || "muted"}`;
  }
}

function initializeLdapOrganizationWizard() {
  const form = document.querySelector("[data-ldap-organization-form]");
  const dialog = document.getElementById("ldap-organization-dialog");
  const launchers = [...document.querySelectorAll("[data-ldap-organization-open]")];
  if (
    !(form instanceof HTMLFormElement)
    || !(dialog instanceof HTMLDialogElement)
    || !launchers.length
    || !window.AtlasoUiPatterns
  ) {
    return;
  }
  const wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "identity", title: "Name the organization", description: "Choose its operator-visible name and desired state." },
      { id: "directory", title: "Choose the naming context", description: "Accept derived values or set a stable slug and isolated LDAP suffix." },
      { id: "enablement", title: "Choose organization state", description: "Control whether the isolated database enters rendered LDAP desired state." },
      { id: "review", title: "Review organization creation", description: "Confirm the new database and one-time VCF bind credential." },
    ],
    discardTitle: "Discard LDAP organization?",
    discardMessage: "The organization values entered in this wizard will be lost.",
    prepareReview: () => renderAtlasoWizardReview(form, [
      { label: "Organization", field: "name" },
      { label: "Description", field: "description" },
      { label: "Slug", value: () => form.elements.slug.value.trim() || "Derived from name" },
      { label: "Suffix DN", value: () => form.elements.suffix_dn.value.trim() || "Derived from slug" },
      { label: "Desired state", field: "enabled" },
      { label: "Bind credential", value: () => "Generated and shown once" },
    ]),
  });
  launchers.forEach((button) => {
    button.addEventListener("click", () => wizard.open({ launcher: button }));
  });
}

function initializeLdapSettingsStatus(root = document) {
  const settingsForm = root.querySelector('form[action="/ldap/settings"]');
  if (settingsForm instanceof HTMLFormElement) {
    if (settingsForm.dataset.ldapSettingsStatusInitialized === "1") return;
    settingsForm.dataset.ldapSettingsStatusInitialized = "1";
    settingsForm.addEventListener("atlaso:autosave-success", (event) => updateLdapSettingsStatus(event.detail || {}));
  }
}

function initializeLdapPageState() {
  initializeLdapSettingsStatus();
  const tabList = document.querySelector("[data-ldap-organization-tabs]");
  if (!(tabList instanceof HTMLElement)) return;
  const links = Array.from(tabList.querySelectorAll("[data-ldap-organization-id]"));
  const currentId = new URL(window.location.href).searchParams.get("organization_id") || "";
  const activeId = tabList.querySelector("[data-ldap-organization-id].active")?.dataset.ldapOrganizationId || "";
  let storedId = "";
  try {
    storedId = window.localStorage.getItem(LDAP_ORGANIZATION_SELECTION_KEY) || "";
  } catch {
    // Page state persistence is optional when browser storage is unavailable.
  }
  const validStoredLink = links.find((link) => link.dataset.ldapOrganizationId === storedId);
  let loading = false;

  const rememberOrganization = (organizationId) => {
    if (!organizationId) return;
    try {
      window.localStorage.setItem(LDAP_ORGANIZATION_SELECTION_KEY, organizationId);
    } catch {
      // Keep the server-selected organization when storage is unavailable.
    }
  };

  const loadOrganization = async (link, options = {}) => {
    if (!(link instanceof HTMLAnchorElement) || loading) return;
    const organizationId = link.dataset.ldapOrganizationId || "";
    if (!organizationId) return;
    const directoryPanel = document.getElementById("ldap-directory-panel");
    const currentPanel = document.getElementById("ldap-organization-current");
    if (!(directoryPanel instanceof HTMLElement) || !(currentPanel instanceof HTMLElement)) {
      window.location.assign(link.href);
      return;
    }
    loading = true;
    directoryPanel.setAttribute("aria-busy", "true");
    try {
      const response = await fetch(link.href, {
        credentials: "same-origin",
        headers: { Accept: "text/html", "X-Requested-With": "Atlaso" },
      });
      if (!response.ok) throw new Error(`LDAP organization load failed (${response.status})`);
      const nextDocument = new DOMParser().parseFromString(await response.text(), "text/html");
      const nextCurrentPanel = nextDocument.getElementById("ldap-organization-current");
      if (!(nextCurrentPanel instanceof HTMLElement)) throw new Error("LDAP organization response is incomplete.");
      currentPanel.replaceWith(document.importNode(nextCurrentPanel, true));

      const currentMembersDialog = document.getElementById("ldap-group-members-modal");
      const nextMembersDialog = nextDocument.getElementById("ldap-group-members-modal");
      if (currentMembersDialog instanceof HTMLDialogElement && nextMembersDialog instanceof HTMLDialogElement) {
        currentMembersDialog.replaceWith(document.importNode(nextMembersDialog, true));
      }

      tabList.querySelectorAll(".tab-button").forEach((item) => {
        const active = item === link;
        item.classList.toggle("active", active);
        item.setAttribute("aria-selected", active ? "true" : "false");
      });
      rememberOrganization(organizationId);
      const targetUrl = new URL(link.href, window.location.href);
      if (options.history !== false) {
        const historyMethod = options.replaceHistory ? "replaceState" : "pushState";
        window.history[historyMethod]({ ldapOrganizationId: organizationId }, "", `${targetUrl.pathname}${targetUrl.search}${targetUrl.hash}`);
      }
      initializeTabs();
      initializeLdapDirectoryTables();
      initializeLdapPasswordModal();
      initializeConfirmationModals();
    } catch (_error) {
      window.location.assign(link.href);
    } finally {
      loading = false;
      directoryPanel.removeAttribute("aria-busy");
    }
  };

  const selectedId = currentId || activeId;
  rememberOrganization(selectedId);
  links.forEach((link) => {
    link.addEventListener("click", (event) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      if (link.classList.contains("active")) return;
      loadOrganization(link);
    });
  });
  window.addEventListener("popstate", () => {
    if (window.location.pathname !== "/ldap") return;
    const organizationId = new URL(window.location.href).searchParams.get("organization_id") || "";
    const targetLink = links.find((link) => link.dataset.ldapOrganizationId === organizationId);
    if (targetLink instanceof HTMLAnchorElement) loadOrganization(targetLink, { history: false });
  });
  if (window.location.pathname === "/ldap" && !currentId && validStoredLink instanceof HTMLAnchorElement && storedId !== activeId) {
    loadOrganization(validStoredLink, { replaceHistory: true });
  }
}

function attachLdapGridState(tableElement, table, resourceName, organizationId) {
  atlasoLdapDirectoryTables.set(tableElement, table);
  const storageKey = `atlaso:ldap:grid:${organizationId}:${resourceName}`;
  window.requestAnimationFrame(() => {
    const holder = tableElement.querySelector(".tabulator-tableholder");
    if (!(holder instanceof HTMLElement)) return;
    try {
      const stored = JSON.parse(window.localStorage.getItem(storageKey) || "{}");
      holder.scrollTop = Number.isFinite(stored.top) ? stored.top : 0;
      holder.scrollLeft = Number.isFinite(stored.left) ? stored.left : 0;
    } catch {
      // Keep the default grid position when stored state is unavailable or invalid.
    }
    holder.addEventListener("scroll", () => {
      try {
        window.localStorage.setItem(storageKey, JSON.stringify({ top: holder.scrollTop, left: holder.scrollLeft }));
      } catch {
        // Scrolling remains functional when browser storage is unavailable.
      }
    }, { passive: true });
  });
}

function redrawLdapDirectoryTables(root = document) {
  if (!(root instanceof Document || root instanceof HTMLElement)) return;
  window.requestAnimationFrame(() => {
    root.querySelectorAll("#ldap-users-table, #ldap-groups-table").forEach((tableElement) => {
      const table = atlasoLdapDirectoryTables.get(tableElement);
      if (!tableElement.isConnected || tableElement.offsetParent === null) return;
      if (!tableElement.querySelector(".tabulator-tableholder")) return;
      if (table && typeof table.redraw === "function") table.redraw(true);
    });
  });
}

async function postLdapDirectoryAction(url, data, csrf, options = {}) {
  const body = new FormData();
  body.set("csrf", csrf);
  Object.entries(data || {}).forEach(([key, value]) => {
    if (["id", "is_new", "dn", "password_status", "password_applied_at", "unlock_requested", "created_at", "updated_at", "member_count", "member_names", "members", "organization_id"].includes(key)) return;
    if (Array.isArray(value)) value.forEach((item) => body.append(key, item ?? ""));
    else body.set(key, value ?? "");
  });
  const response = await fetch(url, { method: "POST", body, credentials: "same-origin", headers: { Accept: "application/json" } });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ") || "The LDAP directory entry could not be saved.");
  }
  if (options.reload !== false) window.location.reload();
  return response.headers.get("content-type")?.includes("application/json") ? response.json() : null;
}

async function autoSaveLdapUser(cell, csrf, organizationId) {
  clearCaMessage("ldap-user-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    reformatPendingNewRecord(cell);
    if (!String(data.uid || "").trim()) return;
    try {
      await postLdapDirectoryAction(`/ldap/organizations/${organizationId}/users`, data, csrf);
    } catch (error) {
      showCaMessage("ldap-user-error", error instanceof Error ? error.message : "The LDAP user could not be added.");
      if (typeof cell.restoreOldValue === "function") cell.restoreOldValue();
    }
    return;
  }
  try {
    await postLdapDirectoryAction(`/ldap/users/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
  } catch (error) {
    showCaMessage("ldap-user-error", error instanceof Error ? error.message : "The LDAP user could not be saved.");
    if (typeof cell.restoreOldValue === "function") cell.restoreOldValue();
  }
}

function openLdapPasswordModal(data) {
  const dialog = document.getElementById("ldap-password-modal");
  const form = document.getElementById("ldap-password-form");
  const title = document.getElementById("ldap-password-modal-title");
  if (!(dialog instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement)) return;
  form.action = `/ldap/users/${encodeURIComponent(data.id)}/password`;
  form.reset();
  if (title) title.textContent = `Reset ${data.uid} password`;
  dialog.showModal();
  const passwordInput = form.querySelector('input[name="password"]');
  if (passwordInput instanceof HTMLInputElement) passwordInput.focus();
}

async function deleteLdapUserFromMenu(row, csrf) {
  const data = row.getData();
  if (data.is_new) return;
  const confirmed = await requestConfirmation({ title: `Delete ${data.uid}?`, message: "This permanently removes the user from desired state and from OpenLDAP on the next global appliance apply.", label: "Delete user" });
  if (!confirmed) return;
  try { await postLdapDirectoryAction(`/ldap/users/${data.id}/delete`, {}, csrf); }
  catch (error) { showCaMessage("ldap-user-error", error instanceof Error ? error.message : "The LDAP user could not be deleted."); }
}

async function unlockLdapUserFromMenu(row, csrf) {
  const data = row.getData();
  if (data.is_new) return;
  try { await postLdapDirectoryAction(`/ldap/users/${data.id}/unlock`, {}, csrf); }
  catch (error) { showCaMessage("ldap-user-error", error instanceof Error ? error.message : "The LDAP user could not be unlocked."); }
}

async function autoSaveLdapGroup(cell, csrf, organizationId) {
  clearCaMessage("ldap-group-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    reformatPendingNewRecord(cell);
    if (!String(data.name || "").trim()) return;
    try { await postLdapDirectoryAction(`/ldap/organizations/${organizationId}/groups`, data, csrf); }
    catch (error) {
      showCaMessage("ldap-group-error", error instanceof Error ? error.message : "The LDAP group could not be added.");
      if (typeof cell.restoreOldValue === "function") cell.restoreOldValue();
    }
    return;
  }
  try {
    await postLdapDirectoryAction(`/ldap/groups/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
  } catch (error) {
    showCaMessage("ldap-group-error", error instanceof Error ? error.message : "The LDAP group could not be saved.");
    if (typeof cell.restoreOldValue === "function") cell.restoreOldValue();
  }
}

function openLdapGroupMembersModal(data) {
  const dialog = document.getElementById("ldap-group-members-modal");
  const form = document.getElementById("ldap-group-members-form");
  const title = document.getElementById("ldap-group-members-modal-title");
  if (!(dialog instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement)) return;
  form.action = `/ldap/groups/${encodeURIComponent(data.id)}/members`;
  if (title) title.textContent = `Edit ${data.name} membership`;
  const selected = new Set((data.members || []).map((member) => `${member.type}:${member.id}`));
  form.querySelectorAll('select[name="members"] option').forEach((option) => {
    option.hidden = option.dataset.memberGroupId === String(data.id);
    option.disabled = option.hidden;
    option.selected = selected.has(option.value);
  });
  dialog.showModal();
}

async function deleteLdapGroupFromMenu(row, csrf) {
  const data = row.getData();
  if (data.is_new) return;
  const confirmed = await requestConfirmation({ title: `Delete ${data.name}?`, message: "This removes the group and its nested memberships from desired state and OpenLDAP on the next global appliance apply.", label: "Delete group" });
  if (!confirmed) return;
  try { await postLdapDirectoryAction(`/ldap/groups/${data.id}/delete`, {}, csrf); }
  catch (error) { showCaMessage("ldap-group-error", error instanceof Error ? error.message : "The LDAP group could not be deleted."); }
}

function ensureLdapMembershipTooltip() {
  if (!ldapMembershipTooltip) {
    ldapMembershipTooltip = document.createElement("div");
    ldapMembershipTooltip.className = "dhcp-range-tooltip ldap-membership-tooltip hidden";
    document.body.appendChild(ldapMembershipTooltip);
  }
  return ldapMembershipTooltip;
}

function moveLdapMembershipTooltip(event) {
  if (!ldapMembershipTooltip || ldapMembershipTooltip.classList.contains("hidden")) return;
  const offset = 12;
  const width = ldapMembershipTooltip.offsetWidth || 280;
  const height = ldapMembershipTooltip.offsetHeight || 160;
  const x = Math.min(event.clientX + offset, window.innerWidth - width - offset);
  const y = Math.min(event.clientY + offset, window.innerHeight - height - offset);
  ldapMembershipTooltip.style.left = `${Math.max(offset, x)}px`;
  ldapMembershipTooltip.style.top = `${Math.max(offset, y)}px`;
}

function showLdapMembershipTooltip(event, members = []) {
  if (!Array.isArray(members) || !members.length) return;
  const tooltip = ensureLdapMembershipTooltip();
  tooltip.innerHTML = `
    <table aria-label="Group membership">
      <thead><tr><th>Type</th><th>Member</th></tr></thead>
      <tbody>${members.map((member) => `<tr><td>${escapeHtml(member.type === "group" ? "Group" : "User")}</td><td>${escapeHtml(member.name || "")}</td></tr>`).join("")}</tbody>
    </table>
  `;
  tooltip.classList.remove("hidden");
  moveLdapMembershipTooltip(event);
}

function hideLdapMembershipTooltip() {
  ldapMembershipTooltip?.classList.add("hidden");
}

function ldapGroupMembershipFormatter(cell) {
  const data = cell.getRow().getData();
  const element = document.createElement("span");
  element.className = "ldap-membership-value";
  element.textContent = String(cell.getValue() || "");
  if (Array.isArray(data.members) && data.members.length) {
    element.addEventListener("mouseenter", (event) => showLdapMembershipTooltip(event, data.members));
    element.addEventListener("mousemove", moveLdapMembershipTooltip);
    element.addEventListener("mouseleave", hideLdapMembershipTooltip);
  }
  return element;
}

function initializeLdapDirectoryTables() {
  hideLdapMembershipTooltip();
  const usersElement = document.getElementById("ldap-users-table");
  if (usersElement instanceof HTMLElement && typeof Tabulator !== "undefined") {
    const csrf = usersElement.dataset.csrf || "";
    const organizationId = usersElement.dataset.organizationId || "0";
    try {
      const adapter = initializeAtlasoResourceWizard({
        elementId: "ldap-users-table",
        formSelector: "[data-ldap-user-form]",
        dialogId: "ldap-user-dialog",
        rows: JSON.parse(usersElement.dataset.users || "[]"),
        newRow: newLdapUserRow(organizationId),
        resourceName: "user",
        normalizeResource: (_resource, payload) => payload,
        createUrl: `/ldap/organizations/${organizationId}/users`,
        editUrl: (id) => `/ldap/users/${id}/edit`,
        deleteResource: true,
        deleteUrl: (id) => `/ldap/users/${id}/delete`,
        editLabel: "Edit user",
        deleteLabel: "Delete user",
        createLabel: "Create LDAP user",
        updateLabel: "Update LDAP user",
        emptyMessage: "No directory users.",
        actionErrorSelector: "#ldap-user-error",
        defaults: newLdapUserRow(organizationId),
        steps: [
          { id: "identity", title: "Define the LDAP identity", description: "Choose the stable UID and operator-visible display name." },
          { id: "contact", title: "Set directory attributes", description: "Add name and optional contact attributes." },
          { id: "password", title: "Stage an optional password", description: "Set a credential now or leave both fields blank to postpone it." },
          { id: "enablement", title: "Choose account state", description: "Control whether the account enters rendered LDAP desired state." },
          { id: "review", title: "Review the LDAP user", description: "Confirm the account and global appliance-apply boundary." },
        ],
        reviewItems: [
          { label: "UID", field: "uid" },
          { label: "Display name", value: (form) => form.elements.display_name.value.trim() || "Derived from name" },
          { label: "Email", field: "email" },
          { label: "Password", value: (form) => form.elements.password.value ? "Staged until apply" : "Unchanged or postponed" },
          { label: "State", field: "enabled" },
        ],
        validateStep: ({ form, step }) => {
          if (step.id !== "password") return { valid: true };
          if (form.elements.password.value === form.elements.confirm_password.value) return { valid: true };
          return { valid: false, field: "confirm_password", message: "Password confirmation does not match." };
        },
        onOpen: ({ form }) => {
          form.elements.password.value = "";
          form.elements.confirm_password.value = "";
        },
        onSaved: ({ resource }) => {
          const select = document.querySelector("[data-ldap-group-form] select[name='members']");
          if (!(select instanceof HTMLSelectElement)) return;
          const value = `user:${resource.id}`;
          let option = [...select.options].find((item) => item.value === value);
          if (!option) {
            option = document.createElement("option");
            option.value = value;
            select.append(option);
          }
          option.textContent = `User: ${resource.uid}`;
        },
        onDeleted: ({ data }) => {
          const select = document.querySelector("[data-ldap-group-form] select[name='members']");
          if (select instanceof HTMLSelectElement) {
            [...select.options].find((option) => option.value === `user:${data.id}`)?.remove();
          }
        },
        extraActions: [
          { label: "Reset password", action: (_event, row) => openLdapPasswordModal(row.getData()), disabled: (component) => component.getData().is_new },
          { label: "Administrative unlock", action: (_event, row) => unlockLdapUserFromMenu(row, csrf), disabled: (component) => component.getData().is_new },
        ],
        deleteConfirmation: (data) => ({
          title: `Delete ${data.uid}?`,
          message: "This permanently removes the user from desired state and from OpenLDAP on the next global appliance apply.",
          confirmLabel: "Delete user",
          tone: "danger",
        }),
        options: {
          layout: "fitColumns",
          height: "420px",
          rowHeight: 28,
          placeholder: "No directory users",
          reactiveData: false,
          columns: [
            { title: "UID", field: "uid", formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add user here</button>' : escapeHtml(cell.getValue()), minWidth: 145 },
            { title: "Given name", field: "given_name", minWidth: 130 },
            { title: "Surname", field: "surname", minWidth: 130 },
            { title: "Display name", field: "display_name", minWidth: 175 },
            { title: "Email", field: "email", minWidth: 195 },
            { title: "Telephone", field: "telephone", minWidth: 145 },
            { title: "Password", field: "password_status", minWidth: 125 },
            { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 95 },
            { title: "DN", field: "dn", minWidth: 260, visible: false },
          ],
          rowFormatter: (row) => markNewRecordRow(row, "uid"),
        },
      });
      if (adapter?.table) {
        attachLdapGridState(usersElement, adapter.table, "users", organizationId);
      }
    } catch (error) { showCaMessage("ldap-user-error", error instanceof Error ? error.message : "LDAP users could not render."); }
  }

  const groupsElement = document.getElementById("ldap-groups-table");
  if (groupsElement instanceof HTMLElement && typeof Tabulator !== "undefined") {
    const csrf = groupsElement.dataset.csrf || "";
    const organizationId = groupsElement.dataset.organizationId || "0";
    try {
      const normalizeGroup = (group) => ({
        ...group,
        member_count: Array.isArray(group.members) ? group.members.length : 0,
        member_names: Array.isArray(group.members) ? group.members.map((member) => `${member.type}: ${member.name}`).join(", ") : "",
      });
      const adapter = initializeAtlasoResourceWizard({
        elementId: "ldap-groups-table",
        formSelector: "[data-ldap-group-form]",
        dialogId: "ldap-group-dialog",
        rows: JSON.parse(groupsElement.dataset.groups || "[]").map(normalizeGroup),
        newRow: newLdapGroupRow(organizationId),
        resourceName: "group",
        normalizeResource: (_resource, payload) => normalizeGroup(payload),
        createUrl: `/ldap/organizations/${organizationId}/groups`,
        editUrl: (id) => `/ldap/groups/${id}/edit`,
        deleteResource: true,
        deleteUrl: (id) => `/ldap/groups/${id}/delete`,
        editLabel: "Edit group",
        deleteLabel: "Delete group",
        createLabel: "Create LDAP group",
        updateLabel: "Update LDAP group",
        emptyMessage: "No directory groups.",
        actionErrorSelector: "#ldap-group-error",
        defaults: newLdapGroupRow(organizationId),
        inlineEnabled: false,
        steps: [
          { id: "identity", title: "Define the LDAP group", description: "Choose its unique name and operator-visible purpose." },
          { id: "membership", title: "Choose group members", description: "Select users and nested groups from this organization." },
          { id: "enablement", title: "Choose group state", description: "Control whether the group enters rendered LDAP desired state." },
          { id: "review", title: "Review the LDAP group", description: "Confirm membership and the global appliance-apply boundary." },
        ],
        reviewItems: [
          { label: "Group", field: "name" },
          { label: "Description", field: "description" },
          { label: "Members", value: (form) => `${form.elements.members.selectedOptions.length} selected` },
          { label: "State", field: "enabled" },
        ],
        onOpen: ({ form, context }) => {
          const selected = new Set((context?.members || []).map((member) => `${member.type}:${member.id}`));
          const memberSelect = form.elements.members;
          if (!(memberSelect instanceof HTMLSelectElement)) return;
          [...memberSelect.options].forEach((option) => {
            const isCurrentGroup = option.dataset.memberGroupId === String(context?.id || "");
            option.hidden = isCurrentGroup;
            option.disabled = isCurrentGroup;
            option.selected = !isCurrentGroup && selected.has(option.value);
          });
        },
        onSaved: ({ resource }) => {
          const select = document.querySelector("[data-ldap-group-form] select[name='members']");
          if (!(select instanceof HTMLSelectElement)) return;
          const value = `group:${resource.id}`;
          let option = [...select.options].find((item) => item.value === value);
          if (!option) {
            option = document.createElement("option");
            option.value = value;
            option.dataset.memberGroupId = String(resource.id);
            select.append(option);
          }
          option.textContent = `Group: ${resource.name}`;
        },
        onDeleted: ({ data }) => {
          const select = document.querySelector("[data-ldap-group-form] select[name='members']");
          if (select instanceof HTMLSelectElement) {
            [...select.options].find((option) => option.value === `group:${data.id}`)?.remove();
          }
        },
        deleteConfirmation: (data) => ({
          title: `Delete ${data.name}?`,
          message: "This removes the group and its nested memberships from desired state and OpenLDAP on the next global appliance apply.",
          confirmLabel: "Delete group",
          tone: "danger",
        }),
        options: {
          layout: "fitColumns",
          height: "420px",
          rowHeight: 28,
          responsiveLayout: "collapse",
          placeholder: "No directory groups",
          reactiveData: false,
          columns: [
            { title: "Name", field: "name", formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add group here</button>' : escapeHtml(cell.getValue()), minWidth: 170 },
            { title: "Description", field: "description", minWidth: 240 },
            { title: "Members", field: "member_count", width: 105, hozAlign: "right" },
            { title: "Membership", field: "member_names", formatter: ldapGroupMembershipFormatter, minWidth: 260 },
            { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), editor: "tickCross", hozAlign: "center", width: 95, cellEdited: (cell) => autoSaveLdapGroup(cell, csrf, organizationId) },
          ],
          rowFormatter: (row) => markNewRecordRow(row, "name"),
        },
      });
      if (adapter?.table) {
        attachLdapGridState(groupsElement, adapter.table, "groups", organizationId);
      }
    } catch (error) { showCaMessage("ldap-group-error", error instanceof Error ? error.message : "LDAP groups could not render."); }
  }
}

function initializeLdapPasswordModal() {
  const dialog = document.getElementById("ldap-password-modal");
  const form = document.getElementById("ldap-password-form");
  const title = document.getElementById("ldap-password-modal-title");
  const cancel = dialog?.querySelector("[data-ldap-password-cancel]");
  if (!(dialog instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement)) return;
  document.querySelectorAll("[data-ldap-password-button]").forEach((button) => {
    if (button.dataset.ldapPasswordInitialized === "true") return;
    button.dataset.ldapPasswordInitialized = "true";
    button.addEventListener("click", () => openLdapPasswordModal({ id: button.dataset.userId || "0", uid: button.dataset.userUid || "directory user" }));
  });
  if (dialog.dataset.ldapPasswordInitialized !== "true") {
    dialog.dataset.ldapPasswordInitialized = "true";
    cancel?.addEventListener("click", () => dialog.close());
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  }

  const membersDialog = document.getElementById("ldap-group-members-modal");
  const membersCancel = membersDialog?.querySelector("[data-ldap-group-members-cancel]");
  if (membersDialog instanceof HTMLDialogElement && membersDialog.dataset.ldapMembersInitialized !== "true") {
    membersDialog.dataset.ldapMembersInitialized = "true";
    membersCancel?.addEventListener("click", () => membersDialog.close());
  }
}

function parseNtpUpstreamSource(value) {
  const source = String(value || "").trim();
  if (!source) return null;
  let host = source;
  let port = "";
  const bracketed = source.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    host = bracketed[1];
    port = bracketed[2] || "";
    if (!isValidIpv6Address(host)) return null;
  } else if (!isValidIpv6Address(source) && source.split(":").length === 2) {
    const parts = source.split(":");
    if (/^\d+$/.test(parts[1])) {
      [host, port] = parts;
    }
  }
  if (port && (Number(port) < 1 || Number(port) > 65535)) return null;
  const normalizedHost = host.replace(/\.$/, "").toLowerCase();
  const fqdnPattern = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!isValidIpv4Address(host) && !isValidIpv6Address(host) && !fqdnPattern.test(normalizedHost)) return null;
  return { host: normalizedHost, port: port ? Number(port) : null };
}

function ntpUpstreamSourceFormatter(cell) {
  const data = cell.getRow().getData();
  const value = String(cell.getValue() || "").trim();
  if (data.is_new && !value) {
    return '<span class="add-row-hint">+ Add source here</span>';
  }
  const valid = Boolean(parseNtpUpstreamSource(value));
  cell.getElement().classList.toggle("invalid-ntp-source-cell", !valid);
  cell.getElement().title = valid ? "" : "Enter an IPv4 address, IPv6 address, or FQDN, optionally followed by :port.";
  return escapeHtml(value);
}

function ntpUpstreamSourceEditor(cell, onRendered, success, cancel) {
  const input = document.createElement("input");
  input.type = "text";
  input.value = cell.getValue() || "";
  input.placeholder = "time.example.com[:4460]";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.setAttribute("aria-label", "NTP upstream source");
  let finished = false;

  const updateValidity = () => {
    const value = input.value.trim();
    input.classList.toggle("invalid-ntp-source-input", Boolean(value) && !parseNtpUpstreamSource(value));
  };
  const submit = () => {
    if (finished) return true;
    const value = input.value.trim();
    if (value && !parseNtpUpstreamSource(value)) {
      input.classList.add("invalid-ntp-source-input");
      const status = document.getElementById("ntp-settings-autosave-status");
      if (status instanceof HTMLElement) {
        status.dataset.state = "error";
        status.textContent = "Enter an IPv4 address, IPv6 address, or FQDN, optionally followed by :port.";
      }
      return false;
    }
    finished = true;
    success(value);
    return true;
  };
  input.addEventListener("input", updateValidity);
  input.addEventListener("blur", () => {
    if (!submit()) cancel();
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    } else if (event.key === "Escape") {
      finished = true;
      cancel();
    }
  });
  onRendered(() => {
    input.focus();
    input.select();
    updateValidity();
  });
  return input;
}

function ntpBlankUpstreamRow() {
  return {
    id: `new-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    source: "",
    enabled: false,
    use_nts: false,
    description: "",
    is_new: true,
  };
}

function ntpUpstreamRowHasSource(cell) {
  return Boolean(String(cell.getRow().getData().source || "").trim());
}

function ntpGuardedTickFormatter(cell) {
  if (!ntpUpstreamRowHasSource(cell)) {
    return "";
  }
  return atlasoBooleanFormatter(cell);
}

function ntpNtsTickFormatter(cell) {
  if (!ntpUpstreamRowHasSource(cell) || !cell.getValue()) {
    return "";
  }
  return atlasoBooleanFormatter(cell);
}

function ntpUnsupportedNtsFormatter(cell) {
  if (!ntpUpstreamRowHasSource(cell)) {
    return "";
  }
  return '<span class="muted" title="NTS is not supported by the installed ntpd binary">unavailable</span>';
}

function ntpGuardedTextFormatter(cell) {
  if (!ntpUpstreamRowHasSource(cell)) {
    return "";
  }
  return escapeHtml(cell.getValue() || "");
}

function normalizeNTPsecUpstreamRows(rows = []) {
  return rows
    .map((row, index) => ({
      id: row.id || `source-${index + 1}`,
      source: String(row.source || "").trim(),
      enabled: row.enabled !== false,
      use_nts: Boolean(row.use_nts),
      description: String(row.description || "").trim(),
    }))
    .filter((row) => row.source);
}

function syncNTPsecUpstreamsHiddenInput(table) {
  const hiddenInput = document.querySelector("[data-ntp-upstreams-json]");
  if (!(hiddenInput instanceof HTMLInputElement)) {
    return;
  }
  hiddenInput.value = JSON.stringify(normalizeNTPsecUpstreamRows(table.getData()));
}

function ensureNTPsecUpstreamAddRow(table) {
  const rows = table.getData();
  const hasBlankRow = rows.some((row) => row.is_new && !String(row.source || "").trim());
  if (!hasBlankRow) {
    table.addRow(ntpBlankUpstreamRow(), false);
  }
}

function submitNtpUpstreamTableChange(table, hiddenInput) {
  syncNTPsecUpstreamsHiddenInput(table);
  if (hiddenInput instanceof HTMLInputElement) {
    hiddenInput.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

async function persistNtpUpstreamTableChange(table, hiddenInput) {
  syncNTPsecUpstreamsHiddenInput(table);
  const settingsForm = hiddenInput?.form;
  if (!(settingsForm instanceof HTMLFormElement) || typeof settingsForm.atlasoSaveNow !== "function") {
    return { valid: false, message: "NTP settings autosave is unavailable. Reload the page and try again." };
  }
  return settingsForm.atlasoSaveNow();
}

async function deleteNtpUpstreamFromMenu(row, table, hiddenInput) {
  const data = row.getData();
  if (data.is_new) return;
  const source = String(data.source || "upstream server");
  const confirmed = await requestConfirmation({
    title: `Delete ${source}?`,
    message: "This removes the upstream server from NTP desired state. The appliance is not changed until global appliance apply runs.",
    label: "Delete server",
  });
  if (!confirmed) return;
  await row.delete();
  ensureNTPsecUpstreamAddRow(table);
  submitNtpUpstreamTableChange(table, hiddenInput);
}

function initializeNTPsecUpstreamsTable() {
  const tableElement = document.getElementById("ntp-upstreams-table");
  const form = document.querySelector("[data-ntp-source-form]");
  const dialog = document.getElementById("ntp-source-dialog");
  if (
    !(tableElement instanceof HTMLElement)
    || !(form instanceof HTMLFormElement)
    || !(dialog instanceof HTMLDialogElement)
  ) return;
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  const hiddenInput = document.querySelector("[data-ntp-upstreams-json]");
  if (typeof Tabulator === "undefined") {
    if (fallback instanceof HTMLElement) {
      fallback.classList.remove("hidden");
    }
    return;
  }
  try {
    const parsedRows = JSON.parse(tableElement.dataset.ntpUpstreams || "[]");
    const ntsSupported = tableElement.dataset.ntpNtsSupported !== "false";
    const rows = normalizeNTPsecUpstreamRows(parsedRows);
    rows.push(ntpBlankUpstreamRow());
    let table;
    let wizard;
    const openSource = (data, launcher) => wizard.open({ launcher, context: data?.is_new ? null : data });
    const grid = window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      fallback: fallback instanceof HTMLElement ? `#${fallback.id}` : undefined,
      status: "#ntp-settings-autosave-status",
      pattern: "wizard-backed",
      emptyMessage: "No upstream sources configured.",
      onOpenRow: (data, row, event) => openSource(
        data,
        event?.currentTarget || row?.getElement?.(),
      ),
      rowActions: [
        {
          label: "Edit source",
          disabled: (row) => row.getData().is_new,
          action: (_event, row) => openSource(row.getData(), row.getElement()),
        },
        {
          label: "Delete server",
          disabled: (row) => row.getData().is_new,
          action: (_event, row) => deleteNtpUpstreamFromMenu(row, table, hiddenInput),
        },
      ],
      options: {
        data: rows,
        index: "id",
        layout: "fitColumns",
        height: "260px",
        rowHeight: 34,
        placeholder: "No upstream sources configured.",
        reactiveData: false,
        columns: [
          {
            title: "Source",
            field: "source",
            formatter: (cell) => cell.getRow().getData().is_new
              ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add source here</button>'
              : escapeHtml(cell.getValue()),
            width: 360,
            minWidth: 230,
            headerTooltip: "IPv4, IPv6, or fully qualified DNS name. Append :port when the upstream uses a non-default port; use [IPv6]:port for IPv6.",
          },
          {
            title: "NTS",
            field: "use_nts",
            formatter: ntsSupported ? ntpNtsTickFormatter : ntpUnsupportedNtsFormatter,
            width: ntsSupported ? 70 : 105,
            hozAlign: "center",
          },
          {
            title: "Enabled",
            field: "enabled",
            formatter: ntpGuardedTickFormatter,
            editor: "tickCross",
            editable: ntpUpstreamRowHasSource,
            width: 92,
            hozAlign: "center",
            cellEdited: () => submitNtpUpstreamTableChange(table, hiddenInput),
          },
          {
            title: "Description",
            field: "description",
            minWidth: 240,
            widthGrow: 5,
            formatter: ntpGuardedTextFormatter,
          },
        ],
        rowFormatter: (row) => markNewRecordRow(row, "source"),
      },
    });
    table = grid.table;
    if (!table) return;
    wizard = window.AtlasoUiPatterns.createWizard({
      form,
      dialog,
      steps: [
        { id: "identity", title: "Define the NTP source", description: "Set the upstream endpoint and its operator-visible purpose." },
        { id: "enablement", title: "Choose source security and state", description: "Choose NTS authentication and whether the source enters desired state." },
        { id: "review", title: "Review NTP desired state", description: "Confirm the source and global appliance-apply boundary." },
      ],
      onOpen: ({ context }) => {
        populateAtlasoWizardForm(form, {
          record_id: context?.id || "",
          source: context?.source || "",
          description: context?.description || "",
          use_nts: Boolean(context?.use_nts),
          enabled: context ? Boolean(context.enabled) : true,
        });
      },
      validateStep: ({ step }) => {
        if (step.id === "identity" && !parseNtpUpstreamSource(form.elements.source.value)) {
          return {
            valid: false,
            message: "Enter an IPv4 address, IPv6 address, or FQDN, optionally followed by :port.",
            field: "source",
          };
        }
        return { valid: true };
      },
      prepareReview: () => renderAtlasoWizardReview(form, [
        { label: "Source", field: "source" },
        { label: "Description", field: "description" },
        { label: "NTS", field: "use_nts" },
        { label: "Enabled", field: "enabled" },
      ]),
      onSubmit: async () => {
        const id = form.elements.record_id.value;
        const payload = {
          id: id || `source-${Date.now()}`,
          source: form.elements.source.value.trim(),
          description: form.elements.description.value.trim(),
          use_nts: ntsSupported && form.elements.use_nts.checked,
          enabled: form.elements.enabled.checked,
        };
        const existing = id ? table.getRow(id) : null;
        const previous = existing ? { ...existing.getData() } : null;
        const inserted = existing
          ? null
          : await table.addRow(payload, true, table.getRows().find((row) => row.getData().is_new));
        if (existing) await existing.update(payload);
        ensureNTPsecUpstreamAddRow(table);
        const result = await persistNtpUpstreamTableChange(table, hiddenInput);
        if (result?.valid === false) {
          if (existing && previous) await existing.update(previous);
          if (inserted) await inserted.delete();
          ensureNTPsecUpstreamAddRow(table);
          syncNTPsecUpstreamsHiddenInput(table);
          return result;
        }
        return { valid: true };
      },
    });
    tableElement.addEventListener("click", (event) => {
      const launcher = event.target.closest("[data-atlaso-wizard-add]");
      if (launcher instanceof HTMLButtonElement) openSource(null, launcher);
    });
    syncNTPsecUpstreamsHiddenInput(table);
  } catch (error) {
    if (fallback instanceof HTMLElement) {
      fallback.classList.remove("hidden");
    }
  }
}

function updateNtpSettingsPreview(form, payload = {}) {
  updateDerivedListenAddressSummary(form, payload);
  const configPath = document.querySelector("[data-ntp-config-path]");
  if (configPath instanceof HTMLElement && payload.config_path) {
    configPath.textContent = payload.config_path;
  }
  const configPreview = document.querySelector("[data-ntp-config-preview]");
  if (configPreview instanceof HTMLElement && payload.config_preview !== undefined) {
    configPreview.textContent = payload.config_preview;
    highlightConfigPreviewElement(configPreview);
  }
  const hostname = form.querySelector('input[name="hostname"]');
  if (hostname instanceof HTMLInputElement && payload.hostname) {
    hostname.value = payload.hostname;
  }
  const port = form.querySelector('input[name="port"]');
  if (port instanceof HTMLInputElement && payload.port) {
    port.value = String(payload.port);
  }
}

function updateNtpValidation(payload = {}) {
  const status = document.querySelector("[data-ntp-validation-status]");
  const validationPanel = status?.closest(".panel");
  if (!(status instanceof HTMLElement) || !(validationPanel instanceof HTMLElement)) {
    return;
  }
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  status.textContent = errors.length ? "needs attention" : "valid";
  status.classList.toggle("good", errors.length === 0);
  status.classList.toggle("warn", errors.length > 0);
  const previewAnchor = validationPanel.querySelector("[data-config-preview-row]");
  let errorBox = validationPanel.querySelector("[data-ntp-validation-errors]");
  const validMessage = validationPanel.querySelector("[data-ntp-validation-message]");
  if (errors.length === 0) {
    errorBox?.remove();
    if (!(validMessage instanceof HTMLElement)) {
      const message = document.createElement("p");
      message.className = "muted";
      message.setAttribute("data-ntp-validation-message", "");
      message.textContent = "The desired NTPsec state passes Atlaso validation. Appliance validation still runs through the allowlisted NTPsec helper before apply.";
      validationPanel.insertBefore(message, previewAnchor);
    }
    return;
  }
  validMessage?.remove();
  if (!(errorBox instanceof HTMLElement)) {
    errorBox = document.createElement("ul");
    errorBox.className = "error-list";
    errorBox.setAttribute("data-ntp-validation-errors", "");
    validationPanel.insertBefore(errorBox, previewAnchor);
  }
  if (errorBox instanceof HTMLElement) {
    errorBox.innerHTML = "";
    errors.forEach((error) => {
      const row = document.createElement("li");
      row.textContent = error;
      errorBox.appendChild(row);
    });
  }
}

function initializeNtpSettings(root = document) {
  root.querySelectorAll("[data-ntp-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.ntpSettingsInitialized === "1") return;
    form.dataset.ntpSettingsInitialized = "1";
    form.addEventListener("atlaso:autosave-success", (event) => {
      const payload = event.detail || {};
      updateNtpSettingsPreview(form, payload);
      updateNtpValidation(payload);
    });
  });
}

function formatNTPsecSourceHealthSection(name, section = {}) {
  const title = name.charAt(0).toUpperCase() + name.slice(1);
  const returnCode = Number(section.returncode ?? 0);
  const stdout = String(section.stdout || "").trimEnd();
  const stderr = String(section.stderr || "").trimEnd();
  const lines = [`[${title}] returncode=${returnCode}`];
  if (stdout) {
    lines.push(stdout);
  }
  if (stderr) {
    lines.push(`stderr: ${stderr}`);
  }
  if (!stdout && !stderr) {
    lines.push("(no output)");
  }
  return lines.join("\n");
}

function formatNTPsecSourceHealthPayload(payload = {}) {
  const sections = payload.status && typeof payload.status === "object" ? payload.status : {};
  const names = ["peers", "variables", "nts"];
  if (names.some((name) => sections[name])) {
    return names.map((name) => formatNTPsecSourceHealthSection(name, sections[name] || {})).join("\n\n");
  }
  const stdout = String(payload.stdout || "").trimEnd();
  const stderr = String(payload.stderr || "").trimEnd();
  return [stdout, stderr ? `stderr: ${stderr}` : ""].filter(Boolean).join("\n\n") || "No NTPsec source health output was returned.";
}

function setNTPsecSourceHealthStatus(statusElement, text, state) {
  if (!(statusElement instanceof HTMLElement)) {
    return;
  }
  statusElement.textContent = text;
  statusElement.classList.toggle("good", state === "good");
  statusElement.classList.toggle("warn", state === "warn");
  statusElement.classList.toggle("muted", state === "muted");
}

let ntpSourceHealthLoader = null;

function openNTPsecSourceHealthModal() {
  const modal = document.getElementById("ntp-source-health-modal");
  if (!(modal instanceof HTMLDialogElement)) {
    return;
  }
  if (typeof modal.showModal === "function") {
    modal.showModal();
  } else {
    modal.setAttribute("open", "");
  }
  if (typeof ntpSourceHealthLoader === "function") {
    ntpSourceHealthLoader();
  }
}

function initializeNTPsecSourceHealthModal() {
  const modal = document.getElementById("ntp-source-health-modal");
  const output = modal?.querySelector("[data-ntp-source-health-output]");
  const status = modal?.querySelector("[data-ntp-source-health-status]");
  const refreshButton = modal?.querySelector("[data-ntp-source-health-refresh]");
  const closeButton = modal?.querySelector("[data-ntp-source-health-close]");
  if (!(modal instanceof HTMLDialogElement) || !(output instanceof HTMLElement)) {
    return;
  }

  const loadHealth = async () => {
    setNTPsecSourceHealthStatus(status, "checking", "muted");
    output.textContent = "Checking ntpq peers, runtime variables, and NTS state...";
    if (refreshButton instanceof HTMLButtonElement) {
      refreshButton.disabled = true;
    }
    try {
      const response = await fetch("/ntp/source-health", {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      const payload = await response.json();
      output.textContent = formatNTPsecSourceHealthPayload(payload);
      const failedSection = Object.values(payload.status || {}).some((section) => Number(section?.returncode ?? 0) !== 0);
      if (!response.ok || !payload.ok || failedSection) {
        setNTPsecSourceHealthStatus(status, "needs attention", "warn");
      } else if (payload.dry_run) {
        setNTPsecSourceHealthStatus(status, "dry-run", "muted");
      } else {
        setNTPsecSourceHealthStatus(status, "healthy", "good");
      }
    } catch (error) {
      output.textContent = error instanceof Error ? error.message : "Unable to check NTPsec source health.";
      setNTPsecSourceHealthStatus(status, "failed", "warn");
    } finally {
      if (refreshButton instanceof HTMLButtonElement) {
        refreshButton.disabled = false;
      }
    }
  };
  ntpSourceHealthLoader = loadHealth;

  document.querySelectorAll("[data-ntp-source-health-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", openNTPsecSourceHealthModal);
  });
  if (refreshButton instanceof HTMLButtonElement) {
    refreshButton.addEventListener("click", loadHealth);
  }
  if (closeButton instanceof HTMLButtonElement) {
    closeButton.addEventListener("click", () => modal.close());
  }
}

function showWanMessage(elementId, message) {
  showCaMessage(elementId, message, "error");
}

async function postWanAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (["id", "is_new", "wan_policy_name"].includes(key)) {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }
  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    const plainText = text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    throw new Error(plainText || "The route and WAN desired state could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newWanRouteRow(defaultTarget = "") {
  return {
    id: "__new__",
    destination_cidr: "",
    gateway: "",
    interface_name: defaultTarget,
    metric: 100,
    enabled: true,
    wan_policy_id: "",
    wan_policy_name: "",
    wan_mode: "interface",
    is_new: true,
  };
}

function newWanPolicyRow() {
  return {
    id: "__new__",
    name: "",
    description: "",
    enabled: true,
    latency_ms: 0,
    jitter_ms: 0,
    packet_loss_percent: 0,
    bandwidth_mbit: "",
    corrupt_percent: 0,
    duplicate_percent: 0,
    reorder_percent: 0,
    is_new: true,
  };
}

function newWanNatRuleRow(defaultTarget = "") {
  return {
    id: "__new__",
    name: "",
    enabled: true,
    source: "any",
    outbound_interface: defaultTarget,
    masquerade: true,
    priority: 100,
    description: "",
    is_new: true,
  };
}

function newWanRoutingRuleRow(defaultSource = "", defaultDestination = "") {
  return {
    id: "__new__",
    name: "",
    kind: "add explicit rule",
    enabled: true,
    source_interface: defaultSource,
    destination_interface: defaultDestination,
    priority: 100,
    description: "",
    generated: false,
    is_new: true,
  };
}

function hasRequiredWanRouteFields(data) {
  return Boolean((data.destination_cidr || "").trim() && (data.interface_name || "").trim());
}

function hasRequiredWanNatFields(data) {
  return Boolean((data.name || "").trim() && (data.outbound_interface || "").trim());
}

function hasRequiredWanPolicyFields(data) {
  return Boolean((data.name || "").trim());
}

function hasRequiredWanRoutingFields(data) {
  return Boolean((data.name || "").trim() && (data.source_interface || "").trim() && (data.destination_interface || "").trim());
}

function wanPolicyValues(policyOptions) {
  const values = { "": "none" };
  policyOptions.forEach((policy) => {
    values[String(policy.id)] = policy.label;
  });
  return values;
}

function wanPolicyFormatter(cell, policyLabels) {
  const value = cell.getValue();
  if (!value) {
    return '<span class="muted">none</span>';
  }
  return escapeHtml(policyLabels[String(value)] || value);
}

async function autoSaveWanRoute(cell, csrf) {
  clearCaMessage("routes-wan-route-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredWanRouteFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postWanAction("/routes-wan/routes", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showWanMessage("routes-wan-route-error", error instanceof Error ? error.message : "The route could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postWanAction(`/routes-wan/routes/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showWanMessage("routes-wan-route-error", error instanceof Error ? error.message : "The route could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function autoSaveWanPolicy(cell, csrf) {
  clearCaMessage("routes-wan-policy-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredWanPolicyFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postWanAction("/routes-wan/policies", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showWanMessage("routes-wan-policy-error", error instanceof Error ? error.message : "The WAN policy could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postWanAction(`/routes-wan/policies/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showWanMessage("routes-wan-policy-error", error instanceof Error ? error.message : "The WAN policy could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function autoSaveWanNatRule(cell, csrf) {
  clearCaMessage("routes-wan-nat-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    if (!hasRequiredWanNatFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postWanAction("/routes-wan/nat-rules", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showWanMessage("routes-wan-nat-error", error instanceof Error ? error.message : "The NAT rule could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postWanAction(`/routes-wan/nat-rules/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showWanMessage("routes-wan-nat-error", error instanceof Error ? error.message : "The NAT rule could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function autoSaveWanRoutingRule(cell, csrf) {
  clearCaMessage("routes-wan-routing-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.generated) {
    return;
  }
  if (data.is_new) {
    if (!hasRequiredWanRoutingFields(data)) {
      reformatPendingNewRecord(cell);
      return;
    }
    try {
      await postWanAction("/routes-wan/routing-rules", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showWanMessage("routes-wan-routing-error", error instanceof Error ? error.message : "The routing rule could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postWanAction(`/routes-wan/routing-rules/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showWanMessage("routes-wan-routing-error", error instanceof Error ? error.message : "The routing rule could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteWanRouteFromMenu(row, csrf) {
  clearCaMessage("routes-wan-route-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete route ${data.destination_cidr}?`,
    message: "This removes the route from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete route",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postWanAction(`/routes-wan/routes/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showWanMessage("routes-wan-route-error", error instanceof Error ? error.message : "The route could not be deleted.");
  }
}

async function deleteWanNatRuleFromMenu(row, csrf) {
  clearCaMessage("routes-wan-nat-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete NAT rule ${data.name}?`,
    message: "This removes the NAT rule from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete NAT rule",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postWanAction(`/routes-wan/nat-rules/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showWanMessage("routes-wan-nat-error", error instanceof Error ? error.message : "The NAT rule could not be deleted.");
  }
}

async function deleteWanPolicyFromMenu(row, csrf) {
  clearCaMessage("routes-wan-policy-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name}?`,
    message: "This removes the WAN policy from Atlaso desired state and clears it from assigned routes. It will not touch the appliance until global appliance apply runs.",
    label: "Delete policy",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postWanAction(`/routes-wan/policies/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showWanMessage("routes-wan-policy-error", error instanceof Error ? error.message : "The WAN policy could not be deleted.");
  }
}

async function deleteWanRoutingRuleFromMenu(row, csrf) {
  clearCaMessage("routes-wan-routing-error");
  const data = row.getData();
  if (data.is_new || data.generated) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete routing rule ${data.name}?`,
    message: "This removes the routing permission from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete routing rule",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postWanAction(`/routes-wan/routing-rules/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showWanMessage("routes-wan-routing-error", error instanceof Error ? error.message : "The routing rule could not be deleted.");
  }
}

function initializeRoutesWanRoutingTable() {
  const tableElement = document.getElementById("routes-wan-routing-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showWanMessage("routes-wan-routing-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const targets = JSON.parse(tableElement.dataset.targetOptions || "[]");
  const targetValues = Object.fromEntries(targets.map((target) => [target.name, target.label]));
  const defaultSource = targets[0]?.name || "";
  const defaultDestination = targets.find((target) => target.name !== defaultSource)?.name || "";
  const generatedRows = JSON.parse(tableElement.dataset.generatedRules || "[]");
  const explicitRows = JSON.parse(tableElement.dataset.rules || "[]").map((row) => ({ ...row, kind: "explicit access rule" }));
  const generatedWithKind = generatedRows.map((row) => ({ ...row, kind: "auto route-role rule" }));
  const rows = [...generatedWithKind, ...explicitRows, newWanRoutingRuleRow(defaultSource, defaultDestination)];
  try {
    const atlasoGridOptions13 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No routing permissions configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete routing rule",
          action: (_event, row) => deleteWanRoutingRuleFromMenu(row, csrf),
          disabled: (component) => component.getData().is_new || component.getData().generated,
        },
      ],
      columns: lockNewRecordColumns([
        {
          title: "Name",
          field: "name",
          editor: "input",
          editable: (cell) => !cell.getRow().getData().generated,
          formatter: (cell) => dnsAddRowHintFormatter(cell, "+ Add explicit access rule"),
          minWidth: 170,
          cellEdited: (cell) => autoSaveWanRoutingRule(cell, csrf),
        },
        {
          title: "Type",
          field: "kind",
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.generated) {
              return '<span class="status-pill good">auto route-role</span>';
            }
            if (data.is_new) {
              return '<span class="status-pill warn">new explicit</span>';
            }
            return '<span class="status-pill muted">explicit access</span>';
          },
          width: 140,
          headerSort: false,
        },
        {
          title: "Source",
          field: "source_interface",
          editor: "list",
          editable: (cell) => !cell.getRow().getData().generated,
          editorParams: { values: targetValues },
          formatter: (cell) => escapeHtml(targetValues[cell.getValue()] || cell.getValue() || "choose source..."),
          minWidth: 220,
          cellEdited: (cell) => autoSaveWanRoutingRule(cell, csrf),
        },
        {
          title: "Destination",
          field: "destination_interface",
          editor: "list",
          editable: (cell) => !cell.getRow().getData().generated,
          editorParams: { values: targetValues },
          formatter: (cell) => escapeHtml(targetValues[cell.getValue()] || cell.getValue() || "choose destination..."),
          minWidth: 220,
          cellEdited: (cell) => autoSaveWanRoutingRule(cell, csrf),
        },
        {
          title: "Priority",
          field: "priority",
          editor: "number",
          editable: (cell) => !cell.getRow().getData().generated,
          width: 100,
          cellEdited: (cell) => autoSaveWanRoutingRule(cell, csrf),
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          editable: (cell) => !cell.getRow().getData().generated,
          hozAlign: "center",
          width: 100,
          headerSort: false,
          cellEdited: (cell) => autoSaveWanRoutingRule(cell, csrf),
        },
        {
          title: "Description",
          field: "description",
          editor: "input",
          editable: (cell) => !cell.getRow().getData().generated,
          minWidth: 190,
          cellEdited: (cell) => autoSaveWanRoutingRule(cell, csrf),
        },
      ], "name"),
      rowFormatter: (row) => {
        const data = row.getData();
        markNewRecordRow(row, "name");
        row.getElement().classList.toggle("readonly-row", Boolean(data.generated));
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions13,
    }).table;
  } catch (error) {
    showWanMessage("routes-wan-routing-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeRoutesWanNatTable() {
  const tableElement = document.getElementById("routes-wan-nat-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showWanMessage("routes-wan-nat-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const targets = JSON.parse(tableElement.dataset.natTargetOptions || "[]");
  const targetValues = Object.fromEntries(targets.map((target) => [target.name, target.label]));
  const defaultTarget = targets[0]?.name || "";
  const rows = [...JSON.parse(tableElement.dataset.natRules || "[]"), newWanNatRuleRow(defaultTarget)];
  try {
    const atlasoGridOptions14 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No NAT rules configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete NAT rule",
          action: (_event, row) => deleteWanNatRuleFromMenu(row, csrf),
          disabled: (component) => component.getData().is_new,
        },
      ],
      columns: lockNewRecordColumns([
        {
          title: "Name",
          field: "name",
          editor: "input",
          formatter: (cell) => dnsAddRowHintFormatter(cell, "+ Add NAT rule here"),
          minWidth: 160,
          cellEdited: (cell) => autoSaveWanNatRule(cell, csrf),
        },
        {
          title: "Source",
          field: "source",
          editor: "input",
          formatter: (cell) => dnsAddRowHintFormatter(cell, "any or CIDR"),
          minWidth: 170,
          cellEdited: (cell) => autoSaveWanNatRule(cell, csrf),
        },
        {
          title: "Outbound",
          field: "outbound_interface",
          editor: "list",
          editorParams: { values: targetValues },
          formatter: (cell) => escapeHtml(targetValues[cell.getValue()] || cell.getValue() || "choose interface..."),
          minWidth: 230,
          cellEdited: (cell) => autoSaveWanNatRule(cell, csrf),
        },
        {
          title: "Masq",
          field: "masquerade",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          hozAlign: "center",
          width: 90,
          headerSort: false,
          cellEdited: (cell) => autoSaveWanNatRule(cell, csrf),
        },
        {
          title: "Priority",
          field: "priority",
          editor: "number",
          width: 100,
          cellEdited: (cell) => autoSaveWanNatRule(cell, csrf),
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          hozAlign: "center",
          width: 100,
          headerSort: false,
          cellEdited: (cell) => autoSaveWanNatRule(cell, csrf),
        },
        { title: "Description", field: "description", editor: "input", minWidth: 180, cellEdited: (cell) => autoSaveWanNatRule(cell, csrf) },
      ], "name"),
      rowFormatter: (row) => {
        markNewRecordRow(row, "name");
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions14,
    }).table;
  } catch (error) {
    showWanMessage("routes-wan-nat-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeRoutesWanRoutesTable() {
  const tableElement = document.getElementById("routes-wan-routes-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showWanMessage("routes-wan-route-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const targets = JSON.parse(tableElement.dataset.targetOptions || "[]");
  const targetValues = Object.fromEntries(targets.map((target) => [target.name, target.label]));
  const policyOptions = JSON.parse(tableElement.dataset.policyOptions || "[]");
  const policyValues = wanPolicyValues(policyOptions);
  const defaultTarget = targets[0]?.name || "";
  const rows = [...JSON.parse(tableElement.dataset.routes || "[]"), newWanRouteRow(defaultTarget)];
  try {
    const atlasoGridOptions15 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No routes configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete route",
          action: (_event, row) => deleteWanRouteFromMenu(row, csrf),
          disabled: (component) => component.getData().is_new,
        },
      ],
      columns: lockNewRecordColumns([
        {
          title: "Destination",
          field: "destination_cidr",
          editor: "input",
          formatter: (cell) => dnsAddRowHintFormatter(cell, "+ Add route here"),
          minWidth: 160,
          cellEdited: (cell) => autoSaveWanRoute(cell, csrf),
        },
        {
          title: "Gateway",
          field: "gateway",
          editor: "input",
          formatter: (cell) => dnsAddRowHintFormatter(cell, "direct"),
          minWidth: 135,
          cellEdited: (cell) => autoSaveWanRoute(cell, csrf),
        },
        {
          title: "Interface",
          field: "interface_name",
          editor: "list",
          editorParams: { values: targetValues },
          formatter: (cell) => escapeHtml(targetValues[cell.getValue()] || cell.getValue() || "choose target..."),
          minWidth: 230,
          cellEdited: (cell) => autoSaveWanRoute(cell, csrf),
        },
        {
          title: "WAN Policy",
          field: "wan_policy_id",
          editor: "list",
          editorParams: { values: policyValues },
          formatter: (cell) => wanPolicyFormatter(cell, policyValues),
          minWidth: 150,
          cellEdited: (cell) => autoSaveWanRoute(cell, csrf),
        },
        {
          title: "Metric",
          field: "metric",
          editor: "number",
          width: 90,
          cellEdited: (cell) => autoSaveWanRoute(cell, csrf),
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          hozAlign: "center",
          width: 100,
          headerSort: false,
          cellEdited: (cell) => autoSaveWanRoute(cell, csrf),
        },
      ], "destination_cidr"),
      rowFormatter: (row) => {
        markNewRecordRow(row, "destination_cidr");
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions15,
    }).table;
  } catch (error) {
    showWanMessage("routes-wan-route-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeRoutesWanPoliciesTable() {
  const tableElement = document.getElementById("routes-wan-policies-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showWanMessage("routes-wan-policy-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const rows = [...JSON.parse(tableElement.dataset.policies || "[]"), newWanPolicyRow()];
  try {
    const atlasoGridOptions16 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No WAN policies configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete policy",
          action: (_event, row) => deleteWanPolicyFromMenu(row, csrf),
          disabled: (component) => component.getData().is_new,
        },
      ],
      columns: lockNewRecordColumns([
        {
          title: "Name",
          field: "name",
          editor: "input",
          formatter: (cell) => dnsAddRowHintFormatter(cell, "+ Add policy here"),
          minWidth: 145,
          cellEdited: (cell) => autoSaveWanPolicy(cell, csrf),
        },
        { title: "Latency ms", field: "latency_ms", editor: "number", width: 115, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        { title: "Jitter ms", field: "jitter_ms", editor: "number", width: 105, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        { title: "Loss %", field: "packet_loss_percent", editor: "number", width: 95, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        { title: "Bandwidth Mbps", field: "bandwidth_mbit", editor: "number", width: 145, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        { title: "Corrupt %", field: "corrupt_percent", editor: "number", width: 105, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        { title: "Duplicate %", field: "duplicate_percent", editor: "number", width: 120, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        { title: "Reorder %", field: "reorder_percent", editor: "number", width: 110, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          hozAlign: "center",
          width: 100,
          headerSort: false,
          cellEdited: (cell) => autoSaveWanPolicy(cell, csrf),
        },
        { title: "Description", field: "description", editor: "input", minWidth: 180, cellEdited: (cell) => autoSaveWanPolicy(cell, csrf) },
      ], "name"),
      rowFormatter: (row) => {
        markNewRecordRow(row, "name");
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions16,
    }).table;
  } catch (error) {
    showWanMessage("routes-wan-policy-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function showNetworkMessage(elementId, message) {
  showCaMessage(elementId, message, "error");
}

async function postNetworkAction(url, data, csrf, options = {}) {
  const reload = options.reload ?? true;
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (
      key === "id" ||
      key === "is_new" ||
      key === "name" ||
      key === "mac_address" ||
      key === "driver" ||
      key === "speed" ||
      key === "host_ip_cidr" ||
      key === "host_ipv6_cidr" ||
      key === "host_mtu" ||
      key === "host_admin_state" ||
      key === "oper_state" ||
      key === "vlan_count" ||
      key === "parent_missing" ||
      key === "admin_up"
    ) {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set("enabled", "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }
  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    const plainText = text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    throw new Error(text.match(/VLAN .* already exists[^<]*/)?.[0] || plainText || "The network desired state could not be saved.");
  }
  if (reload) {
    window.location.reload();
  }
}

function newVlanInterfaceRow(defaultParent = "eth1", defaultMtu = 1500) {
  return {
    id: "__new__",
    name: "",
    parent_interface: defaultParent,
    vlan_id: "",
    ip_cidr: "",
    ipv6_cidr: "",
    mtu: defaultMtu,
    role: "access",
    enabled: true,
    is_new: true,
    is_activated: false,
    requires_activation: true,
  };
}

function physicalLinkTypeFormatter(cell, modeOptions) {
  const data = cell.getRow().getData();
  const value = cell.getValue();
  const label = modeOptions[value] || value;
  const vlanCount = Number(data.vlan_count || 0);
  if (value === "trunk" && vlanCount > 0) {
    return `${escapeHtml(label)} <span class="cell-note">locked by ${vlanCount} VLAN${vlanCount === 1 ? "" : "s"}</span>`;
  }
  return escapeHtml(label);
}

function networkStateIcon(state, label) {
  const normalized = String(state || "").toLowerCase();
  const displayLabel = label || normalized || "unknown";
  let className = "unknown";
  let symbol = "?";
  if (normalized === "up" || normalized === "enabled" || normalized === "true") {
    className = "up";
    symbol = "&#8593;";
  } else if (normalized === "down" || normalized === "disabled" || normalized === "false") {
    className = "down";
    symbol = "&#8595;";
  } else if (normalized === "missing") {
    className = "missing";
    symbol = "!";
  }
  const title = displayLabel === "missing" ? "missing from host inventory" : displayLabel;
  return `<span class="network-state-icon ${className}" title="${escapeHtml(title)}"><span class="state-symbol" aria-hidden="true">${symbol}</span><span class="state-label">${escapeHtml(displayLabel)}</span></span>`;
}

function isValidIpv4Address(value) {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    const numberValue = Number(part);
    return numberValue >= 0 && numberValue <= 255;
  });
}

function ipv4GatewayIsOnLink(gateway, cidr) {
  if (!isValidIpv4Address(gateway) || !isValidCidr(cidr, "ipv4")) return false;
  const [address, prefixText] = String(cidr).split("/");
  const toNumber = (value) => value.split(".").reduce((result, part) => ((result << 8) | Number(part)) >>> 0, 0);
  const prefix = Number(prefixText);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (toNumber(gateway) & mask) === (toNumber(address) & mask) && gateway !== address;
}

function isValidIpv6Address(value) {
  const address = String(value || "");
  if (!address.includes(":") || /[\s[\]]/.test(address)) {
    return false;
  }
  try {
    new URL(`http://[${address}]/`);
    return true;
  } catch (_error) {
    return false;
  }
}

function isValidCidr(value, family) {
  const cidr = String(value || "").trim();
  if (!cidr) {
    return true;
  }
  const parts = cidr.split("/");
  if (parts.length !== 2 || !parts[0] || !/^\d+$/.test(parts[1])) {
    return false;
  }
  const prefix = Number(parts[1]);
  if (family === "ipv4") {
    return prefix >= 0 && prefix <= 32 && isValidIpv4Address(parts[0]);
  }
  return prefix >= 0 && prefix <= 128 && isValidIpv6Address(parts[0]);
}

function showCidrInputError(cell, family) {
  const table = typeof cell.getTable === "function" ? cell.getTable() : null;
  const tableElement = table?.element;
  const target = tableElement?.id === "vlan-interfaces-table" ? "vlan-interface-error" : "physical-interface-error";
  showNetworkMessage(target, family === "ipv4" ? "Enter a valid IPv4 CIDR such as 192.168.50.1/24." : "Enter a valid IPv6 CIDR such as fd00:50::1/64.");
}

function cidrInputEditor(cell, onRendered, success, cancel, editorParams = {}) {
  const family = editorParams.family || "ipv4";
  const input = document.createElement("input");
  input.type = "text";
  input.value = cell.getValue() || "";
  input.placeholder = editorParams.placeholder || (family === "ipv4" ? "192.168.50.1/24" : "fd00:50::1/64");
  input.autocomplete = "off";
  input.spellcheck = false;
  input.inputMode = family === "ipv4" ? "decimal" : "text";
  input.setAttribute("aria-label", family === "ipv4" ? "IPv4 CIDR" : "IPv6 CIDR");
  const disallowed = family === "ipv4" ? /[^0-9./]/g : /[^0-9A-Fa-f:./]/g;

  const updateValidity = () => {
    const nextValue = input.value.replace(disallowed, "");
    if (nextValue !== input.value) {
      input.value = nextValue;
    }
    input.classList.toggle("invalid-cidr-input", !isValidCidr(input.value, family));
  };

  const submit = () => {
    const value = input.value.trim();
    if (!isValidCidr(value, family)) {
      input.classList.add("invalid-cidr-input");
      showCidrInputError(cell, family);
      return false;
    }
    success(value);
    return true;
  };

  input.addEventListener("input", updateValidity);
  input.addEventListener("change", submit);
  input.addEventListener("blur", () => {
    if (!submit()) {
      cancel();
    }
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      submit();
    } else if (event.key === "Escape") {
      cancel();
    }
  });

  onRendered(() => {
    input.focus();
    input.select();
    updateValidity();
  });
  return input;
}

function adminStateFormatter(cell) {
  return networkStateIcon(cell.getValue() ? "up" : "down", cell.getValue() ? "up" : "down");
}

function operStateFormatter(cell) {
  const value = cell.getValue() || "unknown";
  return networkStateIcon(value, value);
}

function vlanEnabledFormatter(cell) {
  const data = cell.getRow().getData();
  if (data.parent_missing) {
    return '<span class="network-state-icon missing" title="Parent NIC is missing; this VLAN is disabled until moved to an available trunk parent."><span class="state-symbol" aria-hidden="true">!</span><span class="state-label">missing</span></span>';
  }
  return adminStateFormatter(cell);
}

function hasRequiredVlanFields(data) {
  return Boolean((data.parent_interface || "").trim() && String(data.vlan_id || "").trim() && (String(data.ip_cidr || "").trim() || String(data.ipv6_cidr || "").trim()));
}

function editNewRowCell(cell, fieldName) {
  const row = cell.getRow();
  if (!row.getData().is_new) {
    return;
  }
  const target = row.getCell(fieldName);
  if (target && typeof target.edit === "function") {
    target.edit();
  }
}

async function activateNewVlanRow(cell) {
  const row = cell.getRow();
  const data = row.getData();
  if (!data.is_new) {
    return;
  }
  data.is_activated = true;
  row.reformat();
  row.getElement().classList.remove("new-record-row-pending");
  const vlanIdCell = row.getCell("vlan_id");
  if (vlanIdCell && typeof vlanIdCell.edit === "function") {
    vlanIdCell.edit();
  }
}

function physicalRoleFormatter(cell) {
  if (cell.getRow().getData().mode === "trunk") {
    return "";
  }
  return escapeHtml(cell.getValue());
}

async function autoSaveVlanParent(cell, csrf, parentMtus) {
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new) {
    const parentMtu = Number(parentMtus[data.parent_interface]);
    if (Number.isInteger(parentMtu) && parentMtu > 0) {
      await row.update({ mtu: parentMtu });
    }
  }
  await updateVlanDerivedName(row);
  await autoSaveVlanInterface(cell, csrf);
}

function vlanDerivedName(data) {
  const parent = String(data.parent_interface || "").trim();
  const vlanId = String(data.vlan_id || "").trim();
  return parent && vlanId ? `${parent}.${vlanId}` : "";
}

async function updateVlanDerivedName(row) {
  const name = vlanDerivedName(row.getData());
  if (row.getData().name !== name) {
    await row.update({ name });
  }
}

async function autoSaveVlanId(cell, csrf) {
  await updateVlanDerivedName(cell.getRow());
  await autoSaveVlanInterface(cell, csrf);
}

function roleValues(options) {
  return Object.fromEntries(options.map((item) => [item, item]));
}

function labeledValues(options, labels) {
  return Object.fromEntries(options.map((item) => [item, labels[item] || item]));
}

function initializeRefreshedSideStack(sideStack) {
  initializeTagEditors(sideStack);
  initializeServiceBindEditors(sideStack);
  initializeSwitchFields(sideStack);
  initializeAutosaveForms(sideStack);
  initializeCaSettings(sideStack);
  initializeKmsSettings(sideStack);
  initializeNtpSettings(sideStack);
  initializeOidcProviderSettings(sideStack);
  initializeFirewallSettings(sideStack);
  initializeDnsSettings(sideStack);
  initializeVcfBackupSettings(sideStack);
  initializeVcfRegistrySettings(sideStack);
  initializeVcfDepotSettings(sideStack);
  initializeLdapSettingsStatus(sideStack);
}

async function refreshNetworkSideStack() {
  const currentSideStack = document.querySelector("aside.side-stack");
  if (!(currentSideStack instanceof HTMLElement)) {
    return;
  }
  const response = await fetch(window.location.href, {
    credentials: "same-origin",
    headers: { "X-Requested-With": "AtlasoSideRefresh" },
  });
  if (!response.ok) {
    return;
  }
  const html = await response.text();
  const nextDocument = new DOMParser().parseFromString(html, "text/html");
  const nextSideStack = nextDocument.querySelector("aside.side-stack");
  if (nextSideStack instanceof HTMLElement) {
    currentSideStack.replaceWith(nextSideStack);
    initializeRefreshedSideStack(nextSideStack);
    highlightConfigPreviews(nextSideStack);
  }
}

async function autoSavePhysicalInterface(cell, csrf) {
  clearCaMessage("physical-interface-error");
  const row = cell.getRow();
  const data = row.getData();
  data.admin_state = data.admin_up ? "up" : "down";
  if (data.ipv4_method === "dhcp") {
    data.ip_cidr = "";
    data.gateway = "";
  }
  if (data.role !== "management" || data.mode === "trunk") data.gateway = "";
  if (!data.ipv6_enabled) {
    data.ipv6_cidr = "";
    data.ipv6_gateway = "";
  }
  if (data.role !== "management" || data.mode === "trunk" || !data.ipv6_cidr) data.ipv6_gateway = "";
  try {
    await postNetworkAction(`/physical-interfaces/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showNetworkMessage("physical-interface-error", error instanceof Error ? error.message : "The physical interface could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function savePhysicalInterfaceRow(row, csrf, successMessage = "Saved") {
  clearCaMessage("physical-interface-error");
  const data = row.getData();
  data.admin_state = data.admin_up ? "up" : "down";
  if (data.ipv4_method === "dhcp") {
    data.ip_cidr = "";
    data.gateway = "";
  }
  if (data.role !== "management" || data.mode === "trunk") data.gateway = "";
  if (!data.ipv6_enabled) {
    data.ipv6_cidr = "";
    data.ipv6_gateway = "";
  }
  if (data.role !== "management" || data.mode === "trunk" || !data.ipv6_cidr) data.ipv6_gateway = "";
  try {
    await postNetworkAction(`/physical-interfaces/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus(successMessage);
    await refreshNetworkSideStack();
  } catch (error) {
    showNetworkMessage("physical-interface-error", error instanceof Error ? error.message : "The physical interface could not be saved.");
    throw error;
  }
}

async function togglePhysicalInterfaceFromMenu(row, csrf) {
  const data = row.getData();
  const nextAdminUp = !Boolean(data.admin_up);
  const actionLabel = nextAdminUp ? "Enable interface" : "Disable interface";
  if (data.role === "management" && !nextAdminUp) {
    showNetworkMessage("physical-interface-error", "The management interface must stay enabled.");
    return;
  }
  const confirmed = await requestConfirmation({
    title: `${actionLabel} ${data.name}?`,
    message: `This changes ${data.name} desired admin state to ${nextAdminUp ? "up" : "down"}. It will not touch the appliance until global appliance apply runs.`,
    label: actionLabel,
  });
  if (!confirmed) {
    return;
  }
  const previousAdminUp = data.admin_up;
  try {
    await row.update({ admin_up: nextAdminUp, admin_state: nextAdminUp ? "up" : "down" });
    await savePhysicalInterfaceRow(row, csrf, nextAdminUp ? "Enabled" : "Disabled");
  } catch (_error) {
    await row.update({ admin_up: previousAdminUp, admin_state: previousAdminUp ? "up" : "down" });
  }
}

async function convertManagementDhcpInterfaceToStatic(row, csrf) {
  const data = row.getData();
  const observedIpv4 = String(data.host_ip_cidr || "").trim();
  const observedIpv6 = String(data.host_ipv6_cidr || "").trim();
  if (data.role !== "management" || data.ipv4_method !== "dhcp") {
    showNetworkMessage("physical-interface-error", "Only a management interface using IPv4 DHCP can be converted to static addressing.");
    return;
  }
  if (!observedIpv4 && !observedIpv6) {
    showNetworkMessage("physical-interface-error", `${data.name} has no observed DHCP IPv4 or IPv6 CIDR to copy into desired state.`);
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Convert ${data.name} DHCP lease to static?`,
    message: `This copies the observed DHCP address${observedIpv6 ? "es" : ""} into desired IPv4/IPv6 CIDR fields and changes IPv4 method to static. If DHCP-provided DNS was being used, Atlaso also preserves it as static resolver or DNS forwarder desired state. The appliance is not changed until global appliance apply runs.`,
    label: "Convert to static",
  });
  if (!confirmed) {
    return;
  }
  const previous = {
    ipv4_method: data.ipv4_method,
    ip_cidr: data.ip_cidr,
    ipv6_cidr: data.ipv6_cidr,
    ipv6_gateway: data.ipv6_gateway,
    ipv6_enabled: data.ipv6_enabled,
  };
  try {
    await row.update({
      ipv4_method: "static",
      ip_cidr: observedIpv4 || data.ip_cidr || "",
      ipv6_cidr: observedIpv6 || data.ipv6_cidr || "",
      ipv6_gateway: "",
      ipv6_enabled: Boolean(observedIpv6 || data.ipv6_enabled),
    });
    await savePhysicalInterfaceRow(row, csrf, "Converted");
  } catch (_error) {
    await row.update(previous);
  }
}

async function forgetPhysicalInterfaceFromMenu(row, csrf) {
  clearCaMessage("physical-interface-error");
  const data = row.getData();
  if (data.oper_state !== "missing") {
    showNetworkMessage("physical-interface-error", "Only interfaces already marked missing from host inventory can be forgotten.");
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Forget ${data.name}?`,
    message: "This removes the missing interface row from Atlaso inventory and deletes disabled VLAN rows tied to it. It does not touch the appliance until global appliance apply runs.",
    label: "Forget interface",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postNetworkAction(`/physical-interfaces/${data.id}/forget`, {}, csrf);
  } catch (error) {
    showNetworkMessage("physical-interface-error", error instanceof Error ? error.message : "The missing interface could not be forgotten.");
  }
}

async function autoSaveVlanInterface(cell, csrf) {
  clearCaMessage("vlan-interface-error");
  const row = cell.getRow();
  const data = row.getData();
  if (data.parent_missing) {
    row.update({ enabled: false });
    showNetworkMessage("vlan-interface-error", `${data.parent_interface} is missing from host inventory. Move this VLAN to an available trunk parent before enabling it.`);
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
    return;
  }
  if (data.is_new) {
    if (!hasRequiredVlanFields(data)) {
      return;
    }
    try {
      await postNetworkAction("/vlan-interfaces", data, csrf, { reload: false });
      showTransientGridStatus("Added");
      window.location.reload();
    } catch (error) {
      showNetworkMessage("vlan-interface-error", error instanceof Error ? error.message : "The VLAN interface could not be added.");
      if (typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
    return;
  }
  try {
    await postNetworkAction(`/vlan-interfaces/${data.id}/edit`, data, csrf, { reload: false });
    showTransientGridStatus("Saved");
    await refreshNetworkSideStack();
  } catch (error) {
    showNetworkMessage("vlan-interface-error", error instanceof Error ? error.message : "The VLAN interface could not be saved.");
    if (typeof cell.restoreOldValue === "function") {
      cell.restoreOldValue();
    }
  }
}

async function deleteVlanInterfaceFromMenu(row, csrf) {
  clearCaMessage("vlan-interface-error");
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name || `${data.parent_interface}.${data.vlan_id}`}?`,
    message: "This removes the VLAN interface from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
    label: "Delete VLAN",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postNetworkAction(`/vlan-interfaces/${data.id}/delete`, {}, csrf);
  } catch (error) {
    showNetworkMessage("vlan-interface-error", error instanceof Error ? error.message : "The VLAN interface could not be deleted.");
  }
}

function initializePhysicalInterfacesTable() {
  const tableElement = document.getElementById("physical-interfaces-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showNetworkMessage("physical-interface-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const roleOptions = roleValues(JSON.parse(tableElement.dataset.roleOptions || "[]"));
  const ipv4MethodOptions = labeledValues(JSON.parse(tableElement.dataset.ipv4MethodOptions || "[]"), {
    static: "Static",
    dhcp: "DHCP",
  });
  const modeOptions = labeledValues(JSON.parse(tableElement.dataset.modeOptions || "[]"), {
    access: "Access (untagged)",
    trunk: "Trunk (tagged VLANs)",
    unused: "Unused",
  });
  const rows = JSON.parse(tableElement.dataset.interfaces || "[]");
  try {
    const atlasoGridOptions17 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No physical interfaces discovered.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: (component) => (component.getData().admin_up ? "Disable interface" : "Enable interface"),
          disabled: (component) => {
            const data = component.getData();
            return data.role === "management" && data.admin_up;
          },
          action: (event, row) => togglePhysicalInterfaceFromMenu(row, csrf),
        },
        {
          label: "Convert DHCP lease to static",
          disabled: (component) => {
            const data = component.getData();
            return data.role !== "management" || data.ipv4_method !== "dhcp" || (!data.host_ip_cidr && !data.host_ipv6_cidr);
          },
          action: (event, row) => convertManagementDhcpInterfaceToStatic(row, csrf),
        },
        {
          label: "Forget missing interface",
          disabled: (component) => component.getData().oper_state !== "missing",
          action: (event, row) => forgetPhysicalInterfaceFromMenu(row, csrf),
        },
      ],
      columns: [
        { title: "Name", field: "name", width: 100, headerSort: false },
        { title: "MAC", field: "mac_address", minWidth: 170, headerSort: false },
        { title: "Driver", field: "driver", width: 110 },
        { title: "Speed", field: "speed", width: 110 },
        { title: "Observed IPv4", field: "host_ip_cidr", minWidth: 150, headerSort: false },
        { title: "Observed IPv6", field: "host_ipv6_cidr", minWidth: 180, headerSort: false },
        {
          title: "IPv4 Method",
          field: "ipv4_method",
          editor: "list",
          editorParams: { values: ipv4MethodOptions },
          editable: (cell) => cell.getRow().getData().role === "management",
          formatter: (cell) => escapeHtml(ipv4MethodOptions[cell.getValue()] || cell.getValue() || "Static"),
          width: 130,
          cellEdited: async (cell) => {
            const row = cell.getRow();
            const data = row.getData();
            if (data.ipv4_method === "dhcp" && data.role !== "management") {
              showNetworkMessage("physical-interface-error", "IPv4 DHCP is available only for the management interface.");
              if (typeof cell.restoreOldValue === "function") {
                cell.restoreOldValue();
              }
              return;
            }
            if (data.ipv4_method === "dhcp") {
              await row.update({ ip_cidr: "", gateway: "" });
            }
            await autoSavePhysicalInterface(cell, csrf);
          },
        },
        {
          title: "IPv4 CIDR",
          field: "ip_cidr",
          editor: (cell, onRendered, success, cancel, editorParams) => {
            const data = cell.getRow().getData();
            if (data.mode === "trunk" || data.ipv4_method === "dhcp") {
              cancel();
              return document.createElement("span");
            }
            return cidrInputEditor(cell, onRendered, success, cancel, editorParams);
          },
          editorParams: { family: "ipv4", placeholder: "192.168.50.1/24" },
          editable: (cell) => cell.getRow().getData().mode !== "trunk",
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.mode === "trunk") {
              return "";
            }
            if (data.ipv4_method === "dhcp") {
              return '<span class="status-pill muted">DHCP</span>';
            }
            return dnsAddRowHintFormatter(cell, "192.168.50.1/24");
          },
          minWidth: 160,
          cellEdited: async (cell) => {
            const row = cell.getRow();
            const data = row.getData();
            if (data.gateway && !ipv4GatewayIsOnLink(data.gateway, data.ip_cidr)) {
              await row.update({ gateway: "" });
            }
            await autoSavePhysicalInterface(cell, csrf);
          },
        },
        {
          title: "IPv4 Gateway",
          field: "gateway",
          editor: "input",
          editable: (cell) => {
            const data = cell.getRow().getData();
            return data.role === "management" && data.mode !== "trunk" && data.ipv4_method === "static";
          },
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.role !== "management" || data.mode === "trunk" || data.ipv4_method !== "static") return "";
            return dnsAddRowHintFormatter(cell, "192.168.1.1");
          },
          headerTooltip: "Default IPv4 gateway for management traffic only. It must be on-link for the management CIDR and is installed in the main table plus management route table 100.",
          minWidth: 145,
          cellEdited: (cell) => autoSavePhysicalInterface(cell, csrf),
        },
        {
          title: "IPv6",
          field: "ipv6_enabled",
          formatter: "tickCross",
          editor: "tickCross",
          headerTooltip: "Enables IPv6 desired state. Enabled with a blank CIDR uses router advertisements and SLAAC; disabled blocks RA and IPv6 link-local addressing.",
          editable: (cell) => cell.getRow().getData().mode !== "trunk",
          hozAlign: "center",
          width: 85,
          cellEdited: async (cell) => {
            if (!cell.getValue()) {
              await cell.getRow().update({ ipv6_cidr: "", ipv6_gateway: "" });
            }
            await autoSavePhysicalInterface(cell, csrf);
            cell.getRow().reformat();
          },
        },
        {
          title: "IPv6 CIDR",
          field: "ipv6_cidr",
          editor: cidrInputEditor,
          editorParams: { family: "ipv6", placeholder: "fd00:50::1/64" },
          editable: (cell) => cell.getRow().getData().mode !== "trunk" && Boolean(cell.getRow().getData().ipv6_enabled),
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.mode === "trunk" || !data.ipv6_enabled) {
              return "";
            }
            if (!cell.getValue()) {
              return '<span class="status-pill muted">RA/SLAAC</span>';
            }
            return dnsAddRowHintFormatter(cell, "fd00:50::1/64");
          },
          minWidth: 180,
          cellEdited: async (cell) => {
            if (!cell.getValue()) {
              await cell.getRow().update({ ipv6_gateway: "" });
            }
            await autoSavePhysicalInterface(cell, csrf);
          },
        },
        {
          title: "IPv6 Gateway",
          field: "ipv6_gateway",
          editor: "input",
          editable: (cell) => {
            const data = cell.getRow().getData();
            return data.role === "management" && data.mode !== "trunk" && Boolean(data.ipv6_enabled && data.ipv6_cidr);
          },
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.role !== "management" || data.mode === "trunk" || !data.ipv6_enabled || !data.ipv6_cidr) return "";
            return dnsAddRowHintFormatter(cell, "fe80::1");
          },
          headerTooltip: "Optional static IPv6 gateway for management traffic. It must be link-local or on-link and is installed in the main table plus management route table 100.",
          minWidth: 170,
          cellEdited: (cell) => autoSavePhysicalInterface(cell, csrf),
        },
        {
          title: "Role",
          field: "role",
          editor: "list",
          editorParams: { values: roleOptions },
          editable: (cell) => cell.getRow().getData().mode !== "trunk",
          formatter: physicalRoleFormatter,
          width: 125,
          cellEdited: async (cell) => {
            if (cell.getValue() !== "management") {
              await cell.getRow().update({ gateway: "", ipv6_gateway: "" });
            }
            await autoSavePhysicalInterface(cell, csrf);
          },
        },
        {
          title: "Link Type",
          field: "mode",
          editor: "list",
          editorParams: { values: modeOptions },
          editable: (cell) => Number(cell.getRow().getData().vlan_count || 0) === 0,
          formatter: (cell) => physicalLinkTypeFormatter(cell, modeOptions),
          cellClick: (event, cell) => {
            const data = cell.getRow().getData();
            const vlanCount = Number(data.vlan_count || 0);
            if (vlanCount > 0) {
              showNetworkMessage(
                "physical-interface-error",
                `${data.name} is the parent of ${vlanCount} VLAN interface${vlanCount === 1 ? "" : "s"}. Move or delete those VLANs before changing the link type.`,
              );
            }
          },
          minWidth: 220,
          cellEdited: async (cell) => {
            if (cell.getValue() === "trunk") {
              await cell.getRow().update({ role: "unused", ipv4_method: "static", ip_cidr: "", gateway: "", ipv6_enabled: false, ipv6_cidr: "", ipv6_gateway: "" });
            }
            await autoSavePhysicalInterface(cell, csrf);
            cell.getRow().reformat();
          },
        },
        {
          title: "MTU",
          field: "mtu",
          editor: "number",
          width: 90,
          cellEdited: (cell) => autoSavePhysicalInterface(cell, csrf),
        },
        {
          title: "Admin Up",
          field: "admin_up",
          formatter: adminStateFormatter,
          editor: "tickCross",
          editable: (cell) => {
            const data = cell.getRow().getData();
            return data.role !== "management" || !data.admin_up;
          },
          hozAlign: "center",
          width: 110,
          headerSort: false,
          cellEdited: (cell) => autoSavePhysicalInterface(cell, csrf),
        },
        { title: "Oper", field: "oper_state", formatter: operStateFormatter, width: 105, headerSort: false },
        { title: "Source", field: "inventory_source", width: 100, headerSort: false },
      ],
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions17,
    }).table;
  } catch (error) {
    showNetworkMessage("physical-interface-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function setOidcGroupMappingMessage(message = "", state = "idle") {
  const status = document.getElementById("oidc-group-mapping-status");
  if (!(status instanceof HTMLElement)) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function showOidcGroupMappingError(message = "") {
  const element = document.getElementById("oidc-group-mapping-error");
  if (!(element instanceof HTMLElement)) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("hidden", !message);
}

async function postOidcGroupMappingAction(url, data, csrf, { expectJson = true } = {}) {
  const body = new FormData();
  body.set("csrf", csrf);
  Object.entries(data).forEach(([key, value]) => body.set(key, value ?? ""));
  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
    headers: { "X-Atlaso-Grid": "1" },
  });
  if (!response.ok) {
    let message = "";
    try {
      const payload = await response.json();
      message = String(payload.detail || "");
    } catch {
      message = (await response.text()).trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    }
    throw new Error(message || "The OIDC group mapping could not be saved.");
  }
  return expectJson ? response.json() : null;
}

function updateOidcProviderValidation(payload = {}) {
  const form = document.querySelector('form[action="/authentication/oidc/provider"]');
  const providerStatus = document.querySelector("[data-oidc-provider-status]");
  const validationPanel = document.querySelector("[data-oidc-provider-validation]");
  const validationStatus = document.querySelector("[data-oidc-provider-validation-status]");
  if (!(form instanceof HTMLFormElement) || !(validationPanel instanceof HTMLElement) || !(validationStatus instanceof HTMLElement)) return;
  const enabled = Boolean(payload.enabled);
  if (providerStatus instanceof HTMLElement) {
    providerStatus.textContent = enabled ? "enabled" : "disabled";
    providerStatus.className = `status-pill ${enabled ? "good" : "muted"}`;
  }
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  const urlFields = {
    issuer: "issuer",
    discovery: "discovery_url",
    jwks: "jwks_uri",
    authorization: "authorization_endpoint",
    token: "token_endpoint",
    userinfo: "userinfo_endpoint",
    logout: "end_session_endpoint",
  };
  Object.entries(urlFields).forEach(([label, field]) => {
    const value = payload.urls?.[field];
    if (typeof value !== "string") return;
    const code = document.querySelector(`[data-oidc-url="${label}"]`);
    const copy = document.querySelector(`[data-oidc-url-copy="${label}"]`);
    if (code instanceof HTMLElement) code.textContent = value;
    if (copy instanceof HTMLButtonElement) copy.dataset.copyValue = value;
  });
  validationStatus.textContent = errors.length ? "needs attention" : "valid";
  validationStatus.className = `status-pill ${errors.length ? "warn" : "good"}`;
  validationPanel.querySelector(".error-list")?.remove();
  if (errors.length) {
    const list = document.createElement("div");
    list.className = "error-list";
    list.setAttribute("role", "list");
    list.setAttribute("data-oidc-provider-validation-errors", "");
    errors.forEach((message) => {
      const item = document.createElement("div");
      item.setAttribute("role", "listitem");
      item.textContent = String(message);
      list.appendChild(item);
    });
    validationPanel.appendChild(list);
  }
}

function initializeOidcProviderSettings(root = document) {
  const form = root.querySelector('form[action="/authentication/oidc/provider"]');
  if (!(form instanceof HTMLFormElement)) return;
  if (form.dataset.oidcProviderSettingsInitialized === "1") return;
  form.dataset.oidcProviderSettingsInitialized = "1";
  form.addEventListener("atlaso:autosave-success", (event) => updateOidcProviderValidation(event.detail || {}));
}

function initializeOidcGroupMappingsTable() {
  const tableElement = document.getElementById("oidc-group-mappings-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showOidcGroupMappingError("Tabulator did not load. Showing the read-only fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const roleOptions = JSON.parse(tableElement.dataset.roleOptions || "[]");
  const groupOptions = JSON.parse(tableElement.dataset.groupOptions || "[]");
  const clientOptions = JSON.parse(tableElement.dataset.clientOptions || "[]");
  const sourceLabels = {};
  roleOptions.forEach((role) => {
    sourceLabels[`role:${role}`] = `Local / ${role}`;
  });
  groupOptions.forEach((group) => {
    sourceLabels[`group:${group.id}`] = group.label;
  });
  const groupById = new Map(groupOptions.map((group) => [Number(group.id), group]));
  const clientById = new Map(clientOptions.map((client) => [Number(client.id), client]));
  const newRow = () => ({
    id: `__new__-${Date.now()}`,
    is_new: true,
    source_type: "",
    source_selection: "",
    source_name: "",
    organization_id: null,
    organization_name: "",
    oidc_client_id: null,
    oidc_client_name: "",
    external_group_name: "",
  });
  const rows = JSON.parse(tableElement.dataset.mappings || "[]").map((row) => ({
    ...row,
    is_new: false,
    source_selection: row.source_type === "local_role"
      ? `role:${row.local_role}`
      : `group:${row.ldap_group_id}`,
  }));
  rows.push(newRow());

  const compatibleClientValues = (data) => {
    const values = {
      "": data.source_type === "ldap_group" ? "Organization default" : "Local default",
    };
    clientOptions.forEach((client) => {
      const compatible = data.source_type === "local_role"
        ? client.organization_id === null
        : client.organization_id === null || Number(client.organization_id) === Number(data.organization_id);
      if (compatible) {
        values[String(client.id)] = `${client.name}${client.enabled ? "" : " (disabled)"}`;
      }
    });
    return values;
  };
  const sourceValues = Object.fromEntries(Object.entries(sourceLabels));

  let table;
  const setMappingCount = (total) => {
    const count = document.getElementById("oidc-group-mapping-count");
    if (!(count instanceof HTMLElement)) {
      return;
    }
    count.textContent = `${total} mapping${total === 1 ? "" : "s"}`;
  };
  const updateMappingCount = () => {
    if (table) {
      setMappingCount(table.getData().filter((row) => !row.is_new).length);
    }
  };
  const saveCell = async (cell) => {
    const row = cell.getRow();
    const data = row.getData();
    const wasNew = Boolean(data.is_new);
    showOidcGroupMappingError("");
    if (
      data.is_new
      && (
        !data.source_type
        || !data.source_selection
        || !String(data.external_group_name || "").trim()
      )
    ) {
      row.reformat();
      setOidcGroupMappingMessage(
        data.source_type
          ? "Complete the source and external group name to add this mapping."
          : "Select a mapping source to begin a new record.",
        "idle",
      );
      return;
    }
    setOidcGroupMappingMessage("Saving mapping…", "saving");
    try {
      const payload = wasNew
        ? await postOidcGroupMappingAction(
            "/authentication/oidc/group-mappings",
            {
              source_type: data.source_type,
              local_role: data.source_type === "local_role"
                ? String(data.source_selection).replace(/^role:/, "")
                : "",
              ldap_group_id: data.source_type === "ldap_group"
                ? String(data.source_selection).replace(/^group:/, "")
                : "",
              oidc_client_id: data.oidc_client_id || "",
              external_group_name: data.external_group_name,
            },
            csrf,
          )
        : await postOidcGroupMappingAction(
            `/authentication/oidc/group-mappings/${data.id}/edit`,
            {
              oidc_client_id: data.oidc_client_id || "",
              external_group_name: data.external_group_name,
            },
            csrf,
          );
      await row.update({
        ...payload,
        is_new: false,
        source_selection: payload.source_type === "local_role"
          ? `role:${payload.local_role}`
          : `group:${payload.ldap_group_id}`,
      });
      if (wasNew) {
        await table.addRow(newRow(), false);
      }
      row.reformat();
      updateMappingCount();
      setOidcGroupMappingMessage("Mapping saved.", "saved");
      showTransientGridStatus(wasNew ? "Added" : "Saved");
    } catch (error) {
      const message = error instanceof Error ? error.message : "The OIDC group mapping could not be saved.";
      showOidcGroupMappingError(message);
      setOidcGroupMappingMessage("Mapping was not saved. Correct the highlighted values and try again.", "error");
      if (!data.is_new && typeof cell.restoreOldValue === "function") {
        cell.restoreOldValue();
      }
    }
  };

  const deleteMapping = async (row) => {
    const data = row.getData();
    if (data.is_new) {
      return;
    }
    const confirmed = await requestConfirmation({
      title: `Delete mapping for ${data.source_name}?`,
      message: "This removes the explicit external group mapping immediately. New OIDC claims will no longer emit this value; no appliance service is changed.",
      label: "Delete group mapping",
    });
    if (!confirmed) {
      return;
    }
    showOidcGroupMappingError("");
    setOidcGroupMappingMessage("Deleting mapping…", "saving");
    try {
      await postOidcGroupMappingAction(
        `/authentication/oidc/group-mappings/${data.id}/delete`,
        {},
        csrf,
        { expectJson: false },
      );
      await row.delete();
      updateMappingCount();
      setOidcGroupMappingMessage("Mapping deleted.", "saved");
      showTransientGridStatus("Deleted");
    } catch (error) {
      showOidcGroupMappingError(error instanceof Error ? error.message : "The mapping could not be deleted.");
      setOidcGroupMappingMessage("Mapping was not deleted.", "error");
    }
  };

  try {
    const grid = window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      fallback,
      status: "#oidc-group-mapping-status",
      pattern: "direct-edit",
      emptyMessage: "No external group mappings configured.",
      rowActions: [
        {
          label: "Delete mapping",
          disabled: (component) => component.getData().is_new,
          action: (event, row) => deleteMapping(row),
        },
      ],
      options: {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "320px",
      rowHeight: 28,
      placeholder: "No external group mappings configured.",
      reactiveData: false,
      rowFormatter: (row) => markNewRecordRow(row, "source_selection"),
      columns: lockNewRecordColumns([
        {
          title: "Source",
          field: "source_selection",
          editor: "list",
          editorParams: { values: sourceValues },
          editable: (cell) => cell.getRow().getData().is_new,
          formatter: (cell) => {
            if (cell.getRow().getData().is_new && !cell.getValue()) {
              return dnsAddRowHintFormatter(cell, "+ Add record here");
            }
            return escapeHtml(sourceLabels[cell.getValue()] || cell.getRow().getData().source_name || "");
          },
          minWidth: 225,
          cellEdited: async (cell) => {
            const selection = String(cell.getValue() || "");
            const sourceType = selection.startsWith("role:") ? "local_role" : "ldap_group";
            const group = sourceType === "ldap_group"
              ? groupById.get(Number(selection.replace(/^group:/, "")))
              : null;
            await cell.getRow().update({
              source_type: sourceType,
              source_name: sourceLabels[selection] || "",
              organization_id: group?.organization_id ?? null,
              organization_name: group?.organization_name || "Local",
              oidc_client_id: null,
              oidc_client_name: "",
            });
            reformatPendingNewRecord(cell);
            await saveCell(cell);
          },
        },
        {
          title: "Source type",
          field: "source_type",
          editable: false,
          formatter: (cell) => escapeHtml(
            cell.getValue() === "local_role"
              ? "Local role"
              : (cell.getValue() === "ldap_group" ? "Managed LDAP group" : ""),
          ),
          minWidth: 160,
        },
        {
          title: "Identity organization",
          field: "organization_name",
          editable: false,
          formatter: (cell) => escapeHtml(cell.getValue() || ""),
          minWidth: 175,
        },
        {
          title: "Client scope",
          field: "oidc_client_id",
          editor: "list",
          editorParams: (cell) => ({ values: compatibleClientValues(cell.getRow().getData()), clearable: true }),
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (!data.source_selection) {
              return "";
            }
            const client = clientById.get(Number(cell.getValue()));
            if (client) {
              return escapeHtml(`${client.name}${client.enabled ? "" : " (disabled)"}`);
            }
            return escapeHtml(data.source_type === "ldap_group" ? "Organization default" : "Local default");
          },
          minWidth: 190,
          cellEdited: saveCell,
        },
        {
          title: "External group",
          field: "external_group_name",
          editor: "input",
          formatter: (cell) => (
            cell.getRow().getData().source_selection
              ? dnsAddRowHintFormatter(cell, "privacy-safe external name")
              : ""
          ),
          minWidth: 220,
          cellEdited: saveCell,
        },
      ], "source_selection"),
      },
    });
    table = grid.table;
    setMappingCount(rows.filter((row) => !row.is_new).length);
    setOidcGroupMappingMessage("Edit a mapped external name or client scope to autosave.", "idle");
  } catch (error) {
    showOidcGroupMappingError(
      error instanceof Error
        ? error.message
        : "The mapping grid could not render. Showing the read-only fallback table.",
    );
  }
}

async function oidcFormRequest(url, formData, { expectJson = true } = {}) {
  const response = await fetch(url, {
    method: "POST",
    body: formData,
    credentials: "same-origin",
    headers: { "X-Atlaso-Grid": "1" },
  });
  if (!response.ok) {
    let message = "";
    try {
      const payload = await response.json();
      message = String(payload.detail || "");
    } catch {
      message = (await response.text()).trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    }
    throw new Error(message || "The OIDC administration request failed.");
  }
  return expectJson ? response.json() : null;
}

function setOidcSecretResult(clientId, secret) {
  const result = document.getElementById("oidc-client-secret-result");
  const textarea = result?.querySelector("textarea");
  if (!(result instanceof HTMLElement) || !(textarea instanceof HTMLTextAreaElement)) return;
  textarea.value = secret || "";
  result.querySelector(".muted").textContent = `Client ID: ${clientId}. The plaintext value is not stored and cannot be shown again.`;
  result.classList.remove("hidden");
  textarea.focus();
  textarea.select();
}

function validateOidcRedirectUriField(form, fieldName, { required = false } = {}) {
  const field = form.elements.namedItem(fieldName);
  if (!(field instanceof HTMLTextAreaElement)) return { valid: true };
  const values = field.value.split(/\r?\n/).filter((value) => value.length > 0);
  if (required && values.length === 0) {
    return { valid: false, field: fieldName, message: "At least one exact redirect URI is required." };
  }
  const allowLoopback = Boolean(form.elements.namedItem("allow_loopback_redirects")?.checked);
  const seen = new Set();
  for (const value of values) {
    if (value !== value.trim()) {
      return { valid: false, field: fieldName, message: "Redirect URIs must not contain surrounding whitespace." };
    }
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      return { valid: false, field: fieldName, message: `"${value}" is not a valid absolute URI.` };
    }
    if (value.includes("*") || value.includes("\\")) {
      return { valid: false, field: fieldName, message: "Redirect URIs must not contain wildcards or backslashes." };
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      return { valid: false, field: fieldName, message: `"${value}" is not a valid absolute URI.` };
    }
    if (parsed.username || parsed.password) {
      return { valid: false, field: fieldName, message: "Redirect URIs must not contain user information." };
    }
    if (parsed.hash) {
      return { valid: false, field: fieldName, message: "Redirect URIs must not contain fragments." };
    }
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    const isLoopback = hostname === "::1" || /^127(?:\.\d{1,3}){3}$/.test(hostname);
    const secure = parsed.protocol === "https:";
    const allowedDevelopmentUri = parsed.protocol === "http:" && allowLoopback && isLoopback && Boolean(parsed.port);
    if (!secure && !allowedDevelopmentUri) {
      return {
        valid: false,
        field: fieldName,
        message: "Redirect URIs must use HTTPS. Explicit HTTP loopback addresses also require development mode and a port.",
      };
    }
    if (seen.has(value)) {
      return { valid: false, field: fieldName, message: "Duplicate redirect URIs are not allowed." };
    }
    seen.add(value);
  }
  return { valid: true };
}

function initializeApiTokensTable() {
  const element = document.getElementById("api-tokens-table");
  if (!(element instanceof HTMLElement)) return;
  const csrf = element.dataset.csrf || "";
  const revokeToken = async (row) => {
    const data = row.getData();
    const confirmed = await requestConfirmation({
      title: `Revoke API token ${data.name}?`,
      message: "The token stops authenticating immediately. Create a replacement token if the integration still needs access.",
      confirmLabel: "Revoke token",
      tone: "danger",
    });
    if (!confirmed) return;
    const body = new FormData();
    body.set("csrf", csrf);
    const payload = await atlasoGridWizardRequest(`/authentication/api-tokens/${data.id}/revoke`, body);
    await row.update(payload.token);
    showTransientGridStatus("Revoked");
  };
  initializeAtlasoResourceWizard({
    elementId: "api-tokens-table",
    formSelector: "[data-api-token-form]",
    dialogId: "api-token-dialog",
    rows: JSON.parse(element.dataset.tokens || "[]"),
    newRow: {
      id: "api-token-new",
      is_new: true,
      name: "",
      description: "",
      owner_username: "",
      role: "",
      scopes: "",
      expires_label: "",
      status: "",
      enabled: false,
    },
    resourceName: "token",
    createUrl: "/authentication/api-tokens",
    editUrl: () => "",
    editResource: false,
    canEdit: () => false,
    createLabel: "Create API token",
    updateLabel: "Create API token",
    emptyMessage: "No API tokens issued.",
    gridError: "API token changes are unavailable because the interactive grid could not initialize.",
    actionErrorSelector: "#api-tokens-status",
    defaults: {
      name: "",
      description: "",
      scopes: "read:dashboard",
    },
    steps: [
      { id: "identity", title: "Define the API token", description: "Give the credential an operator-visible identity and purpose." },
      { id: "scopes", title: "Grant least-privilege scopes", description: "Request only the Atlaso permissions this integration requires." },
      { id: "review", title: "Review immediate issuance", description: "Confirm the token scope and one-time secret handling." },
    ],
    onOpen: ({ form }) => {
      const selected = new Set(String(form.elements.scopes.value || "read:dashboard").split(/\s+/).filter(Boolean));
      form.querySelectorAll('input[name="scope_choices"]').forEach((input) => {
        input.checked = selected.has(input.value);
      });
    },
    validateStep: ({ form, step }) => {
      if (step.id === "scopes" && !form.querySelector('input[name="scope_choices"]:checked')) {
        return { valid: false, message: "Select at least one API scope.", field: form.querySelector('input[name="scope_choices"]') };
      }
      return { valid: true };
    },
    prepareFormData: ({ body, form }) => {
      const scopes = [...form.querySelectorAll('input[name="scope_choices"]:checked')].map((input) => input.value);
      body.set("scopes", scopes.join(" "));
      body.delete("scope_choices");
    },
    reviewItems: [
      { label: "Token", field: "name" },
      { label: "Purpose", field: "description" },
      { label: "Scopes", value: (form) => [...form.querySelectorAll('input[name="scope_choices"]:checked')].map((input) => input.value).join(" ") },
      { label: "Enforcement", value: () => "Immediate application state" },
    ],
    extraActions: [
      {
        label: "Revoke token",
        disabled: (row) => row.getData().is_new || !row.getData().enabled,
        action: (_event, row) => revokeToken(row),
      },
    ],
    onSaved: ({ payload }) => {
      const result = document.querySelector("[data-api-token-secret-result]");
      const secret = document.querySelector("[data-api-token-secret]");
      const copy = document.querySelector("[data-api-token-copy]");
      if (result instanceof HTMLElement && secret instanceof HTMLTextAreaElement) {
        secret.value = payload.raw_token || "";
        result.classList.remove("hidden");
        if (copy instanceof HTMLButtonElement) {
          copy.dataset.copyValue = payload.raw_token || "";
          copy.disabled = !payload.raw_token;
        }
      }
    },
    options: {
      height: "360px",
      placeholder: "No API tokens issued.",
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 190,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add token here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Owner", field: "owner_username", minWidth: 140, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue()) },
        { title: "Role", field: "role", width: 130, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue()) },
        { title: "Scopes", field: "scopes", minWidth: 320, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue()) },
        { title: "Expires", field: "expires_label", width: 120, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue()) },
        {
          title: "Status",
          field: "status",
          width: 105,
          formatter: (cell) => cell.getRow().getData().is_new
            ? ""
            : `<span class="status-pill ${cell.getValue() === "active" ? "good" : "muted"}">${escapeHtml(cell.getValue())}</span>`,
        },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function initializeOidcClientsTable() {
  const element = document.getElementById("oidc-clients-table");
  const form = document.querySelector("[data-oidc-client-form]");
  const dialog = document.getElementById("oidc-client-dialog");
  if (!(element instanceof HTMLElement) || !(form instanceof HTMLFormElement) || !(dialog instanceof HTMLDialogElement)) return;
  const rows = [
    ...JSON.parse(element.dataset.clients || "[]"),
    {
      id: "oidc-client-new",
      is_new: true,
      name: "",
      client_id: "",
      organization_slug: "",
      redirect_uris: [],
      enabled: false,
    },
  ];
  const csrf = element.dataset.csrf || "";
  let table;
  let wizard;

  const checkedScopes = () => [...form.querySelectorAll('input[name="allowed_scopes"]:checked')].map((input) => input.value);
  const populateForm = (data = null) => {
    form.elements.namedItem("client_record_id").value = data?.id || "";
    form.elements.namedItem("name").value = data?.name || "";
    form.elements.namedItem("description").value = data?.description || "";
    form.elements.namedItem("organization_id").value = data?.organization_id || "";
    form.elements.namedItem("redirect_uris").value = (data?.redirect_uris || []).join("\n");
    form.elements.namedItem("post_logout_redirect_uris").value = (data?.post_logout_redirect_uris || []).join("\n");
    form.elements.namedItem("allow_loopback_redirects").checked = Boolean(data?.allow_loopback_redirects);
    form.elements.namedItem("enabled").checked = data ? Boolean(data.enabled) : true;
    const scopes = new Set(data?.allowed_scopes || ["openid"]);
    form.querySelectorAll('input[name="allowed_scopes"]').forEach((input) => {
      input.checked = scopes.has(input.value);
    });
    form.querySelector("[data-atlaso-wizard-submit]").textContent = data ? "Update confidential client" : "Register confidential client";
  };
  const openClient = (data, launcher) => wizard.open({ launcher, context: data || null });
  const refreshRow = async (payload, existingId = null) => {
    if (existingId) {
      const row = table.getRow(existingId);
      if (row) await row.update(payload);
    } else {
      await table.addRow(payload, false, "oidc-client-new");
    }
  };
  const rotateSecret = async (data) => {
    const confirmed = await requestConfirmation({
      title: `Rotate secret for ${data.name}?`,
      message: "The previous secret stops working immediately. The replacement is shown once and must be copied into the relying party.",
      confirmLabel: "Rotate client secret",
    });
    if (!confirmed) return;
    const body = new FormData();
    body.set("csrf", csrf);
    const payload = await oidcFormRequest(`/authentication/oidc/clients/${data.id}/rotate-secret`, body);
    setOidcSecretResult(payload.client_id, payload.client_secret);
  };
  const deleteClient = async (data) => {
    const confirmed = await requestConfirmation({
      title: `Delete OIDC client ${data.name}?`,
      message: "This permanently removes the client, secret hash, exact redirects, and client-specific mappings. No appliance service is changed.",
      confirmLabel: "Delete OIDC client",
      tone: "danger",
    });
    if (!confirmed) return;
    const body = new FormData();
    body.set("csrf", csrf);
    await oidcFormRequest(`/authentication/oidc/clients/${data.id}/delete`, body, { expectJson: false });
    await table.getRow(data.id)?.delete();
  };
  const exportClient = async (data) => {
    const response = await fetch(`/authentication/oidc/clients/${data.id}/integration-export`, { credentials: "same-origin" });
    if (!response.ok) throw new Error("The redacted integration export could not be generated.");
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `atlaso-oidc-${data.id}-integration.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const grid = window.AtlasoUiPatterns.createGrid({
    element,
    fallback: `#${element.dataset.fallbackId}`,
    status: "#oidc-clients-status",
    pattern: "wizard-backed",
    emptyMessage: "No confidential clients registered.",
    onOpenRow: (data, row, event) => openClient(
      data.is_new ? null : data,
      event?.currentTarget || row?.getElement?.(),
    ),
    rowActions: [
      { label: "Edit client", disabled: (row) => row.getData().is_new, action: (event, row) => openClient(row.getData(), row.getElement()) },
      { label: "Rotate secret", disabled: (row) => row.getData().is_new, action: (event, row) => rotateSecret(row.getData()).catch((error) => grid.setError(error.message)) },
      { label: "Download redacted integration", disabled: (row) => row.getData().is_new, action: (event, row) => exportClient(row.getData()).catch((error) => grid.setError(error.message)) },
      { label: "Delete client", disabled: (row) => row.getData().is_new, action: (event, row) => deleteClient(row.getData()).catch((error) => grid.setError(error.message)) },
    ],
    options: {
      data: rows,
      index: "id",
      height: "330px",
      placeholder: "No confidential clients registered.",
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 190,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-oidc-client-add>+ Add client here</button>'
            : escapeHtml(cell.getValue()),
        },
        { title: "Client ID", field: "client_id", minWidth: 230, formatter: (cell) => cell.getRow().getData().is_new ? "" : `<code>${escapeHtml(cell.getValue())}</code>` },
        { title: "Description", field: "description", minWidth: 220, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "") },
        { title: "Organization", field: "organization_slug", minWidth: 150, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "Unbound") },
        { title: "Redirects", field: "redirect_uris", minWidth: 260, formatter: (cell) => cell.getRow().getData().is_new ? "" : (cell.getValue() || []).map((value) => `<code>${escapeHtml(value)}</code>`).join("<br>") },
        { title: "Status", field: "enabled", width: 105, formatter: (cell) => cell.getRow().getData().is_new ? "" : `<span class="status-pill ${cell.getValue() ? "good" : "muted"}">${cell.getValue() ? "enabled" : "disabled"}</span>` },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
  table = grid.table;
  if (!table) {
    const launcher = document.querySelector("[data-oidc-client-add]");
    if (launcher instanceof HTMLButtonElement) {
      launcher.disabled = true;
      launcher.setAttribute("aria-disabled", "true");
    }
    grid.setError("Client changes are unavailable because the interactive grid could not initialize.");
    return;
  }
  wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "identity", title: "Define the confidential client", description: "Set its operator label, validated identity source, and allowed scopes." },
      { id: "redirects", title: "Register exact redirects", description: "Enter byte-for-byte redirect and post-logout destinations." },
      { id: "state", title: "Choose client state", description: "Decide whether the reviewed client may begin and redeem authorization requests." },
      { id: "review", title: "Review client lifecycle", description: "Confirm the application-state change and secret handling." },
    ],
    onOpen: ({ context }) => populateForm(context),
    validateStep: ({ step }) => {
      if (step.id === "identity" && !checkedScopes().includes("openid")) {
        return { valid: false, message: "The openid scope is required." };
      }
      if (step.id === "redirects") {
        const redirectResult = validateOidcRedirectUriField(form, "redirect_uris", { required: true });
        if (!redirectResult.valid) return redirectResult;
        return validateOidcRedirectUriField(form, "post_logout_redirect_uris");
      }
      return { valid: true };
    },
    prepareReview: () => {
      const review = form.querySelector("[data-oidc-client-review]");
      const name = form.elements.namedItem("name").value.trim();
      const description = form.elements.namedItem("description").value.trim();
      const organization = form.elements.namedItem("organization_id").selectedOptions[0]?.textContent || "Unbound";
      const redirects = form.elements.namedItem("redirect_uris").value.split(/\r?\n/).filter(Boolean).length;
      const enabled = form.elements.namedItem("enabled").checked;
      review.innerHTML = `<div><span>Client</span><strong>${escapeHtml(name)}</strong></div><div><span>Description</span><strong>${escapeHtml(description || "Not provided")}</strong></div><div><span>Identity source</span><strong>${escapeHtml(organization)}</strong></div><div><span>Scopes</span><strong>${escapeHtml(checkedScopes().join(" "))}</strong></div><div><span>Exact redirects</span><strong>${redirects}</strong></div><div><span>State</span><strong>${enabled ? "Enabled" : "Disabled"}</strong></div>`;
    },
    onSubmit: async () => {
      const body = new FormData(form);
      const recordId = body.get("client_record_id");
      const url = recordId ? `/authentication/oidc/clients/${recordId}/edit` : "/authentication/oidc/clients";
      const payload = await oidcFormRequest(url, body);
      const client = payload.client || payload;
      await refreshRow(client, recordId ? Number(recordId) : null);
      if (payload.client_secret) setOidcSecretResult(client.client_id, payload.client_secret);
      return { valid: true };
    },
  });
  element.addEventListener("click", (event) => {
    const launcher = event.target.closest("[data-oidc-client-add]");
    if (launcher instanceof HTMLButtonElement) openClient(null, launcher);
  });
}

function initializeOidcKeysTable() {
  const element = document.getElementById("oidc-keys-table");
  const form = document.querySelector("[data-oidc-key-form]");
  const dialog = document.getElementById("oidc-key-dialog");
  if (!(element instanceof HTMLElement) || !(form instanceof HTMLFormElement) || !(dialog instanceof HTMLDialogElement)) return;
  const rows = JSON.parse(element.dataset.keys || "[]");
  const csrf = element.dataset.csrf || "";
  let table;
  const deleteKey = async (data) => {
    const confirmed = await requestConfirmation({
      title: `Delete retired key ${data.kid}?`,
      message: "Deletion is allowed only after its public overlap window ends. The encrypted private key and public JWK will be removed.",
      confirmLabel: "Delete retired key",
      tone: "danger",
    });
    if (!confirmed) return;
    const body = new FormData();
    body.set("csrf", csrf);
    await oidcFormRequest(`/authentication/oidc/signing-keys/${data.id}/delete`, body, { expectJson: false });
    await table.getRow(data.id)?.delete();
  };
  const grid = window.AtlasoUiPatterns.createGrid({
    element,
    fallback: `#${element.dataset.fallbackId}`,
    status: "#oidc-keys-status",
    pattern: "wizard-backed",
    emptyMessage: "No signing key generated.",
    rowActions: [
      {
        label: "Delete retired key",
        disabled: (row) => row.getData().status !== "retired",
        action: (event, row) => deleteKey(row.getData()).catch((error) => grid.setError(error.message)),
      },
    ],
    options: {
      data: rows,
      index: "id",
      height: "250px",
      columns: [
        { title: "Key ID", field: "kid", minWidth: 260, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
        { title: "Algorithm", field: "algorithm", width: 110 },
        { title: "Status", field: "status", width: 110 },
        { title: "Published until", field: "publish_until", minWidth: 190, formatter: (cell) => escapeHtml(cell.getValue() || "active") },
      ],
    },
  });
  table = grid.table;
  if (!table) {
    const launcher = document.querySelector("[data-oidc-key-launch]");
    if (launcher instanceof HTMLButtonElement) {
      launcher.disabled = true;
      launcher.setAttribute("aria-disabled", "true");
    }
    grid.setError("Signing-key changes are unavailable because the interactive grid could not initialize.");
    return;
  }
  const wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "operation", title: "Prepare signing key", description: "Review encrypted custody and public metadata." },
      { id: "review", title: "Review key lifecycle", description: "Confirm generation and the enforced overlap." },
    ],
    onSubmit: async () => {
      const payload = await oidcFormRequest("/authentication/oidc/signing-keys", new FormData(form));
      if (payload.previous) await table.getRow(payload.previous.id)?.update(payload.previous);
      await table.addRow(payload.key, true);
      form.elements.namedItem("rotate").value = "true";
      const launcher = document.querySelector("[data-oidc-key-launch]");
      if (launcher) launcher.textContent = "Rotate signing key";
      form.querySelector("[data-atlaso-wizard-submit]").textContent = "Rotate signing key";
      return { valid: true };
    },
  });
  document.querySelector("[data-oidc-key-launch]")?.addEventListener("click", (event) => wizard.open({ launcher: event.currentTarget }));
}

function initializeOidcSubjectsTable() {
  const element = document.getElementById("oidc-subjects-table");
  if (!(element instanceof HTMLElement)) return;
  window.AtlasoUiPatterns.createGrid({
    element,
    fallback: `#${element.dataset.fallbackId}`,
    status: "#oidc-subjects-status",
    pattern: "read-only",
    emptyMessage: "Subjects are created only after a credential is verified for OIDC.",
    options: {
      data: JSON.parse(element.dataset.subjects || "[]"),
      index: "subject",
      height: "280px",
      columns: [
        { title: "Subject", field: "subject", minWidth: 300, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
        { title: "Source", field: "source", width: 130 },
        { title: "Username", field: "username", minWidth: 160 },
        { title: "Organization", field: "organization_name", minWidth: 170 },
      ],
    },
  });
}

function initializeVlanInterfacesTable() {
  const tableElement = document.getElementById("vlan-interfaces-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showNetworkMessage("vlan-interface-error", "Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const parentOptionRows = JSON.parse(tableElement.dataset.parentOptions || "[]");
  const parentOptions = parentOptionRows.map((item) => (typeof item === "string" ? { name: item, label: item } : item));
  const roleOptions = roleValues(JSON.parse(tableElement.dataset.roleOptions || "[]"));
  const parentValues = Object.fromEntries(parentOptions.map((item) => [item.name, item.label || item.name]));
  const parentMtus = Object.fromEntries(parentOptions.map((item) => [item.name, Number(item.mtu) || 1500]));
  const defaultParent = parentOptions[0]?.name || "";
  const defaultMtu = parentMtus[defaultParent] || 1500;
  const rows = [...JSON.parse(tableElement.dataset.vlans || "[]"), newVlanInterfaceRow(defaultParent, defaultMtu)];
  try {
    const atlasoGridOptions19 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No VLAN interfaces configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete VLAN",
          action: (event, row) => deleteVlanInterfaceFromMenu(row, csrf),
        },
      ],
      columns: lockNewRecordColumns([
        {
          title: "Add VLAN +",
          field: "add_vlan",
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.is_new) {
              return '<span class="add-row-hint">+ Add VLAN</span>';
            }
            return "";
          },
          width: 115,
          headerSort: false,
          editable: false,
          cellClick: (event, cell) => activateNewVlanRow(cell),
        },
        {
          title: "VLAN ID",
          field: "vlan_id",
          editor: "number",
          width: 100,
          cellEdited: (cell) => autoSaveVlanId(cell, csrf),
        },
        {
          title: "Parent",
          field: "parent_interface",
          editor: "list",
          editorParams: { values: parentValues },
          formatter: (cell) => {
            const value = cell.getValue();
            if (!value) {
              return '<span class="add-row-hint">mark a physical NIC as trunk first</span>';
            }
            return escapeHtml(value);
          },
          minWidth: 120,
          cellEdited: (cell) => autoSaveVlanParent(cell, csrf, parentMtus),
        },
        {
          title: "Name",
          field: "name",
          formatter: (cell) => escapeHtml(cell.getValue()),
          minWidth: 140,
          headerSort: false,
          editable: false,
        },
        {
          title: "IPv4 CIDR",
          field: "ip_cidr",
          editor: cidrInputEditor,
          editorParams: { family: "ipv4", placeholder: "192.168.50.1/24" },
          formatter: (cell) => dnsAddRowHintFormatter(cell, "192.168.50.1/24"),
          minWidth: 170,
          cellEdited: (cell) => autoSaveVlanInterface(cell, csrf),
        },
        {
          title: "IPv6 CIDR",
          field: "ipv6_cidr",
          editor: cidrInputEditor,
          editorParams: { family: "ipv6", placeholder: "fd00:50::1/64" },
          formatter: (cell) => dnsAddRowHintFormatter(cell, "fd00:50::1/64"),
          minWidth: 180,
          cellEdited: (cell) => autoSaveVlanInterface(cell, csrf),
        },
        {
          title: "MTU",
          field: "mtu",
          editor: "number",
          width: 90,
          cellEdited: (cell) => autoSaveVlanInterface(cell, csrf),
        },
        {
          title: "Role",
          field: "role",
          editor: "list",
          editorParams: { values: roleOptions },
          minWidth: 130,
          cellEdited: (cell) => autoSaveVlanInterface(cell, csrf),
        },
        {
          title: "Admin Up",
          field: "enabled",
          formatter: vlanEnabledFormatter,
          editor: "tickCross",
          editable: (cell) => !cell.getRow().getData().parent_missing,
          hozAlign: "center",
          width: 100,
          headerSort: false,
          cellEdited: (cell) => autoSaveVlanInterface(cell, csrf),
        },
      ], "vlan_id"),
      rowFormatter: (row) => {
        markNewRecordRow(row, "vlan_id", "add_vlan");
        row.getElement().classList.toggle("locked-record-row", Boolean(row.getData().parent_missing));
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions19,
    }).table;
  } catch (error) {
    showNetworkMessage("vlan-interface-error", error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeDnsRecordsTable() {
  const tableElements = document.querySelectorAll(".dns-records-table");
  if (!tableElements.length) {
    return;
  }
  if (typeof Tabulator === "undefined") {
    showTableError("Tabulator did not load. Showing the fallback table.");
    return;
  }
  tableElements.forEach((tableElement) => initializeDnsRecordsTableElement(tableElement));
}

function initializeDnsDomainWizard() {
  const form = document.querySelector("[data-dns-domain-form]");
  const dialog = document.getElementById("dns-domain-dialog");
  if (!(form instanceof HTMLFormElement) || !(dialog instanceof HTMLDialogElement)) return;
  const wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "identity", title: "Define the DNS domain", description: "Choose the managed DNS suffix that will own its records and zone-file tools." },
      { id: "enablement", title: "Choose domain enablement", description: "Choose whether the domain enters rendered dnsmasq desired state." },
      { id: "review", title: "Review DNS desired state", description: "Confirm the domain and global appliance-apply boundary." },
    ],
    onOpen: () => populateAtlasoWizardForm(form, { domain: "", description: "", enabled: true }),
    validateStep: validateAtlasoWizardStep,
    prepareReview: () => renderAtlasoWizardReview(form, [
      { label: "Domain", field: "domain" },
      { label: "Description", field: "description" },
      { label: "Enabled", field: "enabled" },
    ]),
    onSubmit: async () => {
      await atlasoGridWizardRequest("/dns/zones", new FormData(form));
      window.location.reload();
      return { valid: true };
    },
  });
  document.querySelectorAll("[data-dns-domain-wizard-add]").forEach((launcher) => {
    launcher.addEventListener("click", () => wizard.open({ launcher }));
  });
  document.querySelectorAll("[data-dns-domain-enabled-form]").forEach((toggleForm) => {
    if (!(toggleForm instanceof HTMLFormElement)) return;
    const toggle = toggleForm.elements.namedItem("enabled");
    if (!(toggle instanceof HTMLInputElement)) return;
    toggle.addEventListener("change", async () => {
      const previous = !toggle.checked;
      try {
        await atlasoGridWizardRequest("/dns/zones/enabled", new FormData(toggleForm));
        showTransientGridStatus(toggle.checked ? "Enabled" : "Disabled");
        window.location.reload();
      } catch (error) {
        toggle.checked = previous;
        const status = document.getElementById("dns-record-error");
        if (status instanceof HTMLElement) {
          status.textContent = error instanceof Error ? error.message : "The DNS domain state could not be saved.";
          status.classList.remove("hidden");
        }
      }
    });
  });
}

function initializeDnsRecordsTableElement(tableElement) {
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  const domain = tableElement.dataset.domain || "";
  const records = [...JSON.parse(tableElement.dataset.records || "[]"), newDnsRecordRow(domain, tableElement.dataset.suggestedIpv4 || "")];
  const csrf = tableElement.dataset.csrf || "";

  try {
    const atlasoGridOptions20 = {
      data: records,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No DNS records configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete record",
          action: (event, row) => deleteDnsRecordFromMenu(row, csrf),
        },
      ],
      columns: [
        {
          title: "Host",
          field: "host_label",
          editor: "input",
          editable: dnsRecordCellEditable,
          formatter: (cell) => dnsAddRowHintFormatter(cell, "+ Add record here"),
          minWidth: 180,
          cellEdited: (cell) => autoSaveDnsRecord(cell, csrf),
        },
        { title: "Domain", field: "domain", formatter: dnsRecordDomainFormatter, minWidth: 190, headerSort: false },
        {
          title: "Family",
          field: "record_type",
          editor: "list",
          editable: dnsRecordCellEditable,
          editorParams: { values: dnsRecordTypeOptions() },
          formatter: (cell) => dnsRecordTypeLabel(cell.getValue()),
          width: 130,
          headerSort: false,
          cellEdited: (cell) => autoSaveDnsRecord(cell, csrf),
        },
        {
          title: "Value",
          field: "address",
          editor: "input",
          editable: dnsRecordCellEditable,
          formatter: (cell) => dnsAddRowHintFormatter(cell, dnsRecordValueHint(cell.getRow().getData().record_type)),
          minWidth: 170,
          cellEdited: (cell) => autoSaveDnsRecord(cell, csrf),
        },
        {
          title: "Reverse/PTR",
          field: "reverse_label",
          formatter: reverseStatusFormatter,
          minWidth: 260,
          headerSort: false,
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          editable: dnsRecordCellEditable,
          hozAlign: "center",
          width: 110,
          headerSort: false,
          cellEdited: (cell) => autoSaveDnsRecord(cell, csrf),
        },
        {
          title: "Description",
          field: "description",
          editor: "input",
          editable: dnsRecordCellEditable,
          formatter: (cell) => dnsAddRowHintFormatter(cell, "optional note..."),
          minWidth: 220,
          cellEdited: (cell) => autoSaveDnsRecord(cell, csrf),
        },
      ],
      rowFormatter: (row) => {
        markNewRecordRow(row, "host_label");
      },
    };
    const table = window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions20,
    }).table;
    if (table) {
      atlasoDnsRecordTables.set(tableElement, table);
      redrawDnsRecordTables(tableElement);
    }
  } catch (error) {
    showTableError(error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeDhcpScopesTable() {
  const element = document.getElementById("dhcp-scopes-table");
  if (!(element instanceof HTMLElement)) return;
  const interfaceOptions = JSON.parse(element.dataset.interfaceOptions || "[]");
  const scopeDefaults = JSON.parse(element.dataset.scopeDefaults || "{}");
  const defaultInterface = interfaceOptions[0] || "eth1";
  const defaults = applyDhcpScopeInterfaceDefaults(
    {
      ...newDhcpScopeRow(defaultInterface, scopeDefaults),
      address_family: dhcpDefaultFamilyForInterface(scopeDefaults, defaultInterface),
      interface_name: defaultInterface,
      lease_time: "12h",
    },
    scopeDefaults,
    { overwrite: true },
  );
  const form = document.querySelector("[data-dhcp-scope-form]");
  const parseLeaseTime = (value) => {
    const original = String(value || "").trim();
    const match = original.match(/^([1-9]\d*)([mhd])$/i);
    return match
      ? { duration: match[1], unit: match[2].toLowerCase(), original, supported: true }
      : { duration: "", unit: "h", original, supported: false };
  };
  const syncLeaseTime = () => {
    if (!(form instanceof HTMLFormElement)) return;
    const duration = form.elements.lease_duration;
    const unit = form.elements.lease_unit;
    const leaseTime = form.elements.lease_time;
    if (duration instanceof HTMLInputElement && unit instanceof HTMLSelectElement && leaseTime instanceof HTMLInputElement) {
      leaseTime.value = duration.value
        ? `${duration.value}${unit.value}`
        : leaseTime.dataset.atlasoOriginalLeaseTime || "";
    }
  };
  const leaseTimeLabel = () => {
    if (!(form instanceof HTMLFormElement)) return "";
    const duration = form.elements.lease_duration.value;
    const unit = form.elements.lease_unit.selectedOptions[0]?.textContent || "";
    return `${duration} ${unit}`.trim();
  };
  const refreshDerivedRange = (force = false) => {
    if (!(form instanceof HTMLFormElement)) return;
    const range = form.elements.range_expression;
    if (!(range instanceof HTMLInputElement)) return;
    const derived = deriveDhcpLeaseRange(
      form.elements.site_address.value,
      form.elements.prefix_length.value,
      form.elements.address_family.value,
    );
    const previousDerived = range.dataset.atlasoDerivedRange || "";
    if (derived && (force || !range.value.trim() || range.value === previousDerived)) {
      range.value = derived;
      range.dataset.atlasoDerivedRange = derived;
    }
  };
  const refreshNetworkDefaults = () => {
    if (!(form instanceof HTMLFormElement)) return;
    const interfaceName = form.elements.interface_name.value;
    const family = form.elements.address_family;
    const interfaceDefaults = dhcpInterfaceDefaults(scopeDefaults, interfaceName);
    if (
      family instanceof HTMLSelectElement
      && ((family.value === "ipv4" && !interfaceDefaults.ipv4_address)
        || (family.value === "ipv6" && !interfaceDefaults.ipv6_address))
    ) {
      family.value = dhcpDefaultFamilyForInterface(scopeDefaults, interfaceName);
    }
    const updated = applyDhcpScopeInterfaceDefaults(
      Object.fromEntries(new FormData(form).entries()),
      scopeDefaults,
      { overwrite: true },
    );
    ["site_address", "prefix_length", "dns_server", "ntp_server", "domain_name"].forEach((name) => {
      if (form.elements[name]) form.elements[name].value = updated[name] ?? "";
    });
    refreshDerivedRange(true);
  };
  form?.elements.interface_name?.addEventListener("change", refreshNetworkDefaults);
  form?.elements.address_family?.addEventListener("change", refreshNetworkDefaults);
  form?.elements.site_address?.addEventListener("input", () => refreshDerivedRange());
  form?.elements.prefix_length?.addEventListener("input", () => refreshDerivedRange());
  form?.elements.lease_duration?.addEventListener("input", syncLeaseTime);
  form?.elements.lease_unit?.addEventListener("change", syncLeaseTime);
  initializeAtlasoResourceWizard({
    elementId: "dhcp-scopes-table",
    formSelector: "[data-dhcp-scope-form]",
    dialogId: "dhcp-scope-dialog",
    rows: JSON.parse(element.dataset.scopes || "[]"),
    newRow: { ...defaults, id: "__new__", is_new: true },
    resourceName: "scope",
    createUrl: "/dhcp/scopes",
    editUrl: (id) => `/dhcp/scopes/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/dhcp/scopes/${id}/delete`,
    editLabel: "Edit IP zone",
    deleteLabel: "Delete IP zone",
    createLabel: "Create IP zone",
    updateLabel: "Update IP zone",
    emptyMessage: "No DHCP IP zones configured.",
    actionErrorSelector: "#dhcp-scope-error",
    defaults,
    steps: [
      { id: "identity", title: "Choose zone identity", description: "Name the IP zone and bind its address family and interface." },
      { id: "network", title: "Define the address pool", description: "Set the gateway, prefix, and lease range." },
      { id: "services", title: "Set lease services", description: "Configure lease duration, DNS, NTP, and domain values." },
      { id: "enablement", title: "Choose zone enablement", description: "Choose whether the zone enters rendered dnsmasq desired state." },
      { id: "review", title: "Review DHCP desired state", description: "Confirm the IP zone and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Zone", field: "name" },
      { label: "Family", field: "address_family" },
      { label: "Interface", field: "interface_name" },
      { label: "Network", value: (form) => `${form.elements.site_address.value}/${form.elements.prefix_length.value}` },
      { label: "Range", field: "range_expression" },
      { label: "Lease", value: leaseTimeLabel },
      { label: "Domain", field: "domain_name" },
      { label: "Enabled", field: "enabled" },
    ],
    onOpen: ({ form, context }) => {
      const family = form.elements.address_family;
      if (family instanceof HTMLSelectElement) family.disabled = Boolean(context);
      const lease = parseLeaseTime(context?.lease_time || defaults.lease_time);
      form.elements.lease_time.dataset.atlasoOriginalLeaseTime = lease.original;
      form.elements.lease_duration.value = lease.duration;
      form.elements.lease_unit.value = lease.unit;
      form.elements.lease_duration.placeholder = lease.supported
        ? ""
        : `Replace unsupported value: ${lease.original || "empty"}`;
      syncLeaseTime();
      if (!context) refreshDerivedRange(true);
    },
    validateStep: ({ form, step }) => {
      if (
        step.id === "services"
        && (!/^[1-9]\d*$/.test(form.elements.lease_duration.value)
          || !["m", "h", "d"].includes(form.elements.lease_unit.value))
      ) {
        return {
          valid: false,
          message: "Enter a positive whole-number lease duration and choose Minutes, Hours, or Days.",
          field: "lease_duration",
        };
      }
      return { valid: true };
    },
    prepareFormData: ({ body, form }) => {
      syncLeaseTime();
      body.set("address_family", form.elements.address_family.value);
      body.set("lease_time", form.elements.lease_time.value);
    },
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name} IP zone?`,
      message: "This removes the DHCP IP zone and its scoped options from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete IP zone",
      tone: "danger",
    }),
    options: {
      height: "300px",
      rowHeight: 28,
      placeholder: "No DHCP IP zones configured.",
      columns: [
        { title: "Zone", field: "name", formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add IP zone here</button>' : escapeHtml(cell.getValue()), minWidth: 150 },
        { title: "Family", field: "address_family", formatter: (cell) => cell.getRow().getData().is_new ? "" : (cell.getValue() === "ipv6" ? "IPv6" : "IPv4"), width: 100 },
        { title: "Interface", field: "interface_name", minWidth: 120 },
        { title: "Gateway", field: "site_address", minWidth: 140 },
        { title: "Prefix", field: "prefix_length", width: 90 },
        { title: "Range", field: "range_expression", formatter: dhcpRangeFormatter, minWidth: 240 },
        { title: "Lease", field: "lease_time", width: 90 },
        { title: "DNS", field: "dns_server", minWidth: 140 },
        { title: "NTP", field: "ntp_server", minWidth: 140 },
        { title: "Domain", field: "domain_name", minWidth: 180 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 100, headerSort: false },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function initializeDhcpOptionsTable() {
  const element = document.getElementById("dhcp-options-table");
  if (!(element instanceof HTMLElement)) return;
  const scopeOptions = JSON.parse(element.dataset.scopeOptions || "[]");
  const scopeValues = Object.fromEntries(scopeOptions.map((item) => [item.id, item.label]));
  initializeAtlasoResourceWizard({
    elementId: "dhcp-options-table",
    formSelector: "[data-dhcp-option-form]",
    dialogId: "dhcp-option-dialog",
    rows: JSON.parse(element.dataset.options || "[]"),
    newRow: newDhcpOptionRow(),
    resourceName: "option",
    createUrl: "/dhcp/options",
    editUrl: (id) => `/dhcp/options/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/dhcp/options/${id}/delete`,
    editLabel: "Edit option",
    deleteLabel: "Delete option",
    createLabel: "Create DHCP option",
    updateLabel: "Update DHCP option",
    emptyMessage: "No DHCP options configured.",
    actionErrorSelector: "#dhcp-option-error",
    defaults: newDhcpOptionRow(),
    steps: [
      { id: "target", title: "Choose option target", description: "Apply this option globally or to one managed IP zone." },
      { id: "value", title: "Define the DHCP option", description: "Set the dnsmasq option code, value, and operator notes." },
      { id: "enablement", title: "Choose option enablement", description: "Choose whether the option enters rendered dnsmasq desired state." },
      { id: "review", title: "Review DHCP desired state", description: "Confirm the option and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Applies to", value: (form) => scopeValues[form.elements.scope_id.value] || "Global defaults" },
      { label: "Option", field: "option_code" },
      { label: "Value", field: "value" },
      { label: "Enabled", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete DHCP option ${data.option_code}?`,
      message: "This removes the DHCP option from Atlaso desired state. It will not touch the appliance until global appliance apply runs.",
      confirmLabel: "Delete option",
      tone: "danger",
    }),
    options: {
      height: "260px",
      rowHeight: 28,
      placeholder: "No DHCP options configured.",
      columns: [
        {
          title: "Applies to",
          field: "scope_id",
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add DHCP option here</button>'
            : escapeHtml(scopeValues[cell.getValue()] || "Global defaults"),
          minWidth: 150,
        },
        { title: "Option", field: "option_code", minWidth: 150 },
        { title: "Value", field: "value", minWidth: 220 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 100, headerSort: false },
        { title: "Description", field: "description", minWidth: 220 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "scope_id"),
    },
  });
}

function initializeDhcpReservationsTable() {
  const tableElement = document.getElementById("dhcp-reservations-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showDhcpReservationError("Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const rows = [...JSON.parse(tableElement.dataset.reservations || "[]"), newDhcpReservationRow()];
  const handleDhcpReservationEdited = (cell) => {
    if (cell.getRow().getData().is_new) {
      cell.getRow().reformat();
    }
    return autoSaveDhcpReservation(cell, csrf);
  };
  try {
    const atlasoGridOptions23 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "420px",
      rowHeight: 28,
      placeholder: "No DHCP reservations configured.",
      reactiveData: false,
      rowContextMenu: [
        {
          label: "Delete reservation",
          action: (event, row) => deleteDhcpReservationFromMenu(row, csrf),
        },
      ],
      columns: [
        {
          title: "DNS name / FQDN",
          field: "hostname",
          editor: "input",
          formatter: (cell) => dnsAddRowHintFormatter(cell, "+ Add reservation here"),
          minWidth: 180,
          cellEdited: handleDhcpReservationEdited,
        },
        {
          title: "MAC address",
          field: "mac_address",
          editor: "input",
          editable: dhcpReservationCellEditable,
          formatter: (cell) => dhcpReservationAddRowHintFormatter(cell, "enter MAC..."),
          minWidth: 180,
          cellEdited: handleDhcpReservationEdited,
        },
        {
          title: "IP address",
          field: "ip_address",
          editor: "input",
          editable: dhcpReservationCellEditable,
          formatter: (cell) => dhcpReservationAddRowHintFormatter(cell, "enter IP..."),
          minWidth: 150,
          cellEdited: handleDhcpReservationEdited,
        },
        {
          title: "Zone",
          field: "zone_name",
          formatter: (cell) => escapeHtml(cell.getValue() || "-"),
          minWidth: 120,
          editor: false,
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: "tickCross",
          editable: dhcpReservationCellEditable,
          hozAlign: "center",
          width: 110,
          headerSort: false,
          cellEdited: handleDhcpReservationEdited,
        },
        {
          title: "Description",
          field: "description",
          editor: "input",
          editable: dhcpReservationCellEditable,
          formatter: (cell) => dhcpReservationAddRowHintFormatter(cell, "optional note..."),
          minWidth: 220,
          cellEdited: handleDhcpReservationEdited,
        },
      ],
      rowFormatter: (row) => {
        row.getElement().classList.toggle("new-record-row", Boolean(row.getData().is_new));
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      options: atlasoGridOptions23,
    }).table;
  } catch (error) {
    showDhcpReservationError(error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

function initializeEsxiPxeHostsTable() {
  const tableElement = document.getElementById("esxi-pxe-hosts-table");
  if (!(tableElement instanceof HTMLElement)) {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  if (typeof Tabulator === "undefined") {
    showEsxiHostError("Tabulator did not load. Showing the fallback table.");
    return;
  }
  const csrf = tableElement.dataset.csrf || "";
  const canWrite = tableElement.dataset.canWrite === "true";
  const kickstartOptions = JSON.parse(tableElement.dataset.kickstartOptions || "[]");
  const isoOptions = JSON.parse(tableElement.dataset.isoOptions || "[]");
  const kickstartValues = Object.fromEntries(kickstartOptions.map((item) => [item.id, item.label]));
  const isoValues = Object.fromEntries(isoOptions.map((item) => [item.id, item.label]));
  const defaultIsoPath = isoOptions.find((item) => item.id)?.id || "";
  const rows = [...JSON.parse(tableElement.dataset.hosts || "[]"), newEsxiHostRow(defaultIsoPath)];
  try {
    const atlasoGridOptions24 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "calc(100vh - 250px)",
      rowHeight: 30,
      placeholder: "No ESXi PXE host references configured.",
      reactiveData: false,
      rowContextMenu: canWrite ? [
        {
          label: "Delete host reference",
          action: (event, row) => deleteEsxiHost(row, csrf),
        },
      ] : false,
      columns: lockNewRecordColumns([
        {
          title: "Host",
          field: "hostname",
          editor: canWrite ? "input" : false,
          editable: (cell) => !cell.getRow().getData().is_default,
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.is_default) {
              return "Default / undefined MACs";
            }
            return dnsAddRowHintFormatter(cell, "+ Add host reference here");
          },
          minWidth: 200,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
        {
          title: "MAC address",
          field: "mac_address",
          editor: canWrite ? "input" : false,
          editable: (cell) => !cell.getRow().getData().is_default,
          formatter: (cell) => {
            if (cell.getRow().getData().is_default) {
              return "*";
            }
            return dnsAddRowHintFormatter(cell, "00:50:56:aa:bb:cc");
          },
          minWidth: 170,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
        {
          title: "IP address",
          field: "ip_address",
          editor: canWrite ? "input" : false,
          editable: (cell) => !cell.getRow().getData().is_default,
          formatter: (cell) => {
            if (cell.getRow().getData().is_default) {
              return "DHCP";
            }
            return dnsAddRowHintFormatter(cell, "DHCP");
          },
          minWidth: 140,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
        {
          title: "Kickstart",
          field: "kickstart_id",
          editor: canWrite ? "list" : false,
          editorParams: { values: kickstartValues },
          formatter: (cell) => kickstartValues[cell.getValue()] || "No Kickstart",
          minWidth: 180,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
        {
          title: "Installer ISO",
          field: "installer_iso_path",
          editor: canWrite ? "list" : false,
          editorParams: { values: isoValues, autocomplete: true },
          formatter: (cell) => isoValues[cell.getValue()] || "No ISO selected",
          minWidth: 320,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
        {
          title: "Variables JSON",
          field: "variables_json",
          editor: canWrite ? "input" : false,
          editable: (cell) => !cell.getRow().getData().is_default,
          formatter: (cell) => {
            if (cell.getRow().getData().is_default) {
              return "";
            }
            return dnsAddRowHintFormatter(cell, '{"custom_name":"value"}');
          },
          minWidth: 240,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
        {
          title: "Enabled",
          field: "enabled",
          formatter: atlasoBooleanFormatter,
          editor: canWrite ? "tickCross" : false,
          hozAlign: "center",
          width: 100,
          headerSort: false,
          cellEdited: (cell) => autoSaveEsxiHost(cell, csrf),
        },
      ], "hostname"),
      rowFormatter: (row) => {
        const data = row.getData();
        markNewRecordRow(row, "hostname");
        row.getElement().classList.toggle("managed-record-row", Boolean(data.is_default));
      },
    };
    window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "direct-edit",
      permission: {
        allowed: canWrite,
        message: "You have read-only access to ESXi PXE host references.",
      },
      options: atlasoGridOptions24,
    }).table;
  } catch (error) {
    showEsxiHostError(error instanceof Error ? error.message : "Tabulator could not render. Showing the fallback table.");
  }
}

async function deleteEsxiInstallerIso(row, csrf) {
  const data = row.getData();
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name}?`,
    message: "This removes the installer ISO and clears host references to it. Generated PXE files change only after global appliance apply.",
    label: "Delete ISO",
  });
  if (!confirmed) return;
  const body = new FormData();
  body.set("csrf", csrf);
  body.set("installer_iso_path", data.path);
  const response = await fetch("/esxi-pxe/isos/delete", {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || "The installer ISO could not be deleted.");
  }
  window.location.assign("/network-boot#esxi-pxe-isos-panel");
}

function initializeEsxiInstallerIsosTable() {
  const element = document.getElementById("esxi-installer-isos-table");
  if (!(element instanceof HTMLElement)) return;
  const canWrite = element.dataset.canWrite === "true";
  window.AtlasoUiPatterns.createGrid({
    element,
    fallback: `#${element.dataset.fallbackId}`,
    pattern: "direct-edit",
    permission: {
      allowed: canWrite,
      message: "You have read-only access to ESXi installer ISOs.",
    },
    options: {
      data: JSON.parse(element.dataset.rows || "[]"),
      index: "path",
      layout: "fitColumns",
      height: "calc(100vh - 300px)",
      placeholder: "No installer ISOs found.",
      rowContextMenu: canWrite ? [
        {
          label: "Delete installer ISO",
          action: async (_event, row) => {
            try {
              await deleteEsxiInstallerIso(row, element.dataset.csrf || "");
            } catch (error) {
              showTransientGridStatus(error instanceof Error ? error.message : "The installer ISO could not be deleted.");
            }
          },
        },
      ] : false,
      columns: [
        { title: "Name", field: "name", minWidth: 260, widthGrow: 1.4 },
        { title: "Relative path", field: "relative_path", minWidth: 260, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>`, widthGrow: 1.2 },
        { title: "Source", field: "source_label", minWidth: 150 },
        { title: "Source date", field: "source_at", minWidth: 190 },
        { title: "Size", field: "size_bytes", minWidth: 120, formatter: (cell) => formatMonitorBytes(cell.getValue()) },
      ],
    },
  });
}

function initializeEsxiPxePreviewTable() {
  const element = document.getElementById("esxi-pxe-preview-table");
  if (!(element instanceof HTMLElement)) return;
  window.AtlasoUiPatterns.createGrid({
    element,
    fallback: `#${element.dataset.fallbackId}`,
    pattern: "read-only",
    options: {
      data: JSON.parse(element.dataset.rows || "[]"),
      layout: "fitColumns",
      height: "calc(100vh - 250px)",
      placeholder: "No rendered ESXi PXE artifacts.",
      columns: [
        { title: "Host", field: "hostname", minWidth: 190, frozen: true },
        { title: "PXELINUX", field: "pxelinux_config_path", minWidth: 280, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
        { title: "UEFI boot.cfg", field: "uefi_tftp_boot_cfg_path", minWidth: 280, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
        { title: "Kickstart URL", field: "kickstart_url", minWidth: 260, formatter: (cell) => `<code>${escapeHtml(cell.getValue() || "interactive installer")}</code>` },
        { title: "Image URL", field: "image_http_url", minWidth: 340, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
      ],
    },
  });
}

function initializeEsxiCustomVariablesTable() {
  const element = document.getElementById("esxi-custom-variables-table");
  if (!(element instanceof HTMLElement)) return;
  const rows = JSON.parse(element.dataset.rows || "[]");
  const canWrite = element.dataset.canWrite === "true";
  const columns = [
    {
      title: "Custom variable name",
      field: "name",
      formatter: (cell) => `<code>custom.${escapeHtml(cell.getValue())}</code>`,
      minWidth: 220,
    },
    {
      title: "Description",
      field: "description",
      formatter: (cell) => escapeHtml(cell.getValue() || "Not set"),
      minWidth: 260,
      widthGrow: 1.5,
    },
    {
      title: "Default value, if any",
      field: "default_value",
      formatter: (cell) => escapeHtml(cell.getValue() || "Not set"),
      minWidth: 260,
      widthGrow: 1.2,
    },
  ];
  if (!canWrite) {
    window.AtlasoUiPatterns.createGrid({
      element,
      pattern: "read-only",
      permission: {
        allowed: false,
        message: "You have read-only access to ESXi Kickstart custom variables.",
      },
      options: {
        data: rows,
        index: "id",
        layout: "fitColumns",
        height: "calc(100vh - 250px)",
        placeholder: "No custom Kickstart variables configured.",
        columns,
      },
    });
    return;
  }
  initializeAtlasoResourceWizard({
    elementId: "esxi-custom-variables-table",
    formSelector: "[data-esxi-custom-variable-wizard]",
    dialogId: "esxi-custom-variable-wizard-dialog",
    rows,
    newRow: { id: "__new__", name: "", description: "", default_value: "", is_new: true },
    includeNewRow: false,
    addLauncherSelector: "[data-esxi-custom-variable-add]",
    resourceName: "variable",
    createUrl: "/esxi-pxe/custom-variables",
    editUrl: (id) => `/esxi-pxe/custom-variables/${encodeURIComponent(id)}`,
    deleteUrl: (id) => `/esxi-pxe/custom-variables/${encodeURIComponent(id)}/delete`,
    deleteResource: true,
    editLabel: "Edit",
    deleteLabel: "Remove",
    createLabel: "Add custom variable",
    updateLabel: "Save custom variable",
    emptyMessage: "No custom Kickstart variables configured.",
    gridError: "Custom variable changes are unavailable because the interactive grid could not initialize.",
    actionErrorSelector: "#esxi-custom-variables-error",
    steps: [
      { id: "definition", title: "Define the custom variable", description: "Name and describe the non-secret value, then provide an optional default." },
      { id: "review", title: "Review the custom variable", description: "Confirm the Kickstart marker and optional default before saving." },
    ],
    reviewItems: [
      { label: "Kickstart marker", value: (form) => `{{custom.${form.elements.name.value.trim()}}}` },
      { label: "Description", field: "description" },
      { label: "Default value", field: "default_value" },
    ],
    deleteConfirmation: (data) => ({
      title: `Remove custom variable ${data.name}?`,
      message: `Kickstarts using {{custom.${data.name}}} will fail validation unless the variable is restored or the marker is removed.`,
      confirmLabel: "Remove custom variable",
      tone: "danger",
    }),
    onOpen: ({ context }) => {
      const title = document.querySelector("[data-esxi-custom-variable-modal-title]");
      if (title) title.textContent = context ? "Edit custom variable" : "Add custom variable";
    },
    onSaved: () => window.location.reload(),
    onDeleted: () => window.location.reload(),
    options: {
      layout: "fitColumns",
      height: "calc(100vh - 250px)",
      placeholder: "No custom Kickstart variables configured.",
      columns,
    },
  });
}

function initializeHostsFileEditor() {
  document.querySelectorAll(".hosts-file-input").forEach((input) => {
    if (!(input instanceof HTMLInputElement)) {
      return;
    }
    input.addEventListener("change", async () => {
      const editor = document.getElementById(input.dataset.editorId || "");
      if (!(editor instanceof HTMLTextAreaElement)) {
        return;
      }
      const file = input.files?.[0];
      if (!file) {
        return;
      }
      const fileText = await file.text();
      if (window.AtlasoMonaco && typeof window.AtlasoMonaco.setValue === "function") {
        window.AtlasoMonaco.setValue(editor, fileText);
        window.AtlasoMonaco.focus(editor);
        return;
      }
      editor.value = fileText;
      editor.dispatchEvent(new Event("input", { bubbles: true }));
      editor.focus();
    });
  });
}

function initializeMonacoEditors() {
  if (!window.AtlasoMonaco || typeof window.AtlasoMonaco.enhanceTextarea !== "function") {
    return;
  }
  document.querySelectorAll("textarea[data-monaco-editor]").forEach((textarea) => {
    if (!(textarea instanceof HTMLTextAreaElement)) {
      return;
    }
    window.AtlasoMonaco.enhanceTextarea(textarea, {
      language: textarea.dataset.monacoLanguage || "atlaso-hosts",
    });
  });
}

function initializeKickstartCollection() {
  const element = document.getElementById("esxi-kickstarts-table");
  if (!(element instanceof HTMLElement)) return;
  const rows = JSON.parse(element.dataset.rows || "[]");
  const columns = [
    {
      title: "Name",
      field: "name",
      formatter: (cell) => cell.getRow().getData().is_new
        ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add Kickstart</button>'
        : escapeHtml(cell.getValue()),
      minWidth: 180,
    },
    { title: "Description", field: "description", minWidth: 220, widthGrow: 1.4 },
    { title: "Content hash", field: "content_hash", formatter: (cell) => cell.getRow().getData().is_new ? "" : `<code>${escapeHtml(String(cell.getValue() || "").slice(0, 12))}</code>`, minWidth: 140 },
    { title: "Drift", field: "drift_state", formatter: (cell) => escapeHtml(String(cell.getValue() || "").replaceAll("_", " ")), minWidth: 175 },
    { title: "Updated", field: "updated_at", minWidth: 180 },
    { title: "Enabled", field: "enabled", formatter: atlasoBooleanFormatter, width: 95, hozAlign: "center" },
  ];
  if (element.dataset.canWrite !== "true") {
    window.AtlasoUiPatterns.createGrid({
      element,
      pattern: "read-only",
      permission: { allowed: false, message: "You have read-only access to Kickstarts." },
      options: { data: rows, index: "id", layout: "fitColumns", height: "360px", columns },
    });
    return;
  }
  const form = document.querySelector("[data-kickstart-wizard]");
  if (!(element instanceof HTMLElement) || !(form instanceof HTMLFormElement)) return;
  const source = form.elements.namedItem("content");
  if (!(source instanceof HTMLTextAreaElement)) return;
  const updateSummary = (table) => {
    const summary = document.querySelector("[data-esxi-pxe-summary]");
    if (!(summary instanceof HTMLElement) || !table) return;
    const kickstartCount = table.getData().filter((row) => !row.is_new).length;
    const isoCount = Number(summary.dataset.isoCount || 0);
    summary.textContent = `${kickstartCount} Kickstarts / ${isoCount} ISOs`;
  };
  const submitAction = (action, id) => {
    const actionForm = document.createElement("form");
    actionForm.method = "post";
    actionForm.action = `/esxi-pxe/kickstarts/${id}/${action}`;
    actionForm.innerHTML = `<input type="hidden" name="csrf" value="${escapeHtml(element.dataset.csrf || "")}">`;
    document.body.append(actionForm);
    actionForm.submit();
  };
  const collection = initializeAtlasoResourceWizard({
    elementId: "esxi-kickstarts-table",
    formSelector: "[data-kickstart-wizard]",
    dialogId: "kickstart-wizard-dialog",
    rows,
    newRow: { id: "__new__", is_new: true, name: "" },
    resourceName: "kickstart",
    recordField: "record_id",
    createUrl: "/esxi-pxe/kickstarts",
    editUrl: (id) => `/esxi-pxe/kickstarts/${id}`,
    deleteUrl: (id) => `/esxi-pxe/kickstarts/${id}/delete`,
    deleteResource: true,
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name}?`,
      message: "This removes the Kickstart from desired state and clears host references. Generated runtime files change only after global appliance apply.",
      confirmLabel: "Delete Kickstart",
      tone: "danger",
    }),
    editLabel: "Edit Kickstart",
    deleteLabel: "Delete Kickstart",
    createLabel: "Save Kickstart",
    updateLabel: "Save Kickstart",
    emptyMessage: "No Kickstarts configured.",
    gridError: "Kickstart changes are unavailable because the interactive grid could not initialize.",
    steps: [
      { id: "identity", title: "Identify the Kickstart", description: "Name and describe the database-owned source." },
      { id: "source", title: "Edit Kickstart source", description: "Use the ESXi Kickstart language and Atlaso variables." },
      { id: "state", title: "Choose desired availability", description: "Enabled source is generated during global appliance apply." },
      { id: "review", title: "Review the Kickstart", description: "Confirm source variables and desired state." },
    ],
    extraActions: [
      {
        label: "Duplicate Kickstart",
        disabled: (row) => row.getData().is_new,
        action: (_event, row) => document.getElementById(`kickstart-duplicate-${row.getData().id}`)?.requestSubmit(),
      },
      {
        label: "Validate Kickstart",
        disabled: (row) => row.getData().is_new,
        action: (_event, row) => submitAction("validate", row.getData().id),
      },
      {
        label: "Download Kickstart",
        disabled: (row) => row.getData().is_new,
        action: (_event, row) => { window.location.href = `/esxi-pxe/kickstarts/${row.getData().id}/download`; },
      },
    ],
    onOpen: ({ context }) => {
      form.querySelector("[data-kickstart-modal-title]").textContent = context ? "Edit Kickstart" : "Add Kickstart";
      window.AtlasoMonaco.setValue(source, context?.content ?? source.defaultValue);
      collection?.wizard?.markClean();
    },
    validateStep: ({ step }) => {
      if (step?.id === "source" && !window.AtlasoMonaco.getValue(source).trim()) {
        return { valid: false, field: source, message: "Kickstart source is required." };
      }
      return { valid: true };
    },
    prepareFormData: ({ body }) => body.set("content", window.AtlasoMonaco.getValue(source)),
    prepareReview: () => {
      form.querySelector('[data-kickstart-review="name"]').textContent = form.elements.name.value;
      form.querySelector('[data-kickstart-review="description"]').textContent = form.elements.description.value || "None";
      form.querySelector('[data-kickstart-review="state"]').textContent = form.elements.enabled.checked ? "Enabled" : "Disabled";
      form.querySelector('[data-kickstart-review="variables"]').textContent = [...window.AtlasoMonaco.getValue(source).matchAll(/\{\{\s*([^}]+)\s*\}\}/g)]
        .map((match) => match[1].trim()).join(", ") || "None";
    },
    onSaved: ({ table }) => updateSummary(table),
    onDeleted: ({ table }) => updateSummary(table),
    options: {
      layout: "fitColumns",
      height: "360px",
      rowHeight: 30,
      placeholder: "No Kickstarts configured.",
      columns,
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
  form.querySelector("[data-kickstart-import]")?.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (file) {
      window.AtlasoMonaco.setValue(source, await file.text());
      window.AtlasoMonaco.focus(source);
    }
  });
  document.addEventListener("click", (event) => {
    const trigger = event.target instanceof Element ? event.target.closest("[data-kickstart-edit-id]") : null;
    if (!trigger || !collection?.wizard) return;
    const row = rows.find((item) => String(item.id) === trigger.dataset.kickstartEditId);
    if (row) collection.wizard.open({ context: row, launcher: trigger });
  });
}

function initializeZoneEditors() {
  document.querySelectorAll(".zone-editor-form").forEach((form) => {
    const editor = form.querySelector(".zone-code-editor");
    const input = form.querySelector(".zone-file-input");
    if (!(form instanceof HTMLFormElement) || !(editor instanceof HTMLElement) || !(input instanceof HTMLInputElement)) {
      return;
    }
    const syncEditor = () => {
      input.value = editor.innerText.replace(/\u00a0/g, " ");
    };
    editor.addEventListener("input", syncEditor);
    form.addEventListener("submit", syncEditor);
    syncEditor();
  });
}

function requestConfirmation(options = {}) {
  const modal = document.getElementById("confirm-modal");
  const title = document.getElementById("confirm-modal-title");
  const message = document.getElementById("confirm-modal-message");
  const detailGroup = document.getElementById("confirm-modal-detail-group");
  const detailLabel = document.getElementById("confirm-modal-detail-label");
  const detail = document.getElementById("confirm-modal-detail");
  const confirmButton = document.getElementById("confirm-modal-confirm");
  if (!(modal instanceof HTMLDialogElement) || !(title instanceof HTMLElement) || !(message instanceof HTMLElement) || !(confirmButton instanceof HTMLButtonElement)) {
    return Promise.resolve(false);
  }

  title.textContent = options.title || "Confirm action";
  message.textContent = options.message || "This action cannot be undone.";
  confirmButton.textContent = options.label || "Confirm";
  const hasDetail = Boolean(options.detail) && detailGroup instanceof HTMLElement && detail instanceof HTMLElement;
  modal.classList.toggle("has-confirm-detail", hasDetail);
  if (detailGroup instanceof HTMLElement) detailGroup.classList.toggle("hidden", !hasDetail);
  if (detailLabel instanceof HTMLElement) detailLabel.textContent = options.detailLabel || "Details";
  if (detail instanceof HTMLElement) detail.textContent = hasDetail ? String(options.detail) : "";

  return new Promise((resolve) => {
    const handleClose = () => {
      modal.removeEventListener("close", handleClose);
      modal.classList.remove("has-confirm-detail");
      if (detailGroup instanceof HTMLElement) detailGroup.classList.add("hidden");
      if (detail instanceof HTMLElement) detail.textContent = "";
      resolve(modal.returnValue === "confirm");
    };
    modal.addEventListener("close", handleClose);
    modal.showModal();
  });
}

function initializeAccountMenu() {
  const menu = document.querySelector("[data-account-menu]");
  const aboutModal = document.getElementById("about-modal");
  const aboutOpen = document.querySelector("[data-about-open]");
  const aboutClose = document.querySelector("[data-about-close]");
  if (!(menu instanceof HTMLDetailsElement)) {
    return;
  }

  const closeMenu = () => {
    menu.open = false;
  };
  document.addEventListener("click", (event) => {
    if (!menu.contains(event.target)) {
      closeMenu();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.open) {
      closeMenu();
    }
  });
  menu.querySelectorAll("form").forEach((form) => {
    form.addEventListener("submit", closeMenu);
  });

  if (aboutOpen instanceof HTMLButtonElement && aboutModal instanceof HTMLDialogElement) {
    aboutOpen.addEventListener("click", () => {
      closeMenu();
      aboutModal.showModal();
    });
  }
  if (aboutClose instanceof HTMLButtonElement && aboutModal instanceof HTMLDialogElement) {
    aboutClose.addEventListener("click", () => aboutModal.close());
  }
  if (aboutModal instanceof HTMLDialogElement) {
    aboutModal.addEventListener("click", (event) => {
      if (event.target === aboutModal) {
        aboutModal.close();
      }
    });
  }
}

function initializeConfirmationModals() {
  document.querySelectorAll("form[data-confirm-modal]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.confirmModalInitialized === "true") {
      return;
    }
    form.dataset.confirmModalInitialized = "true";
    form.addEventListener("submit", async (event) => {
      if (form.dataset.confirmed === "1") {
        delete form.dataset.confirmed;
        return;
      }
      event.preventDefault();
      const confirmed = await requestConfirmation({
        title: form.dataset.confirmTitle,
        message: form.dataset.confirmMessage,
        label: form.dataset.confirmLabel,
      });
      if (!confirmed) {
        return;
      }
      form.dataset.confirmed = "1";
      form.requestSubmit();
    });
  });
}

function setAutosaveStatus(element, message, state = "idle") {
  if (!element) {
    return;
  }
  element.textContent = message;
  element.dataset.state = state;
}

function updateApplianceApplySidebar(payload = {}) {
  updateCurrentPageApplyNotice(payload);
  const sidebar = document.querySelector("[data-appliance-apply-sidebar]");
  if (!(sidebar instanceof HTMLElement)) {
    return;
  }
  const pendingCount = Number(payload.pending_count || 0);
  const hasPending = pendingCount > 0;
  const title = sidebar.querySelector("[data-appliance-apply-sidebar-title]");
  const detail = sidebar.querySelector("[data-appliance-apply-sidebar-detail]");
  const badge = sidebar.querySelector("[data-appliance-apply-sidebar-badge]");
  sidebar.dataset.pendingCount = String(pendingCount);
  sidebar.classList.toggle("hidden", !hasPending);
  sidebar.classList.add("pending");
  sidebar.classList.remove("current");
  if (title instanceof HTMLElement) {
    title.textContent = "Review appliance changes";
  }
  if (detail instanceof HTMLElement) {
    detail.textContent = `${pendingCount} pending ${pendingCount === 1 ? "unit" : "units"}`;
  }
  if (badge instanceof HTMLElement) {
    badge.textContent = "pending";
  }
}

function updateCurrentPageApplyNotice(payload = {}) {
  const mainPane = document.querySelector("main.main-pane[data-page-apply-unit]");
  if (!(mainPane instanceof HTMLElement)) {
    return;
  }
  const unitId = mainPane.dataset.pageApplyUnit || "";
  const units = Array.isArray(payload.units) ? payload.units : [];
  const status = units.find((unit) => unit?.id === unitId);
  if (status) {
    updatePageApplyNotice(status);
  }
}

function updatePageApplyNotice(status = {}) {
  let notice = document.querySelector(".page-apply-notice");
  if (!status.changed) {
    notice?.remove();
    return;
  }
  const mainPane = document.querySelector("main.main-pane");
  const header = mainPane?.querySelector("header.topbar");
  if (!(mainPane instanceof HTMLElement) || !(header instanceof HTMLElement)) return;
  if (!(notice instanceof HTMLElement)) {
    notice = document.createElement("div");
    notice.className = "page-apply-notice";
    const main = document.createElement("div");
    main.className = "page-apply-notice-main";
    const pill = document.createElement("span");
    pill.className = "status-pill";
    const title = document.createElement("strong");
    const detail = document.createElement("span");
    detail.textContent = "Review and submit them from the global apply workflow.";
    main.append(pill, title, detail);
    const review = document.createElement("a");
    review.className = "button secondary compact-button";
    review.href = "/dashboard#appliance-apply-review";
    review.dataset.applianceApplyOpen = "";
    review.textContent = "Review appliance changes";
    notice.append(main, review);
    header.insertAdjacentElement("afterend", notice);
  }
  const hasErrors = Array.isArray(status.validation_errors) && status.validation_errors.length > 0;
  notice.classList.toggle("needs-attention", hasErrors);
  notice.classList.toggle("pending", !hasErrors);
  const pill = notice.querySelector(".status-pill");
  if (pill instanceof HTMLElement) {
    pill.className = `status-pill ${status.pill || "warn"}`;
    pill.textContent = status.state || (hasErrors ? "needs attention" : "pending");
  }
  const title = notice.querySelector("strong");
  if (title instanceof HTMLElement) title.textContent = `${status.label || "Appliance component"} has pending appliance changes`;
}

async function refreshApplianceApplySidebar() {
  if (!document.querySelector("[data-appliance-apply-sidebar]")) {
    return;
  }
  const response = await fetch("/appliance-apply/status", {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    return;
  }
  updateApplianceApplySidebar(await response.json());
}

function initializeAutosaveForms(root = document) {
  root.querySelectorAll("[data-autosave-form]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.autosaveInitialized === "1") return;
    form.dataset.autosaveInitialized = "1";
    form.addEventListener("atlaso:autosave-success", (event) => {
      updateDerivedListenAddressSummary(form, event.detail || {});
    });
    const statusElement = document.getElementById(form.dataset.autosaveStatusId || "");
    const inputAutosave = form.dataset.autosaveTrigger !== "change";
    let timer = 0;
    let inFlightRequest = null;

    const selectedFiles = () =>
      Array.from(form.querySelectorAll('input[type="file"]')).flatMap((input) =>
        input instanceof HTMLInputElement && input.files ? Array.from(input.files) : [],
      );

    const clearSelectedFileInputs = () => {
      form.querySelectorAll('input[type="file"]').forEach((input) => {
        if (input instanceof HTMLInputElement) {
          input.value = "";
        }
      });
    };

    const uploadProgress = () => form.querySelector("[data-autosave-upload-progress]");

    const resetUploadProgress = () => {
      const progress = uploadProgress();
      if (progress instanceof HTMLProgressElement) {
        progress.hidden = true;
        progress.value = 0;
        progress.max = 100;
      }
    };

    const autosaveErrorFromText = (text) => {
      try {
        const payload = JSON.parse(text || "{}");
        if (payload.detail) {
          return String(payload.detail);
        }
      } catch {
        // Fall through to the generic message below.
      }
      return "Settings could not be saved.";
    };

    const postWithFetch = async (actionUrl, formData) => {
      const controller = new AbortController();
      const request = { abort: () => controller.abort() };
      inFlightRequest = request;
      const response = await fetch(new URL(actionUrl, window.location.href), {
        method: form.method || "POST",
        body: formData,
        credentials: "same-origin",
        headers: { "X-Atlaso-Autosave": "1" },
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(autosaveErrorFromText(await response.text()));
      }
      return { payload: await response.json(), request };
    };

    const postWithUploadProgress = (actionUrl, formData, files) =>
      new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        const request = { abort: () => xhr.abort() };
        inFlightRequest = request;
        const progress = uploadProgress();
        if (progress instanceof HTMLProgressElement) {
          progress.hidden = false;
          progress.value = 0;
          progress.max = 100;
        }
        xhr.open((form.method || "POST").toUpperCase(), new URL(actionUrl, window.location.href).toString());
        xhr.withCredentials = true;
        xhr.setRequestHeader("X-Atlaso-Autosave", "1");
        xhr.upload.addEventListener("progress", (event) => {
          if (!(progress instanceof HTMLProgressElement)) {
            return;
          }
          if (event.lengthComputable && event.total > 0) {
            const percent = Math.max(1, Math.min(100, Math.round((event.loaded / event.total) * 100)));
            progress.value = percent;
            setAutosaveStatus(statusElement, `Uploading ${files[0]?.name || "file"} (${percent}%)...`, "saving");
          } else {
            progress.removeAttribute("value");
            setAutosaveStatus(statusElement, `Uploading ${files[0]?.name || "file"}...`, "saving");
          }
        });
        xhr.addEventListener("load", () => {
          if (xhr.status < 200 || xhr.status >= 300) {
            reject(new Error(autosaveErrorFromText(xhr.responseText)));
            return;
          }
          try {
            resolve({ payload: JSON.parse(xhr.responseText || "{}"), request });
          } catch {
            reject(new Error("Settings could not be saved."));
          }
        });
        xhr.addEventListener("error", () => reject(new Error("Settings could not be saved.")));
        xhr.addEventListener("abort", () => reject(new DOMException("Request aborted.", "AbortError")));
        xhr.send(formData);
      });

    const save = async () => {
      window.clearTimeout(timer);
      if (inFlightRequest) {
        inFlightRequest.abort();
      }
      const files = selectedFiles();
      const hasFiles = files.length > 0;
      const uploadedFileName = files[0]?.name || "file";
      setAutosaveStatus(statusElement, hasFiles ? `Uploading ${files[0]?.name || "file"}...` : "Saving changes...", "saving");
      try {
        const actionUrl = form.getAttribute("action") || window.location.href;
        const formData = new FormData(form);
        const { payload, request } = hasFiles
          ? await postWithUploadProgress(actionUrl, formData, files)
          : await postWithFetch(actionUrl, formData);
        if (payload.appliance_apply_status) updatePageApplyNotice(payload.appliance_apply_status);
        form.dispatchEvent(new CustomEvent("atlaso:autosave-success", { detail: payload }));
        if (hasFiles) {
          clearSelectedFileInputs();
        }
        setAutosaveStatus(
          statusElement,
          hasFiles
            ? `Uploaded ${payload.tool_archive_name || payload.download_token_name || uploadedFileName}.`
            : payload.updated_at
              ? `Saved automatically at ${new Date(payload.updated_at).toLocaleTimeString()}.`
              : "Saved automatically.",
          "saved",
        );
        if (inFlightRequest === request) {
          inFlightRequest = null;
        }
        resetUploadProgress();
        return { valid: true, payload };
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") {
          return { valid: false, message: "Save was superseded by a newer change." };
        }
        inFlightRequest = null;
        resetUploadProgress();
        const message = error instanceof Error ? error.message : "Settings could not be saved.";
        setAutosaveStatus(statusElement, message, "error");
        return { valid: false, message };
      } finally {
        if (!hasFiles) {
          resetUploadProgress();
        }
      }
    };
    form.atlasoSaveNow = save;

    const scheduleSave = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(save, 350);
    };

    form.addEventListener("input", (event) => {
      if (!inputAutosave) {
        return;
      }
      if (event.target instanceof HTMLInputElement && event.target.type === "file") {
        return;
      }
      scheduleSave();
    });
    form.addEventListener("change", scheduleSave);
    form.addEventListener("tag-editor:change", scheduleSave);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      save();
    });
  });
}

function initializeSwitchFields(root = document) {
  root.querySelectorAll(".switch-field").forEach((field) => {
    if (!(field instanceof HTMLLabelElement)) {
      return;
    }
    if (field.dataset.switchFieldInitialized === "1") return;
    field.dataset.switchFieldInitialized = "1";
    const input = field.querySelector(".switch-input");
    if (!(input instanceof HTMLInputElement) || input.type !== "checkbox") {
      return;
    }
    field.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement) || target === input || target.closest(".help-icon")) {
        return;
      }
      event.preventDefault();
      input.checked = !input.checked;
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
  });
}

function initializeNonTabbableHelperControls() {
  document.querySelectorAll(".help-icon, .password-toggle").forEach((control) => {
    if (!(control instanceof HTMLElement)) {
      return;
    }
    control.setAttribute("tabindex", "-1");
  });
  document.addEventListener("mousedown", (event) => {
    if (event.target instanceof Element && event.target.closest(".help-icon")) {
      event.preventDefault();
    }
  }, true);
}

function initializeSecretToggles() {
  document.querySelectorAll("[data-secret-toggle]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    const display = button.closest(".secret-value")?.querySelector("[data-secret-display]");
    if (!(display instanceof HTMLElement)) {
      return;
    }
    const mask = display.dataset.secretMask || "hidden";
    const secretText = display.dataset.secretText || "";
    display.textContent = mask;
    button.addEventListener("click", () => {
      const nextVisible = button.getAttribute("aria-pressed") !== "true";
      button.setAttribute("aria-pressed", nextVisible ? "true" : "false");
      button.setAttribute("aria-label", `${nextVisible ? "Hide" : "Show"} secrets key source`);
      display.textContent = nextVisible ? secretText : mask;
    });
  });
}

function updateFirewallDesiredState(payload = {}) {
  if (payload.enabled !== undefined) {
    document.querySelectorAll("[data-firewall-enabled-status]").forEach((status) => {
      if (!(status instanceof HTMLElement)) {
        return;
      }
      const enabled = Boolean(payload.enabled);
      status.textContent = enabled ? "enabled" : "disabled";
      status.classList.toggle("good", enabled);
      status.classList.toggle("muted", !enabled);
    });
  }

  const validationPanel = document.querySelector("[data-firewall-validation-panel]");
  if (!(validationPanel instanceof HTMLElement)) {
    return;
  }
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  const valid = payload.valid !== undefined ? Boolean(payload.valid) : errors.length === 0;
  const status = validationPanel.querySelector("[data-firewall-validation-status]");
  if (status instanceof HTMLElement) {
    status.textContent = valid ? "valid" : "needs attention";
    status.classList.toggle("good", valid);
    status.classList.toggle("warn", !valid);
  }
  const previewAnchor = validationPanel.querySelector("[data-config-preview-row]");
  let errorList = validationPanel.querySelector("[data-firewall-validation-errors]");
  let message = validationPanel.querySelector("[data-firewall-validation-message]");
  if (valid) {
    if (errorList instanceof HTMLElement) {
      errorList.remove();
    }
    if (!(message instanceof HTMLElement)) {
      message = document.createElement("p");
      message.className = "muted";
      message.setAttribute("data-firewall-validation-message", "");
      validationPanel.insertBefore(message, previewAnchor);
    }
    message.textContent =
      "The desired firewall state passes Atlaso validation. Appliance validation still runs through the allowlisted nftables helper before apply.";
  } else {
    if (message instanceof HTMLElement) {
      message.remove();
    }
    if (!(errorList instanceof HTMLElement)) {
      errorList = document.createElement("ul");
      errorList.className = "error-list";
      errorList.setAttribute("data-firewall-validation-errors", "");
      validationPanel.insertBefore(errorList, previewAnchor);
    }
    errorList.innerHTML = "";
    errors.forEach((error) => {
      const item = document.createElement("li");
      item.textContent = error;
      errorList.append(item);
    });
  }
  const configPath = validationPanel.querySelector("[data-firewall-config-path]");
  if (configPath instanceof HTMLElement && typeof payload.config_path === "string") {
    configPath.textContent = payload.config_path;
  }
  const configPreview = validationPanel.querySelector("[data-firewall-config-preview]");
  if (configPreview instanceof HTMLElement && typeof payload.config_preview === "string") {
    configPreview.textContent = payload.config_preview;
    highlightConfigPreviewElement(configPreview);
  }
  const refreshStatus = validationPanel.querySelector("[data-firewall-validation-refresh]");
  if (refreshStatus instanceof HTMLElement) {
    const updatedAt = typeof payload.updated_at === "string" ? new Date(payload.updated_at) : new Date();
    const timestamp = Number.isNaN(updatedAt.getTime()) ? new Date() : updatedAt;
    refreshStatus.textContent = `Preview refreshed ${timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}.`;
    refreshStatus.dataset.state = "saved";
  }
  validationPanel.classList.remove("validation-panel-refreshed");
  void validationPanel.offsetWidth;
  validationPanel.classList.add("validation-panel-refreshed");
}

const FIREWALL_SOURCE_GROUP_SELECTION_KEY = "atlaso:firewall:active-source-group";

function rememberFirewallSourceGroup(groupId) {
  try {
    window.localStorage.setItem(FIREWALL_SOURCE_GROUP_SELECTION_KEY, groupId || "");
  } catch {
    // Remembering the selected editor is only a convenience.
  }
}

function storedFirewallSourceGroup() {
  try {
    return window.localStorage.getItem(FIREWALL_SOURCE_GROUP_SELECTION_KEY) || "";
  } catch {
    return "";
  }
}

function showFirewallSourceGroupEditor(manager, groupId) {
  manager.querySelectorAll("[data-source-group-editor]").forEach((editor) => {
    if (!(editor instanceof HTMLElement)) {
      return;
    }
    const active = editor.dataset.sourceGroupId === groupId;
    editor.classList.toggle("active", active);
    if (active) {
      editor.removeAttribute("hidden");
    } else {
      editor.setAttribute("hidden", "");
    }
  });
}

function triggerSourceGroupAutosave(form) {
  if (form instanceof HTMLFormElement) {
    form.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

function addSourceGroupEntry(form, value) {
  const list = form.querySelector("[data-source-group-entry-list]");
  const entry = String(value || "").trim();
  if (!(list instanceof HTMLElement) || !entry) {
    return;
  }
  const existingRows = Array.from(list.querySelectorAll(".source-group-entry-row"));
  if (entry.toLowerCase() === "any") {
    existingRows.forEach((row) => row.remove());
  } else {
    existingRows.forEach((row) => {
      const input = row.querySelector('input[name="group_entries"]');
      if (input instanceof HTMLInputElement && input.value.trim().toLowerCase() === "any") {
        row.remove();
      }
    });
  }
  const duplicate = Array.from(list.querySelectorAll('input[name="group_entries"]')).some((input) => input instanceof HTMLInputElement && input.value.trim().toLowerCase() === entry.toLowerCase());
  if (duplicate) {
    triggerSourceGroupAutosave(form);
    return;
  }
  const row = document.createElement("div");
  row.className = "source-group-entry-row";
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "group_entries";
  input.value = entry;
  const label = document.createElement("span");
  label.className = "source-group-entry-label";
  label.textContent = entry;
  const remove = document.createElement("button");
  remove.className = "icon-button source-group-entry-remove";
  remove.type = "button";
  remove.dataset.sourceGroupRemoveEntry = "";
  remove.setAttribute("aria-label", "Remove entry");
  remove.textContent = "x";
  row.append(input, label, remove);
  list.append(row);
  triggerSourceGroupAutosave(form);
}

function ensureSourceGroupHasEntry(form) {
  const list = form.querySelector("[data-source-group-entry-list]");
  if (!(list instanceof HTMLElement) || list.querySelector("[name='group_entries']")) {
    return;
  }
  addSourceGroupEntry(form, "any");
}

function initializeFirewallSourceGroupManager() {
  const renameModal = document.getElementById("firewall-rename-group-modal");
  const renameForm = renameModal instanceof HTMLDialogElement ? renameModal.querySelector("form") : null;
  const renameGroupId = renameForm instanceof HTMLFormElement ? renameForm.querySelector('input[name="group_id"]') : null;
  const renameGroupName = renameForm instanceof HTMLFormElement ? renameForm.querySelector('input[name="group_name"]') : null;
  if (renameModal instanceof HTMLDialogElement) {
    renameModal.querySelectorAll("[data-firewall-rename-group-cancel]").forEach((button) => {
      button.addEventListener("click", () => renameModal.close());
    });
  }

  document.querySelectorAll("[data-source-group-manager]").forEach((manager) => {
    if (!(manager instanceof HTMLElement)) {
      return;
    }
    const select = manager.querySelector("[data-source-group-select]");
    if (!(select instanceof HTMLSelectElement)) {
      return;
    }
    const storedGroup = storedFirewallSourceGroup();
    if (storedGroup && Array.from(select.options).some((option) => option.value === storedGroup)) {
      select.value = storedGroup;
    }
    showFirewallSourceGroupEditor(manager, select.value);
    select.addEventListener("change", () => {
      rememberFirewallSourceGroup(select.value);
      showFirewallSourceGroupEditor(manager, select.value);
    });
  });

  document.querySelectorAll("[data-source-group-editor]").forEach((editor) => {
    if (!(editor instanceof HTMLElement)) {
      return;
    }
    const form = editor.querySelector('form[data-firewall-source-groups]');
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    form.addEventListener("input", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLInputElement) || target.name !== "group_name") {
        return;
      }
      const manager = editor.closest("[data-source-group-manager]");
      const select = manager?.querySelector("[data-source-group-select]");
      const groupId = editor.dataset.sourceGroupId || "";
      const option = select instanceof HTMLSelectElement ? Array.from(select.options).find((item) => item.value === groupId) : null;
      if (option) {
        option.textContent = target.value.trim() || groupId;
      }
    });
    form.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }
      if (target.matches("[data-source-group-remove-entry]")) {
        event.preventDefault();
        target.closest(".source-group-entry-row")?.remove();
        ensureSourceGroupHasEntry(form);
        triggerSourceGroupAutosave(form);
        return;
      }
      if (target.matches("[data-source-group-add-any]")) {
        event.preventDefault();
        addSourceGroupEntry(form, "any");
        return;
      }
      if (target.matches("[data-source-group-add-cidr]")) {
        event.preventDefault();
        const input = form.querySelector("[data-source-group-cidr-input]");
        if (input instanceof HTMLInputElement) {
          addSourceGroupEntry(form, input.value);
          input.value = "";
          input.focus();
        }
        return;
      }
      if (target.matches("[data-source-group-add-ref]")) {
        event.preventDefault();
        const select = form.querySelector("[data-source-group-ref-select]");
        if (select instanceof HTMLSelectElement && select.value) {
          addSourceGroupEntry(form, select.value);
          select.value = "";
        }
      }
    });
  });

  document.querySelectorAll("[data-source-group-rename]").forEach((button) => {
    button.addEventListener("click", () => {
      if (!(renameModal instanceof HTMLDialogElement) || !(renameGroupId instanceof HTMLInputElement) || !(renameGroupName instanceof HTMLInputElement)) {
        return;
      }
      renameGroupId.value = button instanceof HTMLElement ? button.dataset.groupId || "" : "";
      renameGroupName.value = button instanceof HTMLElement ? button.dataset.groupName || "" : "";
      renameModal.showModal();
      renameGroupName.focus();
      renameGroupName.select();
    });
  });
}

function initializeFirewallSettings(root = document) {
  root.querySelectorAll('form[action="/firewall/settings"]').forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.firewallSettingsInitialized === "1") return;
    form.dataset.firewallSettingsInitialized = "1";
    form.addEventListener("atlaso:autosave-success", (event) => {
      updateFirewallDesiredState(event.detail || {});
    });
  });
  root.querySelectorAll("[data-firewall-source-groups]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.firewallGroupsInitialized === "1") return;
    form.dataset.firewallGroupsInitialized = "1";
    form.addEventListener("atlaso:autosave-success", (event) => {
      updateFirewallDesiredState(event.detail || {});
    });
  });
}

function updateValidationList(list, items = []) {
  if (!(list instanceof HTMLElement)) {
    return;
  }
  list.innerHTML = "";
  const useRoleListItems = list.getAttribute("role") === "list";
  items.forEach((message) => {
    const item = document.createElement(useRoleListItems ? "div" : "li");
    if (useRoleListItems) {
      item.setAttribute("role", "listitem");
    }
    item.textContent = message;
    list.append(item);
  });
  list.classList.toggle("hidden", items.length === 0);
}

function updateApplianceSettingsDhcpDns(payload = {}) {
  const servers = Array.isArray(payload.observed_dhcp_dns_servers) ? payload.observed_dhcp_dns_servers.filter(Boolean) : [];
  const usingDhcp = payload.resolver_mode === "dhcp";
  const textarea = document.querySelector("[data-appliance-settings-external-dns]");
  if (textarea instanceof HTMLTextAreaElement) {
    textarea.placeholder = usingDhcp && servers.length ? `DHCP: ${servers.join(", ")}` : "";
  }
  const sourceList = document.querySelector("[data-appliance-settings-dhcp-dns]");
  if (!(sourceList instanceof HTMLElement)) {
    return;
  }
  sourceList.classList.toggle("hidden", !usingDhcp);
  const values = sourceList.querySelector("[data-appliance-settings-dhcp-dns-values]");
  if (!(values instanceof HTMLElement)) {
    return;
  }
  values.innerHTML = "";
  if (!servers.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "No lease resolver servers reported yet.";
    values.append(empty);
    return;
  }
  servers.forEach((server) => {
    const code = document.createElement("code");
    code.textContent = server;
    values.append(code);
  });
}

function updateApplianceSettingsValidation(payload = {}) {
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  const warnings = Array.isArray(payload.validation_warnings) ? payload.validation_warnings : [];
  const valid = payload.valid !== undefined ? Boolean(payload.valid) : errors.length === 0;
  const pill = document.querySelector("[data-appliance-settings-valid-pill]");
  if (pill instanceof HTMLElement) {
    pill.textContent = valid ? "valid" : "needs attention";
    pill.classList.toggle("good", valid);
    pill.classList.toggle("warn", !valid);
  }
  updateValidationList(document.querySelector("[data-appliance-settings-errors]"), errors);
  updateValidationList(document.querySelector("[data-appliance-settings-warnings]"), warnings);

  const configPath = document.querySelector("[data-appliance-settings-config-path]");
  if (configPath instanceof HTMLElement && typeof payload.config_path === "string") {
    configPath.textContent = payload.config_path;
  }
  const preview = document.querySelector("[data-appliance-settings-preview]");
  if (preview instanceof HTMLElement && typeof payload.config_preview === "string") {
    preview.textContent = payload.config_preview;
    highlightConfigPreviewElement(preview);
  }
  const management = document.querySelector("[data-appliance-settings-management]");
  if (management instanceof HTMLElement && payload.management_interface) {
    const name = payload.management_interface.name || "not found";
    const ip = payload.management_interface.ip ? ` / ${payload.management_interface.ip}` : "";
    management.textContent = `${name}${ip}`;
  }
  const rootSsh = document.querySelector("[data-appliance-settings-root-ssh]");
  if (rootSsh instanceof HTMLElement && payload.root_ssh_enabled !== undefined) {
    rootSsh.textContent = payload.root_ssh_enabled ? "enabled" : "disabled";
  }
  const webTerminal = document.querySelector("[data-appliance-settings-web-terminal]");
  if (webTerminal instanceof HTMLElement && payload.web_terminal_enabled !== undefined) {
    const addresses = Array.isArray(payload.web_terminal_addresses) && payload.web_terminal_addresses.length
      ? ` / ${payload.web_terminal_addresses.join(", ")}`
      : "";
    webTerminal.textContent = `${payload.web_terminal_enabled ? "enabled" : "disabled"}${addresses}`;
  }
  if (payload.vmware_ceip_enabled !== undefined) {
    const enabled = Boolean(payload.vmware_ceip_enabled);
    document.querySelectorAll("[data-vmware-ceip-pill]").forEach((element) => {
      if (!(element instanceof HTMLElement)) return;
      element.textContent = enabled ? "CEIP on" : "CEIP off";
      element.classList.toggle("good", enabled);
      element.classList.toggle("muted", !enabled);
    });
    document.querySelectorAll("[data-vmware-ceip-status]").forEach((element) => {
      if (element instanceof HTMLElement) element.textContent = enabled ? "enabled" : "disabled";
    });
  }
  updateApplianceSettingsDhcpDns(payload);
  const dnsStatus = document.querySelector("[data-appliance-settings-dns-status]");
  if (dnsStatus instanceof HTMLElement) {
    const localDnsEnabled = Boolean(payload.local_dns_enabled);
    dnsStatus.classList.toggle("success", localDnsEnabled);
    dnsStatus.classList.toggle("warning", !localDnsEnabled);
    const fqdn = typeof payload.fqdn === "string" ? payload.fqdn : "the appliance FQDN";
    const actionMessages = {
      created: "Created the app-owned appliance DNS record.",
      updated: "Updated the app-owned appliance DNS record.",
      unchanged: "The app-owned appliance DNS record already matched the management IP.",
      "updated+removed-old": "Updated the appliance DNS record and removed the old app-owned record.",
      "created+removed-old": "Created the appliance DNS record and removed the old app-owned record.",
      conflict: "A user-owned DNS record already uses this appliance FQDN.",
    };
    if (payload.dns_record_action && actionMessages[payload.dns_record_action]) {
      dnsStatus.textContent = actionMessages[payload.dns_record_action];
    } else if (localDnsEnabled) {
      dnsStatus.textContent = `Local DNS is enabled. Autosave manages the app-owned appliance DNS record for ${fqdn}.`;
    } else if (payload.resolver_mode === "dhcp") {
      dnsStatus.textContent = "Local DNS is disabled. Management DHCP will keep lease-provided resolver servers unless external DNS servers are entered.";
    } else {
      dnsStatus.textContent = "Local DNS is disabled. External DNS servers are required for appliance resolver apply.";
    }
  }
}

function initializeApplianceSettings() {
  document.querySelectorAll("[data-appliance-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    form.addEventListener("atlaso:autosave-success", (event) => {
      updateApplianceSettingsValidation(event.detail || {});
    });
  });
}

function updateDnsValidation(payload = {}) {
  const validationPanel = document.querySelector("[data-dns-validation-panel]");
  if (!(validationPanel instanceof HTMLElement)) {
    return;
  }
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  const warnings = Array.isArray(payload.validation_warnings) ? payload.validation_warnings : [];
  const valid = payload.valid !== undefined ? Boolean(payload.valid) : errors.length === 0;
  const status = validationPanel.querySelector("[data-dns-validation-status]");
  if (status instanceof HTMLElement) {
    status.textContent = valid ? "valid" : "needs attention";
    status.classList.toggle("good", valid);
    status.classList.toggle("warn", !valid);
  }
  const errorList = validationPanel.querySelector("[data-dns-validation-errors]");
  if (errorList instanceof HTMLElement) {
    errorList.innerHTML = "";
    errors.forEach((error) => {
      const item = document.createElement("div");
      item.textContent = error;
      errorList.append(item);
    });
    errorList.classList.toggle("hidden", errors.length === 0);
  }
  const warningList = validationPanel.querySelector("[data-dns-validation-warnings]");
  if (warningList instanceof HTMLElement) {
    warningList.innerHTML = "";
    warnings.forEach((warning) => {
      const item = document.createElement("div");
      item.textContent = warning;
      warningList.append(item);
    });
    warningList.classList.toggle("hidden", warnings.length === 0);
  }
  const message = validationPanel.querySelector("[data-dns-validation-message]");
  if (message instanceof HTMLElement) {
    if (!valid) {
      message.textContent = "";
    } else if (warnings.length) {
      message.textContent = "The desired DNS/DHCP state is valid, but review the warning before using this domain with VCF.";
    } else {
      message.innerHTML =
        "The desired DNS/DHCP state passes Atlaso validation. Host validation still runs through <code>dnsmasq --test</code> on the appliance.";
    }
  }
  const configPath = validationPanel.querySelector("[data-dns-config-path]");
  if (configPath instanceof HTMLElement && typeof payload.config_path === "string") {
    configPath.textContent = payload.config_path;
  }
  const configPreview = validationPanel.querySelector("[data-dns-config-preview]");
  if (configPreview instanceof HTMLElement && typeof payload.config_preview === "string") {
    configPreview.textContent = payload.config_preview;
    highlightConfigPreviewElement(configPreview);
  }
  const dhcpUpstreams = Array.isArray(payload.observed_dhcp_upstream_servers) ? payload.observed_dhcp_upstream_servers : null;
  if (dhcpUpstreams) {
    const upstreamInput = document.querySelector('form[action="/dns/settings"] textarea[name="upstream_servers"]');
    if (upstreamInput instanceof HTMLTextAreaElement) {
      upstreamInput.placeholder = dhcpUpstreams.length ? `DHCP: ${dhcpUpstreams.join(", ")}` : "";
    }
    const upstreamList = document.querySelector("[data-dns-dhcp-upstreams]");
    if (upstreamList instanceof HTMLElement) {
      const values = upstreamList.querySelector("span:last-child");
      if (values instanceof HTMLElement) {
        values.innerHTML = "";
        dhcpUpstreams.forEach((server) => {
          const code = document.createElement("code");
          code.textContent = server;
          values.append(code);
          values.append(" ");
        });
      }
      upstreamList.classList.toggle("hidden", dhcpUpstreams.length === 0);
    }
  }
}

function initializeDnsSettings(root = document) {
  root.querySelectorAll('form[action="/dns/settings"]').forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.dnsSettingsInitialized === "1") return;
    form.dataset.dnsSettingsInitialized = "1";
    form.addEventListener("atlaso:autosave-success", (event) => {
      updateDnsValidation(event.detail || {});
    });
  });
}

function vcfFqdnRowsElement() {
  const rows = document.querySelector("[data-vcf-fqdn-rows]");
  return rows instanceof HTMLElement ? rows : null;
}

function vcfFqdnComponents() {
  const rows = vcfFqdnRowsElement();
  if (!rows) {
    return [];
  }
  const target = document.querySelector("[data-vcf-fqdn-target]");
  try {
    const targetComponents = JSON.parse(rows.dataset.targetComponents || "{}");
    const selectedTarget = target instanceof HTMLSelectElement ? target.value : "";
    if (selectedTarget && targetComponents && typeof targetComponents === "object" && Array.isArray(targetComponents[selectedTarget])) {
      return targetComponents[selectedTarget];
    }
    const parsed = JSON.parse(rows.dataset.components || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function vcfFqdnTargetLabel() {
  const target = document.querySelector("[data-vcf-fqdn-target]");
  if (!(target instanceof HTMLSelectElement)) {
    return "VCF";
  }
  return target.selectedOptions[0]?.textContent?.trim() || target.value || "VCF";
}

function vcfFqdnExistingData() {
  const rows = vcfFqdnRowsElement();
  if (!rows) {
    return { fqdns: [], addressRecords: {} };
  }
  try {
    const fqdns = JSON.parse(rows.dataset.existingFqdns || "[]");
    const addressRecords = JSON.parse(rows.dataset.existingAddressRecords || rows.dataset.existingARecords || "{}");
    return {
      fqdns: Array.isArray(fqdns) ? fqdns : [],
      addressRecords: addressRecords && typeof addressRecords === "object" && !Array.isArray(addressRecords) ? addressRecords : {},
    };
  } catch {
    return { fqdns: [], addressRecords: {} };
  }
}

function vcfFqdnHostLabel(component, prefix, suffix) {
  return `${String(prefix || "").trim().toLowerCase()}${component.host || ""}${String(suffix || "").trim().toLowerCase()}`;
}

function vcfFqdnForComponent(component, domain, prefix, suffix) {
  const hostLabel = vcfFqdnHostLabel(component, prefix, suffix);
  const zone = String(domain || "").trim().replace(/\.$/, "").toLowerCase();
  if (!hostLabel || !zone) {
    return "";
  }
  return `${hostLabel}.${zone}`;
}

function vcfFqdnAddressFor(fqdn, payload = {}) {
  const created = Array.isArray(payload.created) ? payload.created : [];
  const skipped = Array.isArray(payload.skipped) ? payload.skipped : [];
  const existing = vcfFqdnExistingData();
  const createdRow = created.find((row) => row.fqdn === fqdn);
  if (createdRow?.address) {
    return createdRow.address;
  }
  const skippedRow = skipped.find((row) => row.fqdn === fqdn);
  if (skippedRow?.address) {
    return skippedRow.address;
  }
  const existingAddresses = existing.addressRecords[fqdn];
  if (Array.isArray(existingAddresses) && existingAddresses.length) {
    return existingAddresses.join(", ");
  }
  return "";
}

function vcfFqdnCurrentFqdns() {
  const domain = document.querySelector("[data-vcf-fqdn-domain]");
  const target = document.querySelector("[data-vcf-fqdn-target]");
  const prefix = document.querySelector("[data-vcf-fqdn-prefix]");
  const suffix = document.querySelector("[data-vcf-fqdn-suffix]");
  if (!(domain instanceof HTMLSelectElement) || !(target instanceof HTMLSelectElement)) {
    return [];
  }
  const prefixValue = prefix instanceof HTMLInputElement ? prefix.value : "";
  const suffixValue = suffix instanceof HTMLInputElement ? suffix.value : "";
  return vcfFqdnComponents()
    .map((component) => vcfFqdnForComponent(component, domain.value, prefixValue, suffixValue))
    .filter(Boolean);
}

function vcfFqdnHasAnyAddress(payload = {}) {
  return vcfFqdnCurrentFqdns().some((fqdn) => Boolean(vcfFqdnAddressFor(fqdn, payload)));
}

function vcfFqdnRowsHaveAddresses(payload = {}) {
  const fqdns = vcfFqdnCurrentFqdns();
  return fqdns.length > 0 && fqdns.every((fqdn) => Boolean(vcfFqdnAddressFor(fqdn, payload)));
}

function updateVcfFqdnActions(payload = {}) {
  const submit = document.querySelector("[data-vcf-fqdn-submit]");
  const cancelButton = document.querySelector("[data-vcf-fqdn-modal-cancel]");
  const deleteButton = document.querySelector("[data-vcf-fqdn-delete]");
  const complete = vcfFqdnRowsHaveAddresses(payload);
  if (submit instanceof HTMLButtonElement) {
    submit.textContent = complete ? "Done" : "Create DNS records";
    submit.dataset.complete = complete ? "1" : "0";
  }
  if (cancelButton instanceof HTMLButtonElement) {
    cancelButton.hidden = complete;
  }
  if (deleteButton instanceof HTMLButtonElement) {
    deleteButton.disabled = !vcfFqdnHasAnyAddress(payload);
  }
}

function vcfFqdnApplyDeletionPayload(payload = {}) {
  const rows = vcfFqdnRowsElement();
  if (!rows) {
    return;
  }
  const deleted = Array.isArray(payload.deleted) ? payload.deleted : [];
  if (!deleted.length) {
    return;
  }
  const deletedFqdns = new Set(deleted.map((row) => row.fqdn).filter(Boolean));
  const existing = vcfFqdnExistingData();
  rows.dataset.existingFqdns = JSON.stringify(existing.fqdns.filter((fqdn) => !deletedFqdns.has(fqdn)));
  const nextAddressRecords = { ...existing.addressRecords };
  deletedFqdns.forEach((fqdn) => {
    delete nextAddressRecords[fqdn];
  });
  rows.dataset.existingAddressRecords = JSON.stringify(nextAddressRecords);
}

function vcfFqdnRowStatus(fqdn, payload = {}) {
  const address = vcfFqdnAddressFor(fqdn, payload);
  if (address) {
    return address;
  }
  const skipped = Array.isArray(payload.skipped) ? payload.skipped : [];
  const existing = vcfFqdnExistingData();
  const skippedRow = skipped.find((row) => row.fqdn === fqdn);
  if (skippedRow || existing.fqdns.includes(fqdn)) {
    return "existing record skipped";
  }
  return "allocated on confirm";
}

function renderVcfFqdnRows(payload = {}) {
  const rows = vcfFqdnRowsElement();
  const domain = document.querySelector("[data-vcf-fqdn-domain]");
  const target = document.querySelector("[data-vcf-fqdn-target]");
  const prefix = document.querySelector("[data-vcf-fqdn-prefix]");
  const suffix = document.querySelector("[data-vcf-fqdn-suffix]");
  if (!rows || !(domain instanceof HTMLSelectElement) || !(target instanceof HTMLSelectElement)) {
    return;
  }
  const prefixValue = prefix instanceof HTMLInputElement ? prefix.value : "";
  const suffixValue = suffix instanceof HTMLInputElement ? suffix.value : "";
  rows.innerHTML = "";
  vcfFqdnComponents().forEach((component) => {
    const fqdn = vcfFqdnForComponent(component, domain.value, prefixValue, suffixValue);
    const row = document.createElement("tr");
    const componentCell = document.createElement("td");
    const fqdnCell = document.createElement("td");
    const statusCell = document.createElement("td");
    componentCell.textContent = component.description || component.host || "";
    fqdnCell.textContent = fqdn;
    statusCell.textContent = vcfFqdnRowStatus(fqdn, payload);
    if (statusCell.textContent === "existing record skipped" || statusCell.textContent === "allocated on confirm") {
      statusCell.className = "muted";
    }
    row.append(componentCell, fqdnCell, statusCell);
    rows.append(row);
  });
  updateVcfFqdnActions(payload);
}

function setVcfFqdnMessage(selector, messages, type = "error") {
  const element = document.querySelector(selector);
  if (!(element instanceof HTMLElement)) {
    return;
  }
  const values = Array.isArray(messages) ? messages : [messages];
  element.innerHTML = "";
  values.filter(Boolean).forEach((message) => {
    const item = document.createElement("div");
    item.textContent = message;
    element.append(item);
  });
  element.classList.toggle("hidden", values.filter(Boolean).length === 0);
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
}

function initializeVcfFqdnGenerator() {
  const modal = document.getElementById("vcf-fqdn-modal");
  const form = document.querySelector("[data-vcf-fqdn-form]");
  if (!(modal instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement)) {
    return;
  }
  const submit = form.querySelector("[data-vcf-fqdn-submit]");
  const deleteButton = form.querySelector("[data-vcf-fqdn-delete]");
  const clearButton = form.querySelector("[data-vcf-fqdn-clear]");
  const controls = form.querySelectorAll("[data-vcf-fqdn-target], [data-vcf-fqdn-prefix], [data-vcf-fqdn-suffix], [data-vcf-fqdn-domain]");
  let currentPayload = {};
  document.querySelectorAll("[data-vcf-fqdn-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      currentPayload = {};
      setVcfFqdnMessage("[data-vcf-fqdn-errors]", []);
      setVcfFqdnMessage("[data-vcf-fqdn-result]", [], "success");
      renderVcfFqdnRows(currentPayload);
      modal.showModal();
    });
  });
  document.querySelectorAll("[data-vcf-fqdn-modal-cancel]").forEach((button) => {
    if (button instanceof HTMLButtonElement) {
      button.addEventListener("click", () => modal.close("cancel"));
    }
  });
  controls.forEach((control) => {
    control.addEventListener("input", () => {
      currentPayload = {};
      renderVcfFqdnRows(currentPayload);
    });
    control.addEventListener("change", () => {
      currentPayload = {};
      renderVcfFqdnRows(currentPayload);
    });
  });
  if (clearButton instanceof HTMLButtonElement) {
    clearButton.addEventListener("click", () => {
      const prefix = form.querySelector("[data-vcf-fqdn-prefix]");
      const suffix = form.querySelector("[data-vcf-fqdn-suffix]");
      if (prefix instanceof HTMLInputElement) {
        prefix.value = "";
      }
      if (suffix instanceof HTMLInputElement) {
        suffix.value = "";
      }
      currentPayload = {};
      renderVcfFqdnRows(currentPayload);
    });
  }
  const setActionsDisabled = (disabled) => {
    if (submit instanceof HTMLButtonElement) {
      submit.disabled = disabled;
    }
    if (deleteButton instanceof HTMLButtonElement) {
      deleteButton.disabled = disabled;
    }
  };
  const submitRequest = async (url, action) => {
    setVcfFqdnMessage("[data-vcf-fqdn-errors]", []);
    setVcfFqdnMessage("[data-vcf-fqdn-result]", [], "success");
    setActionsDisabled(true);
    try {
      const response = await fetch(url, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: {
          "X-Atlaso-VCF-Helper": "1",
        },
      });
      const payload = await response.json();
      if (!response.ok) {
        setVcfFqdnMessage("[data-vcf-fqdn-errors]", payload.errors || `Generated VCF FQDNs could not be ${action}.`);
        return null;
      }
      return payload;
    } catch (error) {
      setVcfFqdnMessage("[data-vcf-fqdn-errors]", error instanceof Error ? error.message : `Generated VCF FQDNs could not be ${action}.`);
      return null;
    } finally {
      setActionsDisabled(false);
      updateVcfFqdnActions(currentPayload);
    }
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit instanceof HTMLButtonElement && submit.dataset.complete === "1") {
      modal.close("done");
      window.location.reload();
      return;
    }
    const domain = form.querySelector("[data-vcf-fqdn-domain]");
    const zone = domain instanceof HTMLSelectElement ? domain.value : "the selected domain";
    const confirmed = await requestConfirmation({
      title: "Create generated VCF DNS records?",
      message: `Create missing DNS A or AAAA records for ${vcfFqdnComponents().length} ${vcfFqdnTargetLabel()} components in ${zone}? Existing FQDNs remain unchanged, and allocation stays inside the selected IP subnet.`,
      label: "Create DNS records",
    });
    if (confirmed) {
      const payload = await submitRequest(form.action, "created");
      if (payload) {
        currentPayload = payload;
        renderVcfFqdnRows(currentPayload);
        const createdCount = Array.isArray(payload.created) ? payload.created.length : 0;
        const skippedCount = Array.isArray(payload.skipped) ? payload.skipped.length : 0;
        setVcfFqdnMessage(
          "[data-vcf-fqdn-result]",
          `Created ${createdCount} DNS records${skippedCount ? `; skipped ${skippedCount} existing records` : ""}.`,
          "success"
        );
      }
    }
  });
  if (deleteButton instanceof HTMLButtonElement) {
    deleteButton.addEventListener("click", async () => {
      const domain = form.querySelector("[data-vcf-fqdn-domain]");
      const zone = domain instanceof HTMLSelectElement ? domain.value : "the selected domain";
      const confirmed = await requestConfirmation({
        title: "Delete generated VCF DNS records?",
        message: `Delete VCF Helper A or AAAA records matching the current deployment, prefix, suffix, and ${zone} domain? Unrelated and skipped existing records are preserved. The appliance changes only after global Appliance Apply.`,
        label: "Delete DNS records",
      });
      if (confirmed) {
        const payload = await submitRequest(`${form.action}/delete`, "deleted");
        if (payload) {
          vcfFqdnApplyDeletionPayload(payload);
          currentPayload = { skipped: Array.isArray(payload.preserved) ? payload.preserved : [] };
          renderVcfFqdnRows(currentPayload);
          const deletedCount = Array.isArray(payload.deleted) ? payload.deleted.length : 0;
          const preservedCount = Array.isArray(payload.preserved) ? payload.preserved.length : 0;
          setVcfFqdnMessage(
            "[data-vcf-fqdn-result]",
            `Deleted ${deletedCount} VCF Helper DNS records${preservedCount ? `; preserved ${preservedCount} unrelated records` : ""}.`,
            "success"
          );
        }
      }
    });
  }
  renderVcfFqdnRows(currentPayload);
}

function updateVcfBackupDerivedAddress(form, payload = {}) {
  const portInput = form.querySelector('input[name="port"]');
  const { interfaceLabel: bindInterfaceLabel, address, addresses, addressLabel } = serviceBindSelection(form, payload);
  const port = payload.port || portInput?.value || "22";
  const endpoint = document.querySelector("[data-vcf-endpoint]");
  const host = document.querySelector("[data-vcf-host]");
  const targetPort = document.querySelector("[data-vcf-port]");
  const interfaceElement = document.querySelector("[data-vcf-interface]");
  const sftpUser = document.querySelector("[data-vcf-sftp-user]");
  const targetUser = document.querySelector("[data-vcf-target-user]");
  const storagePaths = document.querySelectorAll("[data-vcf-storage-path]");
  const remoteDirectories = document.querySelectorAll("[data-vcf-remote-directory]");
  const chrootLabel = document.querySelector("[data-vcf-chroot-label]");
  const authMethods = document.querySelector("[data-vcf-auth-methods]");
  const maxSessions = document.querySelector("[data-vcf-max-sessions]");
  if (endpoint instanceof HTMLElement) {
    endpoint.textContent = address ? `${address}:${port}` : `no interface IP:${port}`;
  }
  if (host instanceof HTMLElement) {
    host.textContent = address || "no interface IP";
  }
  if (targetPort instanceof HTMLElement) {
    targetPort.textContent = String(port);
  }
  if (interfaceElement instanceof HTMLElement) {
    interfaceElement.textContent = `${bindInterfaceLabel || "no interface"} / ${addressLabel || "no interface IP"}`;
  }
  if (sftpUser instanceof HTMLElement && payload.sftp_username !== undefined) {
    sftpUser.textContent = payload.sftp_username || "not selected";
  }
  if (targetUser instanceof HTMLElement && payload.sftp_username !== undefined) {
    targetUser.textContent = payload.sftp_username || "select a user";
  }
  if (payload.storage_path) {
    storagePaths.forEach((storagePath) => {
      if (storagePath instanceof HTMLElement) {
        storagePath.textContent = payload.storage_path;
      }
    });
  }
  if (payload.remote_directory) {
    remoteDirectories.forEach((remoteDirectory) => {
      if (remoteDirectory instanceof HTMLElement) {
        remoteDirectory.textContent = payload.remote_directory;
      }
    });
  }
  if (chrootLabel instanceof HTMLElement && payload.chroot_label) {
    chrootLabel.textContent = payload.chroot_label;
  }
  if (authMethods instanceof HTMLElement && payload.auth_methods) {
    authMethods.textContent = payload.auth_methods;
  }
  if (maxSessions instanceof HTMLElement && payload.max_sessions !== undefined) {
    maxSessions.textContent = `${payload.max_sessions} max sessions`;
  }
}

function updateVcfBackupValidation(payload = {}) {
  const status = document.querySelector("[data-vcf-validation-status]");
  const validationPanel = status?.closest(".panel");
  const applyButton = document.querySelector("[data-vcf-apply-button]");
  const configPath = document.querySelector("[data-vcf-config-path]");
  const configPreview = document.querySelector("[data-vcf-config-preview]");
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  if (status instanceof HTMLElement && payload.valid !== undefined) {
    status.textContent = payload.valid ? "valid" : "needs attention";
    status.classList.toggle("good", Boolean(payload.valid));
    status.classList.toggle("warn", !payload.valid);
  }
  if (applyButton instanceof HTMLButtonElement && payload.valid !== undefined) {
    applyButton.disabled = !payload.valid;
  }
  if (configPath instanceof HTMLElement && payload.config_path) {
    configPath.textContent = payload.config_path;
  }
  if (configPreview instanceof HTMLElement && payload.config_preview !== undefined) {
    configPreview.textContent = payload.config_preview;
    highlightConfigPreviewElement(configPreview);
  }
  if (validationPanel instanceof HTMLElement && payload.valid !== undefined) {
    const previewAnchor = validationPanel.querySelector("[data-config-preview-row]");
    let errorList = validationPanel.querySelector("[data-vcf-validation-errors]");
    let message = validationPanel.querySelector("[data-vcf-validation-message]");
    if (payload.valid) {
      if (errorList) {
        errorList.remove();
      }
      if (!(message instanceof HTMLElement)) {
        message = document.createElement("p");
        message.className = "muted";
        message.setAttribute("data-vcf-validation-message", "");
        validationPanel.insertBefore(message, previewAnchor);
      }
      message.textContent = "The desired VCF backup SFTP state passes Atlaso validation. Appliance validation still runs through the allowlisted OpenSSH helper before apply.";
    } else {
      if (message) {
        message.remove();
      }
      if (!(errorList instanceof HTMLElement)) {
        errorList = document.createElement("ul");
        errorList.className = "error-list";
        errorList.setAttribute("data-vcf-validation-errors", "");
        validationPanel.insertBefore(errorList, previewAnchor);
      }
      errorList.innerHTML = "";
      errors.forEach((error) => {
        const item = document.createElement("li");
        item.textContent = error;
        errorList.appendChild(item);
      });
    }
  }
}

function initializeVcfBackupSettings(root = document) {
  root.querySelectorAll("[data-vcf-backup-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.vcfBackupSettingsInitialized === "1") return;
    form.dataset.vcfBackupSettingsInitialized = "1";
    const portInput = form.querySelector('input[name="port"]');
    const refresh = () => updateVcfBackupDerivedAddress(form);
    if (portInput instanceof HTMLInputElement) {
      portInput.addEventListener("input", refresh);
    }
    form.addEventListener("atlaso:autosave-success", (event) => {
      const payload = event.detail || {};
      updateVcfBackupDerivedAddress(form, payload);
      updateVcfBackupValidation(payload);
    });
    refresh();
  });
}

function showVcfRegistryMessage(message, type = "error") {
  const element = document.getElementById("vcf-registry-bundle-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function newVcfRegistryBundleRow() {
  return {
    id: "__new__",
    name: "",
    source_reference: "",
    target_reference: "",
    enabled: true,
    status: "planned",
    notes: "",
    is_new: true,
  };
}

function hasRequiredVcfRegistryBundleFields(data) {
  return Boolean((data.name || "").trim() && (data.source_reference || "").trim());
}

async function postVcfRegistryBundleAction(url, data, csrf) {
  const body = new FormData();
  body.set("csrf", csrf);
  for (const [key, value] of Object.entries(data)) {
    if (["id", "is_new", "created_at", "updated_at"].includes(key)) {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set(key, "on");
      }
      continue;
    }
    body.set(key, value ?? "");
  }
  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    const plainText = text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    throw new Error(plainText || "The Supervisor Service bundle could not be saved.");
  }
  window.location.reload();
}

async function autoSaveVcfRegistryBundle(cell, csrf) {
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new && !hasRequiredVcfRegistryBundleFields(data)) {
    reformatPendingNewRecord(cell);
    return;
  }
  const url = data.is_new ? "/vcf-private-registry/bundles" : `/vcf-private-registry/bundles/${data.id}/edit`;
  try {
    await postVcfRegistryBundleAction(url, data, csrf);
  } catch (error) {
    showVcfRegistryMessage(error instanceof Error ? error.message : "The Supervisor Service bundle could not be saved.");
  }
}

async function deleteVcfRegistryBundleFromMenu(row, csrf) {
  const data = row.getData();
  if (data.is_new) {
    row.getTable().deleteRow(data.id);
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name || "Supervisor Service"} bundle?`,
    message: "This removes the Supervisor Service bundle from Atlaso desired state. It does not remove images from Harbor until a future appliance task explicitly does so.",
    label: "Delete",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postVcfRegistryBundleAction(`/vcf-private-registry/bundles/${data.id}/delete`, data, csrf);
  } catch (error) {
    showVcfRegistryMessage(error instanceof Error ? error.message : "The Supervisor Service bundle could not be deleted.");
  }
}

function initializeVcfRegistryBundlesTable() {
  const element = document.getElementById("vcf-registry-bundles-table");
  if (!(element instanceof HTMLElement)) return;
  initializeAtlasoResourceWizard({
    elementId: "vcf-registry-bundles-table",
    formSelector: "[data-vcf-registry-bundle-form]",
    dialogId: "vcf-registry-bundle-dialog",
    rows: JSON.parse(element.dataset.bundles || "[]"),
    newRow: newVcfRegistryBundleRow(),
    resourceName: "bundle",
    createUrl: "/vcf-private-registry/bundles",
    editUrl: (id) => `/vcf-private-registry/bundles/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/vcf-private-registry/bundles/${id}/delete`,
    editLabel: "Edit bundle",
    deleteLabel: "Delete bundle",
    createLabel: "Create bundle",
    updateLabel: "Update bundle",
    emptyMessage: "No Supervisor Service bundles configured.",
    actionErrorSelector: "#vcf-registry-bundle-error",
    defaults: newVcfRegistryBundleRow(),
    steps: [
      { id: "source", title: "Choose the source bundle", description: "Name the Supervisor Service bundle and identify its upstream reference." },
      { id: "target", title: "Set the Harbor target", description: "Accept the derived target or provide an explicit internal registry reference." },
      { id: "state", title: "Choose relocation state", description: "Set lifecycle status, enablement, and operator notes." },
      { id: "review", title: "Review registry desired state", description: "Confirm the bundle and global appliance-apply boundary." },
    ],
    reviewItems: [
      { label: "Bundle", field: "name" },
      { label: "Source", field: "source_reference" },
      { label: "Target", field: "target_reference" },
      { label: "Status", field: "status" },
      { label: "Enabled", field: "enabled" },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name} bundle?`,
      message: "This removes the Supervisor Service bundle from Atlaso desired state. It does not remove images from Harbor.",
      confirmLabel: "Delete bundle",
      tone: "danger",
    }),
    options: {
      height: "360px",
      rowHeight: 28,
      placeholder: "No Supervisor Service bundles configured.",
      columns: [
        { title: "Name", field: "name", formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add bundle here</button>' : escapeHtml(cell.getValue()), minWidth: 170 },
        { title: "Source reference", field: "source_reference", minWidth: 260 },
        { title: "Target reference", field: "target_reference", minWidth: 260 },
        { title: "Status", field: "status", width: 120 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 95, headerSort: false },
        { title: "Notes", field: "notes", minWidth: 180 },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
}

function updateVcfRegistrySummary(form, payload = {}) {
  const portInput = form.querySelector('input[name="port"]');
  const hostnameInput = form.querySelector('input[name="hostname"]');
  const projectInput = form.querySelector('input[name="harbor_project"]');
  const { interfaceLabel: bindInterfaceLabel, addressLabel } = serviceBindSelection(form, payload);
  const port = payload.port || portInput?.value || "443";
  const hostname = payload.hostname || hostnameInput?.value || "";
  const endpointValue = payload.endpoint || (port === "443" || port === 443 ? hostname : `${hostname}:${port}`);
  const endpoint = document.querySelector("[data-vcf-registry-endpoint]");
  const interfaceLabel = document.querySelector("[data-vcf-registry-interface]");
  const project = document.querySelector("[data-vcf-registry-project]");
  const robot = document.querySelector("[data-vcf-registry-robot]");
  const storagePaths = document.querySelectorAll("[data-vcf-registry-storage]");
  const caBundleSource = document.querySelector("[data-vcf-registry-ca-bundle-source]");
  const caBundlePath = document.querySelector("[data-vcf-registry-ca-bundle-path]");
  if (endpoint instanceof HTMLElement) {
    endpoint.textContent = endpointValue || "registry hostname required";
  }
  if (interfaceLabel instanceof HTMLElement) {
    interfaceLabel.textContent = `${bindInterfaceLabel || "no interface"} / ${addressLabel || "no interface IP"}`;
  }
  if (project instanceof HTMLElement) {
    project.textContent = payload.harbor_project || projectInput?.value || "";
  }
  if (robot instanceof HTMLElement && payload.robot_account !== undefined) {
    robot.textContent = payload.robot_account || "";
  }
  if (payload.storage_path) {
    storagePaths.forEach((storagePath) => {
      if (storagePath instanceof HTMLElement) {
        storagePath.textContent = payload.storage_path;
      }
    });
  }
  if (caBundleSource instanceof HTMLElement && payload.ca_bundle_source_label !== undefined) {
    const uploadedName = payload.ca_bundle_uploaded_name || "not uploaded";
    const sourceText = `${payload.ca_bundle_source === "uploaded" ? uploadedName : payload.ca_bundle_source_label} / `;
    if (caBundleSource.firstChild) {
      caBundleSource.firstChild.textContent = sourceText;
    } else {
      caBundleSource.prepend(document.createTextNode(sourceText));
    }
  }
  if (caBundlePath instanceof HTMLElement && payload.ca_bundle_path) {
    caBundlePath.textContent = payload.ca_bundle_path;
  }
}

function updateVcfRegistryValidation(payload = {}) {
  const status = document.querySelector("[data-vcf-registry-validation-status]");
  const validationPanel = status?.closest(".panel");
  const applyButton = document.querySelector("[data-vcf-registry-apply-button]");
  const configPath = document.querySelector("[data-vcf-registry-config-path]");
  const harborPreview = document.querySelector("[data-vcf-registry-harbor-preview]");
  const relocationPreview = document.querySelector("[data-vcf-registry-relocation-preview]");
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  const warnings = Array.isArray(payload.validation_warnings) ? payload.validation_warnings : [];
  if (status instanceof HTMLElement && payload.valid !== undefined) {
    status.textContent = payload.valid ? "valid" : "needs attention";
    status.classList.toggle("good", Boolean(payload.valid));
    status.classList.toggle("warn", !payload.valid);
  }
  if (applyButton instanceof HTMLButtonElement && payload.valid !== undefined) {
    applyButton.disabled = !payload.valid;
  }
  if (configPath instanceof HTMLElement && payload.config_path) {
    configPath.textContent = payload.config_path;
  }
  if (harborPreview instanceof HTMLElement && payload.harbor_config_preview !== undefined) {
    harborPreview.textContent = payload.harbor_config_preview;
    highlightConfigPreviewElement(harborPreview);
  }
  if (relocationPreview instanceof HTMLElement && payload.relocation_preview !== undefined) {
    relocationPreview.textContent = payload.relocation_preview;
    highlightConfigPreviewElement(relocationPreview);
  }
  if (validationPanel instanceof HTMLElement && payload.valid !== undefined) {
    const previewAnchor = validationPanel.querySelector("[data-config-preview-row]");
    let errorList = validationPanel.querySelector("[data-vcf-registry-validation-errors]");
    let message = validationPanel.querySelector("[data-vcf-registry-validation-message]");
    let warningList = validationPanel.querySelector("[data-vcf-registry-validation-warnings]");
    if (payload.valid) {
      if (errorList) {
        errorList.remove();
      }
      if (!(message instanceof HTMLElement)) {
        message = document.createElement("p");
        message.className = "muted";
        message.setAttribute("data-vcf-registry-validation-message", "");
        validationPanel.insertBefore(message, previewAnchor);
      }
      message.textContent = "The desired VCF private registry state passes Atlaso validation. Appliance validation still runs through the allowlisted Harbor helper before apply.";
    } else {
      if (message) {
        message.remove();
      }
      if (!(errorList instanceof HTMLElement)) {
        errorList = document.createElement("ul");
        errorList.className = "error-list";
        errorList.setAttribute("data-vcf-registry-validation-errors", "");
        validationPanel.insertBefore(errorList, previewAnchor);
      }
      errorList.innerHTML = "";
      errors.forEach((error) => {
        const item = document.createElement("li");
        item.textContent = error;
        errorList.appendChild(item);
      });
    }
    if (!(warningList instanceof HTMLElement)) {
      warningList = document.createElement("ul");
      warningList.className = "warning-list";
      warningList.setAttribute("data-vcf-registry-validation-warnings", "");
      validationPanel.insertBefore(warningList, previewAnchor);
    }
    warningList.innerHTML = "";
    warnings.forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = warning;
      warningList.appendChild(item);
    });
    warningList.classList.toggle("hidden", warnings.length === 0);
  }
}

function initializeVcfRegistrySettings(root = document) {
  root.querySelectorAll("[data-vcf-registry-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.vcfRegistrySettingsInitialized === "1") return;
    form.dataset.vcfRegistrySettingsInitialized = "1";
    const portInput = form.querySelector('input[name="port"]');
    const hostnameInput = form.querySelector('input[name="hostname"]');
    const projectInput = form.querySelector('input[name="harbor_project"]');
    const refresh = () => updateVcfRegistrySummary(form);
    [portInput, hostnameInput, projectInput].forEach((input) => {
      if (input instanceof HTMLElement) {
        input.addEventListener("input", refresh);
        input.addEventListener("change", refresh);
      }
    });
    form.addEventListener("atlaso:autosave-success", (event) => {
      const payload = event.detail || {};
      updateVcfRegistrySummary(form, payload);
      updateVcfRegistryValidation(payload);
    });
    refresh();
  });
}

function showVcfDepotMessage(message, type = "error") {
  const element = document.getElementById("vcf-depot-profile-error");
  if (!element) {
    return;
  }
  element.textContent = message;
  element.classList.toggle("error", type === "error");
  element.classList.toggle("success", type === "success");
  element.classList.remove("hidden");
}

function newVcfDepotProfileRow() {
  return {
    id: "__new__",
    name: "",
    profile_type: "binaries",
    sku: "VCF",
    vcf_version: "9.1.0",
    binary_type: "INSTALL",
    automated_install: true,
    upgrades_only: false,
    patches_only: false,
    download_mode: "automated_install",
    component: "",
    component_version: "",
    disabled_platforms: [],
    enabled: false,
    status: "planned",
    notes: "",
    is_new: true,
  };
}

function hasRequiredVcfDepotProfileFields(data) {
  return Boolean((data.name || "").trim() && (data.profile_type || "").trim());
}

function vcfDepotListValues(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item || "").trim()).filter(Boolean);
  }
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatVcfDepotChoiceList(cell, values, emptyText) {
  const selected = vcfDepotListValues(cell.getValue());
  if (!selected.length) {
    return `<span class="muted">${escapeHtml(emptyText)}</span>`;
  }
  return selected.map((item) => escapeHtml(values[item] || item)).join("<br>");
}

function formatVcfDepotDisabledPlatforms(cell, values, emptyText) {
  const selected = vcfDepotListValues(cell.getValue());
  if (!selected.length) {
    return `<span class="muted">${escapeHtml(emptyText)}</span>`;
  }
  const summaryItems = selected.slice(0, 3).map((item) => escapeHtml(values[item] || item));
  const summary = [
    summaryItems.join("<br>"),
    selected.length > summaryItems.length ? `<span class="muted">+ ${selected.length - summaryItems.length} more</span>` : "",
  ].filter(Boolean).join("<br>");
  const rows = selected.map((item) => {
    const label = values[item] || item;
    return `<tr><td><code>${escapeHtml(item)}</code></td><td>${escapeHtml(label)}</td></tr>`;
  }).join("");
  const ariaLabel = selected.map((item) => values[item] || item).join(", ");
  return [
    `<span class="vcf-platform-tooltip" tabindex="0" aria-label="Disabled platforms: ${escapeHtml(ariaLabel)}">`,
    `<span class="vcf-platform-summary">${summary}</span>`,
    '<span class="vcf-platform-tip" role="tooltip">',
    '<strong>Disabled platforms</strong>',
    '<table><thead><tr><th>Value</th><th>Label</th></tr></thead>',
    `<tbody>${rows}</tbody></table>`,
    '</span>',
    '</span>',
  ].join("");
}

function rememberActiveTab(storageKey, targetId) {
  if (!storageKey || !targetId) {
    return;
  }
  try {
    window.localStorage.setItem(storageKey, targetId);
  } catch {
    // Tab persistence is a convenience only; private browsing can disable it.
  }
}

function vcfDepotDisabledPlatformsEditor(cell, onRendered, success, cancel, editorParams) {
  const values = editorParams.values || {};
  const selected = new Set(vcfDepotListValues(cell.getValue()));
  const wrapper = document.createElement("div");
  wrapper.className = "tabulator-checklist-editor";
  const options = document.createElement("div");
  options.className = "tabulator-checklist-options";
  Object.entries(values).forEach(([value, label]) => {
    const row = document.createElement("label");
    row.className = "tabulator-checklist-option";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = value;
    checkbox.checked = selected.has(value);
    const text = document.createElement("span");
    text.textContent = label;
    row.append(checkbox, text);
    options.appendChild(row);
  });
  const actions = document.createElement("div");
  actions.className = "tabulator-checklist-actions";
  const clearButton = document.createElement("button");
  clearButton.type = "button";
  clearButton.textContent = "Clear";
  const doneButton = document.createElement("button");
  doneButton.type = "button";
  doneButton.textContent = "Done";
  doneButton.className = "primary";
  actions.append(clearButton, doneButton);
  wrapper.append(options, actions);

  function selectedValues() {
    return Array.from(wrapper.querySelectorAll("input[type='checkbox']:checked")).map((input) => input.value);
  }

  clearButton.addEventListener("click", (event) => {
    event.preventDefault();
    wrapper.querySelectorAll("input[type='checkbox']").forEach((input) => {
      input.checked = false;
    });
  });
  doneButton.addEventListener("click", (event) => {
    event.preventDefault();
    success(selectedValues());
  });
  wrapper.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.ctrlKey) {
      event.preventDefault();
      success(selectedValues());
    }
    if (event.key === "Escape") {
      event.preventDefault();
      cancel();
    }
  });
  onRendered(() => {
    const firstCheckbox = wrapper.querySelector("input[type='checkbox']");
    if (firstCheckbox instanceof HTMLElement) {
      firstCheckbox.focus();
    }
  });
  return wrapper;
}

async function postVcfDepotProfileAction(url, data, csrf) {
  const body = new FormData();
  body.set("csrf", csrf);
  const downloadMode = data.download_mode || "automated_install";
  body.set(downloadMode, "on");
  for (const [key, value] of Object.entries(data)) {
    if (["id", "is_new", "created_at", "updated_at"].includes(key)) {
      continue;
    }
    if (["automated_install", "upgrades_only", "patches_only", "download_mode"].includes(key)) {
      continue;
    }
    if (key === "enabled") {
      if (value) {
        body.set(key, "on");
      }
      continue;
    }
    if (key === "disabled_platforms") {
      body.set(key, vcfDepotListValues(value).join("\n"));
      continue;
    }
    body.set(key, value ?? "");
  }
  const response = await fetch(url, {
    method: "POST",
    body,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    const plainText = text.trim().replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
    throw new Error(plainText || "The VCFDT download profile could not be saved.");
  }
  window.location.reload();
}

async function autoSaveVcfDepotProfile(cell, csrf) {
  const row = cell.getRow();
  const data = row.getData();
  if (data.is_new && !hasRequiredVcfDepotProfileFields(data)) {
    reformatPendingNewRecord(cell);
    return;
  }
  const url = data.is_new ? "/vcf-offline-depot/profiles" : `/vcf-offline-depot/profiles/${data.id}/edit`;
  try {
    await postVcfDepotProfileAction(url, data, csrf);
  } catch (error) {
    showVcfDepotMessage(error instanceof Error ? error.message : "The VCFDT download profile could not be saved.");
  }
}

async function deleteVcfDepotProfileFromMenu(row, csrf) {
  const data = row.getData();
  if (data.is_new) {
    row.getTable().deleteRow(data.id);
    return;
  }
  const confirmed = await requestConfirmation({
    title: `Delete ${data.name || "VCFDT"} profile?`,
    message: "This removes the VCFDT download profile from Atlaso desired state. It does not remove files from the appliance depot until a future task explicitly does so.",
    label: "Delete",
  });
  if (!confirmed) {
    return;
  }
  try {
    await postVcfDepotProfileAction(`/vcf-offline-depot/profiles/${data.id}/delete`, data, csrf);
  } catch (error) {
    showVcfDepotMessage(error instanceof Error ? error.message : "The VCFDT download profile could not be deleted.");
  }
}

async function startVcfDepotProfileDownload(row, csrf) {
  const data = row.getData();
  if (data.is_new) {
    return;
  }
  if (!data.enabled) {
    showVcfDepotMessage("Enable the VCFDT download profile before starting a download.");
    return;
  }
  if (data.download_active) {
    showVcfDepotMessage(data.active_task_blocker || "Wait for the active VCFDT task to finish before starting another download.");
    return;
  }
  if (!data.can_start) {
    showVcfDepotMessage(data.start_blocker || "Stage Broadcom credentials before starting this VCFDT download profile.");
    return;
  }
  try {
    const body = new FormData();
    body.set("csrf", csrf);
    const response = await fetch(`/vcf-offline-depot/profiles/${data.id}/download`, {
      method: "POST",
      body,
      credentials: "same-origin",
      headers: { "X-Atlaso-Autosave": "1" },
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "The VCFDT download job could not be started.");
    }
    const blocker = `Wait for VCFDT task ${payload.job_id} to finish before starting another download.`;
    await row.update({
      status: payload.profile_status || data.status,
      download_active: true,
      active_task_blocker: blocker,
    });
    setVcfDepotDownloadActive(true, payload.job_id);
    if (vcfDepotTasksTable) {
      await vcfDepotTasksTable.setPage(1);
      await refreshVcfDepotTasksTable();
    }
    showVcfDepotMessage(`VCFDT task ${payload.job_id} started for ${payload.profile_name}.`, "success");
  } catch (error) {
    showVcfDepotMessage(error instanceof Error ? error.message : "The VCFDT download job could not be started.");
  }
}

async function previewVcfDepotProfileScript(row) {
  const data = row.getData();
  if (data.is_new) {
    showVcfDepotMessage("Save the VCFDT download profile before previewing its script.");
    return;
  }
  try {
    const response = await fetch(`/vcf-offline-depot/profiles/${data.id}/preview`, {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "The VCFDT profile script could not be rendered.");
    }
    const sourceCode = document.createElement("code");
    sourceCode.className = "language-bash";
    openPreviewModal(`${payload.profile_name || data.name || "VCFDT"} profile script`, payload.script || "", sourceCode);
  } catch (error) {
    showVcfDepotMessage(error instanceof Error ? error.message : "The VCFDT profile script could not be rendered.");
  }
}

let vcfDepotProfilesTable = null;

function setVcfDepotDownloadActive(active, activeJobId = "") {
  if (!vcfDepotProfilesTable) {
    return;
  }
  const blocker = active
    ? `Wait for VCFDT task ${activeJobId || "in progress"} to finish before starting another download.`
    : "";
  vcfDepotProfilesTable.getRows().forEach((row) => {
    const data = row.getData();
    if (!data.is_new) {
      row.update({ download_active: active, active_task_blocker: blocker });
    }
  });
}

function initializeVcfDepotProfilesTable() {
  const element = document.getElementById("vcf-depot-profiles-table");
  if (!(element instanceof HTMLElement)) return;
  const componentOptions = JSON.parse(element.dataset.components || "[]");
  const componentValues = {
    "": "All components",
    ...Object.fromEntries(componentOptions.map((item) => [item.value, item.label])),
  };
  const esxPlatformOptions = JSON.parse(element.dataset.esxPlatforms || "[]");
  const esxPlatformValues = Object.fromEntries(esxPlatformOptions.map((item) => [item.value, item.label]));
  const csrf = element.dataset.csrf || "";
  const normalize = (row) => ({
    ...row,
    disabled_platforms: Array.isArray(row.disabled_platforms)
      ? row.disabled_platforms.join(",")
      : row.disabled_platforms,
  });
  const adapter = initializeAtlasoResourceWizard({
    elementId: "vcf-depot-profiles-table",
    formSelector: "[data-vcf-depot-profile-form]",
    dialogId: "vcf-depot-profile-dialog",
    rows: JSON.parse(element.dataset.profiles || "[]").map(normalize),
    newRow: newVcfDepotProfileRow(),
    resourceName: "profile",
    createUrl: "/vcf-offline-depot/profiles",
    editUrl: (id) => `/vcf-offline-depot/profiles/${id}/edit`,
    deleteResource: true,
    deleteUrl: (id) => `/vcf-offline-depot/profiles/${id}/delete`,
    editLabel: "Edit profile",
    deleteLabel: "Delete profile",
    createLabel: "Create download profile",
    updateLabel: "Update download profile",
    emptyMessage: "No VCFDT download profiles configured.",
    actionErrorSelector: "#vcf-depot-profile-error",
    defaults: newVcfDepotProfileRow(),
    steps: [
      { id: "identity", title: "Choose profile identity", description: "Name the VCFDT profile, select its download type, and record optional notes." },
      { id: "release", title: "Choose release content", description: "Set SKU, VCF release, binary type, and download mode." },
      { id: "filter", title: "Filter components", description: "Limit component and ESX platform content when required." },
      { id: "enablement", title: "Choose profile availability", description: "Control whether the VCFDT profile may be started." },
      { id: "review", title: "Review depot desired state", description: "Confirm the VCFDT profile and execution boundary." },
    ],
    reviewItems: [
      { label: "Profile", field: "name" },
      { label: "Type", field: "profile_type" },
      { label: "Release", value: (form) => `${form.elements.sku.value} ${form.elements.vcf_version.value}` },
      { label: "Binary", field: "binary_type" },
      { label: "Mode", field: "download_mode" },
      { label: "Component", field: "component" },
      { label: "Enabled", field: "enabled" },
    ],
    prepareFormData: ({ body }) => {
      const mode = body.get("download_mode") || "automated_install";
      body.delete("download_mode");
      body.set(mode, "on");
      body.set("disabled_platforms", vcfDepotListValues(body.get("disabled_platforms")).join("\n"));
    },
    normalizeResource: normalize,
    extraActions: [
      {
        label: "Preview script",
        disabled: (row) => Boolean(row.getData().is_new),
        action: (_event, row) => previewVcfDepotProfileScript(row),
      },
      {
        label: "Start download",
        disabled: (row) => {
          const data = row.getData();
          return data.is_new || !data.enabled || !data.can_start;
        },
        action: (_event, row) => startVcfDepotProfileDownload(row, element.dataset.csrf || ""),
      },
    ],
    deleteConfirmation: (data) => ({
      title: `Delete ${data.name} profile?`,
      message: "This removes the VCFDT download profile from Atlaso desired state. Existing downloaded content is not removed.",
      confirmLabel: "Delete profile",
      tone: "danger",
    }),
    options: {
      height: "380px",
      rowHeight: 34,
      placeholder: "No VCFDT download profiles configured.",
      columns: [
        { title: "Name", field: "name", formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-atlaso-wizard-add>+ Add profile here</button>' : escapeHtml(cell.getValue()), minWidth: 180 },
        {
          title: "Start",
          field: "start",
          formatter: (cell) => {
            const data = cell.getRow().getData();
            const disabled = data.is_new || data.download_active || !data.enabled || !data.can_start ? " disabled" : "";
            const blocker = data.active_task_blocker || data.start_blocker;
            const title = blocker ? ` title="${escapeHtml(blocker)}"` : "";
            return `<button class="button tiny secondary" type="button" data-vcf-depot-start-download${disabled}${title}>Start</button>`;
          },
          width: 90,
          hozAlign: "center",
          headerSort: false,
          cellClick: (_event, cell) => startVcfDepotProfileDownload(cell.getRow(), csrf),
        },
        { title: "Type", field: "profile_type", width: 110 },
        { title: "Enabled", field: "enabled", formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), hozAlign: "center", width: 95, headerSort: false },
        { title: "SKU", field: "sku", width: 85 },
        { title: "VCF version", field: "vcf_version", width: 125 },
        { title: "Binary type", field: "binary_type", width: 125 },
        { title: "Download mode", field: "download_mode", minWidth: 150 },
        { title: "Component", field: "component", formatter: (cell) => componentValues[cell.getValue()] || escapeHtml(cell.getValue()), minWidth: 210 },
        { title: "Component version", field: "component_version", minWidth: 145 },
        {
          title: "Disabled platforms",
          field: "disabled_platforms",
          formatter: (cell) => formatVcfDepotDisabledPlatforms(cell, esxPlatformValues, "none"),
          minWidth: 190,
          cssClass: "vcf-platforms-cell",
        },
        {
          title: "Last run",
          field: "status",
          formatter: (cell) => ({
            planned: "Never run",
            ready: "Running",
            synced: "Succeeded",
            blocked: "Failed",
          })[cell.getValue()] || "Unknown",
          width: 110,
          headerSort: false,
        },
      ],
      rowFormatter: (row) => markNewRecordRow(row, "name"),
    },
  });
  vcfDepotProfilesTable = adapter?.table || null;
}

let vcfDepotTasksTable = null;
let vcfDepotTasksRefreshInterval = null;
let vcfDepotTasksRefreshPending = false;

async function refreshVcfDepotTasksTable() {
  if (!vcfDepotTasksTable || vcfDepotTasksRefreshPending) {
    return;
  }
  vcfDepotTasksRefreshPending = true;
  try {
    await vcfDepotTasksTable.replaceData();
  } catch (error) {
    showVcfDepotMessage(error instanceof Error ? error.message : "Unable to refresh VCFDT tasks.");
  } finally {
    vcfDepotTasksRefreshPending = false;
  }
}

function initializeVcfDepotTasksTable() {
  const tableElement = document.getElementById("vcf-depot-tasks-table");
  if (!(tableElement instanceof HTMLElement) || typeof window.Tabulator !== "function") {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  try {
    const tasks = JSON.parse(tableElement.dataset.tasks || "[]");
    const atlasoGridOptions27 = {
      data: tasks,
      ajaxURL: "/vcf-offline-depot/tasks/status",
      pagination: true,
      paginationMode: "remote",
      paginationSize: 10,
      paginationCounter: "rows",
      dataSendParams: { page: "page", size: "size" },
      ajaxResponse: (_url, _params, response) => {
        setVcfDepotDownloadActive(Boolean(response.download_active), response.active_job_id || "");
        return response;
      },
      layout: "fitColumns",
      height: "380px",
      placeholder: "No VCFDT tasks have been executed.",
      rowContextMenu: [
        {
          label: "View log",
          action: (_event, row) => {
            const logUrl = row.getData().log_url;
            if (logUrl) {
              openVcfDepotTaskLog(logUrl);
            }
          },
        },
      ],
      columns: [
        { title: "Task", field: "id", minWidth: 190, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
        { title: "Profile", field: "profile_name", minWidth: 130, formatter: (cell) => escapeHtml(cell.getValue() || "Unknown profile") },
        {
          title: "State",
          field: "status",
          width: 105,
          headerSort: false,
          formatter: (cell) => {
            const value = String(cell.getValue() || "unknown");
            const pill = value === "succeeded" ? "success" : value === "failed" ? "error" : "warn";
            return `<span class="status-pill ${pill}">${escapeHtml(value)}</span>`;
          },
        },
        { title: "Mode", field: "dry_run", width: 90, formatter: (cell) => cell.getValue() === "yes" ? "dry-run" : "real" },
        { title: "Created", field: "created_at", minWidth: 210 },
        { title: "Started", field: "started_at", minWidth: 210, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        { title: "Finished", field: "finished_at", minWidth: 210, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
      ],
    };
    vcfDepotTasksTable = window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "read-only",
      options: atlasoGridOptions27,
    }).table;
    if (vcfDepotTasksRefreshInterval) {
      window.clearInterval(vcfDepotTasksRefreshInterval);
    }
    vcfDepotTasksRefreshInterval = window.setInterval(refreshVcfDepotTasksTable, 2000);
  } catch (error) {
    showVcfDepotMessage(error instanceof Error ? error.message : "VCFDT tasks could not render. Showing the fallback table.");
  }
}

let vcfDepotTaskLogRefreshTimer = null;

async function openVcfDepotTaskLog(logUrl) {
  const modal = document.getElementById("vcf-depot-task-log-modal");
  const content = document.querySelector("[data-vcf-depot-task-log-content]");
  const title = document.querySelector("[data-vcf-depot-task-log-title]");
  const meta = document.querySelector("[data-vcf-depot-task-log-meta]");
  if (!(modal instanceof HTMLDialogElement) || !(content instanceof HTMLElement)) {
    return;
  }
  content.textContent = "Loading task log…";
  if (vcfDepotTaskLogRefreshTimer) {
    window.clearTimeout(vcfDepotTaskLogRefreshTimer);
    vcfDepotTaskLogRefreshTimer = null;
  }
  modal.showModal();
  const loadLog = async () => {
    try {
      const response = await fetch(logUrl, { headers: { "X-Atlaso-Task-Log": "1" } });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || "Unable to load the VCFDT task log.");
      }
      if (title instanceof HTMLElement) {
        title.textContent = `${payload.profile_name || "Unknown profile"} task log`;
      }
      if (meta instanceof HTMLElement) {
        meta.textContent = `${payload.job_id} · ${payload.status} · ${payload.updated_at || "not written"}`;
      }
      content.textContent = payload.text || "No task log is available.";
      registerAtlasoPrismLanguages();
      if (window.Prism && typeof window.Prism.highlightElement === "function") {
        window.Prism.highlightElement(content);
      }
      if (modal.open && ["pending", "running"].includes(payload.status)) {
        vcfDepotTaskLogRefreshTimer = window.setTimeout(loadLog, 2000);
      }
    } catch (error) {
      content.textContent = error instanceof Error ? error.message : "Unable to load the VCFDT task log.";
    }
  };
  await loadLog();
}

function initializeVcfDepotTaskLogModal() {
  const modal = document.getElementById("vcf-depot-task-log-modal");
  const closeButton = document.querySelector("[data-vcf-depot-task-log-close]");
  if (modal instanceof HTMLDialogElement && closeButton instanceof HTMLButtonElement) {
    closeButton.addEventListener("click", () => {
      if (vcfDepotTaskLogRefreshTimer) {
        window.clearTimeout(vcfDepotTaskLogRefreshTimer);
        vcfDepotTaskLogRefreshTimer = null;
      }
      modal.close();
    });
  }
}

let atlasoTasksTable = null;
let atlasoTasks = [];
let atlasoTaskComponentOptions = [];
let atlasoSelectedTaskId = "";
let atlasoNewTaskId = "";
let atlasoTasksRefreshTimer = 0;
let atlasoTasksReopenSelected = false;

function taskStatusActive(status) {
  return ["pending", "running"].includes(String(status || ""));
}

function setApplianceUpdateActionsDisabled(disabled) {
  const form = document.querySelector("[data-appliance-update-submit-form]");
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  if (disabled) {
    form.setAttribute("aria-busy", "true");
  } else {
    form.removeAttribute("aria-busy");
  }
  form.querySelectorAll("[data-appliance-update-action]").forEach((button) => {
    if (button instanceof HTMLButtonElement) {
      button.disabled = disabled;
    }
  });
}

function updateApplianceUpdateActions(tasks = atlasoTasks) {
  const page = document.querySelector("[data-tasks-page]");
  if (page?.dataset.taskType !== "appliance-update") {
    return;
  }
  setApplianceUpdateActionsDisabled(tasks.some((task) => !task.is_step && taskStatusActive(task.status)));
}

function taskById(taskId) {
  for (const task of atlasoTasks) {
    if (task.id === taskId) return task;
    const child = (task._children || []).find((item) => item.id === taskId);
    if (child) return child;
  }
  return null;
}

function taskStatusPillHtml(task) {
  return `<span class="status-pill ${escapeHtml(task.status_pill || "muted")}">${escapeHtml(task.status || "unknown")}</span>`;
}

function renderTaskDetail(task) {
  const modal = document.getElementById("task-detail-modal");
  if (!(modal instanceof HTMLDialogElement) || !task) {
    return;
  }
  atlasoSelectedTaskId = task.id;
  const title = modal.querySelector("[data-task-detail-title]");
  const statusPill = modal.querySelector("[data-task-detail-status]");
  const summary = modal.querySelector("[data-task-detail-summary]");
  const facts = modal.querySelector("[data-task-detail-facts]");
  const errorDetails = modal.querySelector("[data-task-detail-errors]");
  const errorContent = modal.querySelector("[data-task-detail-errors-content]");
  const consoleDetails = modal.querySelector("[data-task-detail-console]");
  const consoleContent = modal.querySelector("[data-task-detail-console-content]");
  const consoleErrorContent = modal.querySelector("[data-task-detail-console-error-content]");
  const result = modal.querySelector("[data-task-detail-result]");
  const cancelButton = modal.querySelector("[data-task-detail-cancel]");
  const logButton = modal.querySelector("[data-task-detail-log]");
  if (title instanceof HTMLElement) {
    title.textContent = `${task.type_label || task.type || "Task"} ${task.id}`;
  }
  if (statusPill instanceof HTMLElement) {
    statusPill.className = `status-pill ${task.status_pill || "muted"}`;
    statusPill.textContent = task.status || "unknown";
  }
  if (summary instanceof HTMLElement) {
    summary.textContent = task.summary || task.state || "";
  }
  if (facts instanceof HTMLElement) {
    facts.replaceChildren();
    [
      ["Type", task.type_label || task.type || "—"],
      ["State", task.state || task.status || "—"],
      ["Progress", `${task.progress_percent || 0}%`],
      ["Created", task.created_at || "—"],
      ["Started", task.started_at || "—"],
      ["Finished", task.finished_at || "—"],
      ["Created by", task.created_by || "—"],
    ].forEach(([label, value]) => {
      const row = document.createElement("div");
      const key = document.createElement("span");
      const val = document.createElement("strong");
      key.textContent = label;
      val.textContent = value;
      row.append(key, val);
      facts.append(row);
    });
  }
  if (errorDetails instanceof HTMLDetailsElement && errorContent instanceof HTMLElement) {
    const errorMessages = Array.isArray(task.error_messages) ? task.error_messages.filter(Boolean) : [];
    errorDetails.classList.toggle("hidden", errorMessages.length === 0);
    errorDetails.open = errorMessages.length > 0;
    errorContent.textContent = errorMessages.join("\n\n");
    highlightConfigPreviewElement(errorContent);
  }
  if (consoleDetails instanceof HTMLDetailsElement && consoleContent instanceof HTMLElement && consoleErrorContent instanceof HTMLElement) {
    const consoleStdout = String(task.console_stdout || "").trim();
    const consoleStderr = String(task.console_stderr || "").trim();
    const hasConsoleOutput = Boolean(consoleStdout || consoleStderr);
    consoleDetails.classList.toggle("hidden", !hasConsoleOutput);
    consoleDetails.open = hasConsoleOutput;
    consoleContent.textContent = consoleStdout;
    consoleContent.classList.toggle("hidden", !consoleStdout);
    highlightConfigPreviewElement(consoleContent);
    consoleErrorContent.textContent = consoleStderr ? `stderr:\n${consoleStderr}` : "";
    consoleErrorContent.classList.toggle("hidden", !consoleStderr);
  }
  if (result instanceof HTMLElement) {
    result.textContent = task.result_json || "{}";
    highlightConfigPreviewElement(result);
  }
  if (cancelButton instanceof HTMLButtonElement) {
    cancelButton.classList.toggle("hidden", !task.can_cancel);
    cancelButton.disabled = !task.can_cancel;
    cancelButton.dataset.taskId = task.id;
  }
  if (logButton instanceof HTMLButtonElement) {
    logButton.dataset.taskId = task.id;
    logButton.classList.toggle("hidden", Boolean(task.is_step));
  }
}

function openTaskDetail(taskOrId) {
  const task = typeof taskOrId === "string" ? taskById(taskOrId) : taskOrId;
  const modal = document.getElementById("task-detail-modal");
  if (!(modal instanceof HTMLDialogElement) || !task) {
    return;
  }
  renderTaskDetail(task);
  const url = new URL(window.location.href);
  url.searchParams.set("job_id", task.is_step ? task.job_id : task.id);
  window.history.replaceState({}, "", url);
  if (!modal.open) {
    modal.showModal();
  }
}

function applyTasksStatusPayload(payload, { reopen = false } = {}) {
  const page = document.querySelector("[data-tasks-page]");
  if (!(page instanceof HTMLElement)) {
    return [];
  }
  const queryId = atlasoSelectedTaskId || page.dataset.selectedTaskId || "";
  atlasoTasks = Array.isArray(payload.tasks) ? payload.tasks : [];
  const count = document.querySelector("[data-tasks-count]");
  if (count instanceof HTMLElement) {
    const active = Number(payload.active_count || 0);
    const total = Number(payload.total_count ?? atlasoTasks.length);
    const filtered = Number(payload.filtered_count ?? atlasoTasks.length);
    const taskCount = filtered === total ? `${total} tasks` : `${filtered} of ${total} tasks`;
    count.textContent = active ? `${active} active · ${taskCount}` : taskCount;
    count.className = `status-pill ${active ? "warn" : "muted"}`;
  }
  const selected = payload.selected_task || taskById(queryId);
  if (selected && (reopen || document.getElementById("task-detail-modal")?.open)) {
    renderTaskDetail(selected);
    if (reopen) {
      openTaskDetail(selected);
    }
  }
  updateApplianceUpdateActions(atlasoTasks);
  window.clearTimeout(atlasoTasksRefreshTimer);
  if (atlasoTasks.some((task) => taskStatusActive(task.status))) {
    atlasoTasksRefreshTimer = window.setTimeout(() => refreshTasksPage().catch(() => {}), 2000);
  }
  return atlasoTasks;
}

async function refreshTasksPage({ reopen = false } = {}) {
  const page = document.querySelector("[data-tasks-page]");
  if (!(page instanceof HTMLElement)) {
    return;
  }
  if (atlasoTasksTable) {
    atlasoTasksReopenSelected = reopen;
    await atlasoTasksTable.replaceData();
    return;
  }
  const queryId = atlasoSelectedTaskId || page.dataset.selectedTaskId || "";
  const response = await fetch(`/tasks/status?job_id=${encodeURIComponent(queryId)}`, { credentials: "same-origin" });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Unable to refresh tasks.");
  }
  applyTasksStatusPayload(payload, { reopen });
}

async function requestTasksTableData(_url, _config, params = {}) {
  const page = document.querySelector("[data-tasks-page]");
  const query = new URLSearchParams();
  query.set("job_id", atlasoSelectedTaskId || page?.dataset.selectedTaskId || "");
  if (page?.dataset.taskType) {
    query.set("task_type", page.dataset.taskType);
  }
  query.set("page", String(params.page || 1));
  query.set("size", String(params.size || 25));
  query.set("filters", JSON.stringify(params.filters || params.filter || []));
  const response = await fetch(`/tasks/status?${query.toString()}`, { credentials: "same-origin" });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Unable to filter tasks.");
  }
  return payload;
}

async function openTaskLog(taskId) {
  const modal = document.getElementById("task-log-modal");
  const title = document.querySelector("[data-task-log-title]");
  const meta = document.querySelector("[data-task-log-meta]");
  const content = document.querySelector("[data-task-log-content]");
  if (!(modal instanceof HTMLDialogElement) || !(content instanceof HTMLElement)) {
    return;
  }
  content.textContent = "Loading task log…";
  highlightConfigPreviewElement(content);
  if (title instanceof HTMLElement) {
    title.textContent = "Task log";
  }
  if (meta instanceof HTMLElement) {
    meta.textContent = taskId;
  }
  if (!modal.open) {
    modal.showModal();
  }
  try {
    const response = await fetch(`/tasks/${encodeURIComponent(taskId)}/log`, { credentials: "same-origin" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Unable to load task log.");
    }
    if (title instanceof HTMLElement) {
      title.textContent = payload.title || "Task log";
    }
    if (meta instanceof HTMLElement) {
      meta.textContent = `${payload.job_id || taskId} · ${payload.status || "unknown"}`;
    }
    content.textContent = payload.text || "No task log is available.";
    highlightConfigPreviewElement(content);
  } catch (error) {
    content.textContent = error instanceof Error ? error.message : "Unable to load task log.";
    highlightConfigPreviewElement(content);
  }
}

async function cancelTask(taskId) {
  const page = document.querySelector("[data-tasks-page]");
  if (!(page instanceof HTMLElement)) {
    return;
  }
  const confirmed = await requestConfirmation({
    title: "Cancel task",
    message: `Cancel task ${taskId}? If the worker is already inside a target system operation, Atlaso will request cancellation and record the task as cancelled.`,
    label: "Cancel task",
  });
  if (!confirmed) {
    return;
  }
  const body = new URLSearchParams();
  body.set("csrf", page.dataset.csrf || "");
  const response = await fetch(`/tasks/${encodeURIComponent(taskId)}/cancel`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Unable to cancel task.");
  }
  await refreshTasksPage();
  const task = payload.task || taskById(taskId);
  if (task) {
    renderTaskDetail(task);
  }
}

function initializeTasksPage() {
  const page = document.querySelector("[data-tasks-page]");
  if (!(page instanceof HTMLElement)) {
    return;
  }
  try {
    atlasoTasks = JSON.parse(page.dataset.tasks || "[]");
  } catch (_error) {
    atlasoTasks = [];
  }
  try {
    atlasoTaskComponentOptions = JSON.parse(page.dataset.taskComponentOptions || "[]");
  } catch (_error) {
    atlasoTaskComponentOptions = [];
  }
  atlasoSelectedTaskId = page.dataset.selectedTaskId || new URLSearchParams(window.location.search).get("job_id") || "";
  const shouldOpenSelected = Boolean(atlasoSelectedTaskId);
  atlasoTasksReopenSelected = shouldOpenSelected;
  const tableElement = document.getElementById("tasks-table");
  const fallback = document.getElementById(tableElement?.dataset.fallbackId || "");
  if (tableElement instanceof HTMLElement && typeof window.Tabulator === "function") {
    const initialComponentFilter = page.dataset.taskInitialComponentFilter || "";
    const componentFilterLocked = page.dataset.taskLockComponentFilter === "true";
    const atlasoGridOptions28 = {
      ajaxURL: "/tasks/status",
      ajaxParams: () => ({ job_id: atlasoSelectedTaskId || page.dataset.selectedTaskId || "" }),
      ajaxRequestFunc: requestTasksTableData,
      ajaxResponse: (_url, _params, response) => {
        applyTasksStatusPayload({ ...response, tasks: response.data || response.tasks || [] }, { reopen: atlasoTasksReopenSelected });
        atlasoTasksReopenSelected = false;
        return response;
      },
      layout: "fitColumns",
      height: page.dataset.taskGridHeight || "100%",
      pagination: true,
      paginationMode: "remote",
      paginationSize: 25,
      paginationCounter: "rows",
      filterMode: "remote",
      initialHeaderFilter: initialComponentFilter && !componentFilterLocked ? [{ field: "id", value: initialComponentFilter }] : [],
      headerFilterLiveFilterDelay: 500,
      placeholder: "No tasks have been recorded yet.",
      selectableRows: 1,
      rowContextMenu: [
        {
          label: "Details",
          action: (_event, row) => openTaskDetail(row.getData()),
        },
        {
          label: "Log",
          disabled: (component) => Boolean(component.getData().is_step),
          action: (_event, row) => openTaskLog(row.getData().id),
        },
        {
          label: "Cancel task",
          disabled: (component) => !component.getData().can_cancel,
          action: (_event, row) => {
            const task = row.getData();
            if (!task.can_cancel) {
              return;
            }
            cancelTask(task.id).catch((error) => window.alert(error instanceof Error ? error.message : "Unable to cancel task."));
          },
        },
      ],
      columns: [
        {
          title: "Status",
          field: "status",
          width: 130,
          formatter: (cell) => taskStatusPillHtml(cell.getRow().getData()),
          headerFilter: "list",
          headerFilterParams: { values: { "": "All", succeeded: "Succeeded", failed: "Failed", running: "Running", pending: "Pending", cancelled: "Cancelled" } },
          headerFilterFunc: "=",
        },
        {
          title: "Task / component",
          field: "id",
          minWidth: 260,
          widthGrow: 1.5,
          ...(componentFilterLocked ? {} : {
            headerFilter: "list",
            headerFilterParams: {
              values: atlasoTaskComponentOptions,
              autocomplete: true,
              freetext: true,
              allowEmpty: true,
              clearable: true,
              listOnEmpty: true,
            },
          headerFilterFunc: "like",
            headerFilterPlaceholder: "Choose or type custom",
          }),
          formatter: (cell) => {
            const data = cell.getRow().getData();
            const label = data.is_step ? data.label : data.type_label;
            const newBadge = data.id === atlasoNewTaskId ? '<span class="status-pill info task-grid-new-badge">New</span>' : "";
            return `<span class="service-name-cell"><strong>${escapeHtml(label || "Task")}${newBadge}</strong><small>${escapeHtml(data.id || "")}</small></span>`;
          },
        },
        {
          title: "State",
          field: "state",
          minWidth: 160,
          formatter: (cell) => escapeHtml(cell.getValue() || ""),
          headerFilter: "list",
          headerFilterParams: { values: { "": "All", pending: "Pending", running: "Running", succeeded: "Succeeded", failed: "Failed", cancelled: "Cancelled" } },
          headerFilterFunc: "=",
        },
        { title: "Progress", field: "progress_percent", width: 105, formatter: (cell) => `${Number(cell.getValue() || 0)}%` },
        { title: "Created", field: "created_at", minWidth: 190, formatter: (cell) => escapeHtml(cell.getValue() || "—"), headerFilter: "input", headerFilterPlaceholder: "Filter date" },
        { title: "Duration", field: "duration", width: 105, formatter: (cell) => applianceApplyDuration(cell.getRow().getData()) },
      ],
      dataTree: true,
      dataTreeStartExpanded: false,
      rowFormatter: (row) => {
        row.getElement().classList.toggle("task-grid-new-task", row.getData().id === atlasoNewTaskId);
      },
    };
    atlasoTasksTable = window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "read-only",
      onOpenRow: (rowData) => openTaskDetail(rowData),
      options: atlasoGridOptions28,
    }).table;
    atlasoTasksTable?.on("dataLoaded", () => {
      updateApplianceUpdateActions();
      if (!atlasoNewTaskId) {
        return;
      }
      const row = atlasoTasksTable.getRow(atlasoNewTaskId);
      if (row) {
        row.select();
        row.scrollTo("top", false).catch(() => {});
      }
    });
    atlasoTasksTable?.on("rowClick", (_event, row) => {
      atlasoSelectedTaskId = row.getData().id || "";
      row.select();
    });
    atlasoTasksTable?.on("rowDblClick", (_event, row) => openTaskDetail(row.getData()));
  }
  document.querySelector("[data-task-detail-close]")?.addEventListener("click", () => document.getElementById("task-detail-modal")?.close());
  document.querySelector("[data-task-log-close]")?.addEventListener("click", () => document.getElementById("task-log-modal")?.close());
  document.querySelector("[data-task-detail-log]")?.addEventListener("click", () => {
    if (atlasoSelectedTaskId) {
      openTaskLog(atlasoSelectedTaskId);
    }
  });
  document.querySelector("[data-task-detail-cancel]")?.addEventListener("click", () => {
    if (atlasoSelectedTaskId) {
      cancelTask(atlasoSelectedTaskId).catch((error) => window.alert(error instanceof Error ? error.message : "Unable to cancel task."));
    }
  });
  if (!atlasoTasksTable) {
    refreshTasksPage({ reopen: shouldOpenSelected }).catch(() => {
      if (shouldOpenSelected) {
        openTaskDetail(atlasoSelectedTaskId);
      }
    });
  }
}

function updateVcfDepotSummary(form, payload = {}) {
  const portInput = form.querySelector('input[name="port"]');
  const hostnameInput = form.querySelector('input[name="hostname"]');
  const userSelect = form.querySelector('select[name="http_user_id"]');
  const unauthenticatedInput = form.querySelector('input[name="allow_unauthenticated_access"]');
  const { interfaceLabel: bindInterfaceLabel, address, addressLabel, addresses } = serviceBindSelection(form, payload);
  const port = payload.port || portInput?.value || "443";
  const hostname = payload.hostname || hostnameInput?.value || "";
  const selectedUsername =
    userSelect instanceof HTMLSelectElement
      ? (userSelect.selectedOptions[0]?.textContent || "").replace(/\s+\(disabled\)\s*$/, "").trim()
      : "";
  const allowUnauthenticated =
    payload.allow_unauthenticated_access !== undefined
      ? Boolean(payload.allow_unauthenticated_access)
      : unauthenticatedInput instanceof HTMLInputElement && unauthenticatedInput.checked;
  const endpointValue = payload.endpoint || (port === "443" || port === 443 ? hostname : `${hostname}:${port}`);
  const endpoint = document.querySelector("[data-vcf-depot-endpoint]");
  const interfaceLabel = document.querySelector("[data-vcf-depot-interface]");
  const storePaths = document.querySelectorAll("[data-vcf-depot-store]");
  const toolVersions = document.querySelectorAll("[data-vcf-depot-tool-version]");
  const toolStatuses = document.querySelectorAll("[data-vcf-depot-tool-status]");
  const toolArchiveNames = document.querySelectorAll("[data-vcf-depot-tool-archive-name]");
  const toolUploadActions = document.querySelectorAll("[data-vcf-depot-tool-upload-action]");
  const toolUploadNames = document.querySelectorAll("[data-vcf-depot-tool-upload-name]");
  const toolResetPanels = document.querySelectorAll("[data-vcf-depot-tool-reset-panel], [data-vcf-depot-tool-reset-action]");
  const accessLabel = document.querySelector("[data-vcf-depot-access]");
  const dnsStatus = document.querySelector("[data-vcf-depot-dns-status]");
  const propertiesStatus = document.querySelector("[data-vcf-depot-properties-status]");
  const softwareDepotGenerateButtons = document.querySelectorAll("[data-vcf-depot-generate-id-modal-open]");
  if (endpoint instanceof HTMLElement) {
    endpoint.textContent = endpointValue || "depot hostname required";
  }
  if (interfaceLabel instanceof HTMLElement) {
    interfaceLabel.textContent = `${bindInterfaceLabel || "no interface"} / ${addressLabel || "no interface IP"}`;
  }
  if (payload.depot_store_path) {
    storePaths.forEach((storePath) => {
      if (storePath instanceof HTMLElement) {
        storePath.textContent = payload.depot_store_path;
      }
    });
  }
  if (accessLabel instanceof HTMLElement && (payload.allow_unauthenticated_access !== undefined || payload.http_username !== undefined || selectedUsername)) {
    accessLabel.textContent = allowUnauthenticated ? "unauthenticated" : payload.http_username || selectedUsername || "user required";
  }
  if (payload.tool_archive_name !== undefined) {
    const toolAvailable = Boolean(payload.tool_archive_name);
    toolStatuses.forEach((toolStatus) => {
      if (toolStatus instanceof HTMLElement) {
        toolStatus.textContent = toolAvailable ? "tool staged" : "upload required";
      }
    });
    toolArchiveNames.forEach((toolArchiveName) => {
      if (toolArchiveName instanceof HTMLElement) {
        toolArchiveName.textContent = payload.tool_archive_name || "no package staged";
      }
    });
    toolUploadActions.forEach((toolUploadAction) => {
      if (toolUploadAction instanceof HTMLElement) {
        toolUploadAction.textContent = toolAvailable ? "Update" : "Add";
      }
    });
    toolUploadNames.forEach((toolUploadName) => {
      if (toolUploadName instanceof HTMLElement) {
        toolUploadName.textContent = payload.tool_archive_name || "vcf-download-tool-*.tar.gz";
      }
    });
    toolResetPanels.forEach((toolResetPanel) => {
      if (toolResetPanel instanceof HTMLElement) {
        toolResetPanel.classList.toggle("hidden", !toolAvailable);
      }
    });
    softwareDepotGenerateButtons.forEach((softwareDepotGenerateButton) => {
      if (softwareDepotGenerateButton instanceof HTMLButtonElement) {
        softwareDepotGenerateButton.disabled = !toolAvailable;
      }
    });
    setVcfDepotToolDependentActions(toolAvailable);
  }
  if (payload.tool_version !== undefined) {
    toolVersions.forEach((toolVersion) => {
      if (toolVersion instanceof HTMLElement) {
        toolVersion.textContent = payload.tool_version || "not uploaded";
      }
    });
  }
  updateVcfDepotCredentialStatus(payload);
  if (propertiesStatus instanceof HTMLElement && payload.application_properties_source !== undefined) {
    propertiesStatus.textContent = payload.application_properties_updated_at
      ? `${payload.application_properties_source || "operator saved"} · saved`
      : payload.application_properties_source || "Atlaso default";
  }
  updateVcfDepotSoftwareDepotId(payload);
  if (dnsStatus instanceof HTMLElement && payload.dns_record_action !== undefined) {
    const dnsMessages = {
      created: "DNS alias and target records created for this endpoint.",
      updated: "DNS alias and target records updated for this endpoint.",
      unchanged: "DNS alias already matches this endpoint.",
      "created+removed-old": "DNS alias created and old endpoint records removed.",
      "updated+removed-old": "DNS alias updated and old endpoint records removed.",
      "unchanged+removed-old": "Old endpoint DNS alias and target records removed.",
      "removed-old": "Old endpoint DNS alias and target records removed.",
    };
    dnsStatus.textContent = dnsMessages[payload.dns_record_action] || "DNS alias follows the first selected service listener.";
  }
  const livePreviewPayload = {
    ...payload,
    hostname,
    endpoint: endpointValue,
    listen_address: address,
    listen_addresses: addresses,
    port,
    http_username: payload.http_username || selectedUsername,
    allow_unauthenticated_access: allowUnauthenticated,
    server_certificate: payload.server_certificate || hostname,
  };
  updateVcfDepotHttpsPreview(livePreviewPayload);
}

function updateVcfDepotCredentialStatus(payload = {}) {
  const tokenStatus = document.querySelector("[data-vcf-depot-token-status]");
  const activationStatus = document.querySelector("[data-vcf-depot-activation-status]");
  const credentialSeparator = document.querySelector("[data-vcf-depot-credential-separator]");
  const credentialsStatus = document.querySelector("[data-vcf-depot-credentials-status]");
  const currentTokenText = tokenStatus instanceof HTMLElement ? tokenStatus.textContent?.trim() || "" : "";
  const currentActivationText = activationStatus instanceof HTMLElement ? activationStatus.textContent?.trim() || "" : "";
  const tokenPresent =
    payload.download_token_present !== undefined ? Boolean(payload.download_token_present) : Boolean(currentTokenText && currentTokenText !== "token not uploaded");
  const activationPresent =
    payload.activation_code_present !== undefined
      ? Boolean(payload.activation_code_present)
      : Boolean(currentActivationText && currentActivationText !== "code not uploaded");
  const tokenName = payload.download_token_name || (tokenPresent ? currentTokenText : "");
  const activationName = payload.activation_code_name || (activationPresent ? currentActivationText : "");

  if (tokenStatus instanceof HTMLElement && payload.download_token_present !== undefined) {
    tokenStatus.textContent = tokenPresent ? tokenName || "token uploaded" : activationPresent ? "" : "token not uploaded";
  }
  if (activationStatus instanceof HTMLElement && payload.activation_code_present !== undefined) {
    activationStatus.textContent = activationPresent ? activationName || "code uploaded" : tokenPresent ? "" : "code not uploaded";
  }
  if (credentialSeparator instanceof HTMLElement) {
    credentialSeparator.textContent = tokenPresent && activationPresent ? " / " : tokenPresent || activationPresent ? "" : " / ";
  }
  if (credentialsStatus instanceof HTMLElement) {
    const staged = [];
    if (tokenPresent) {
      staged.push(`Download token staged${tokenName && tokenName !== "token uploaded" ? `: ${tokenName}` : ""}`);
    }
    if (activationPresent) {
      staged.push(`Activation code staged${activationName && activationName !== "code uploaded" ? `: ${activationName}` : ""}`);
    }
    credentialsStatus.textContent = staged.length
      ? `${staged.join(" · ")}. Runtime files refresh during Appliance Apply or profile download.`
      : "No Broadcom credentials staged.";
  }
}

function initializeApplianceUpdateSubmission() {
  const form = document.querySelector("[data-appliance-update-submit-form]");
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  updateApplianceUpdateActions();
  form.addEventListener("submit", async (event) => {
    const submitter = event.submitter;
    if (!(submitter instanceof HTMLButtonElement)) {
      return;
    }
    event.preventDefault();
    setApplianceUpdateActionsDisabled(true);
    try {
      const response = await fetch(submitter.formAction, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        body: new FormData(form),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || "Unable to start the appliance update task.");
      }
      atlasoNewTaskId = payload.job_id || "";
      atlasoSelectedTaskId = atlasoNewTaskId;
      const page = document.querySelector("[data-tasks-page]");
      if (page instanceof HTMLElement) {
        page.dataset.selectedTaskId = atlasoNewTaskId;
      }
      await refreshTasksPage();
    } catch (error) {
      updateApplianceUpdateActions();
      window.alert(error instanceof Error ? error.message : "Unable to start the appliance update task.");
    }
  });
}

function setVcfDepotToolDependentActions(toolAvailable) {
  document.querySelectorAll("[data-vcf-depot-requires-tool]").forEach((control) => {
    if (control instanceof HTMLButtonElement) {
      control.disabled = !toolAvailable;
    }
  });
}

function updateVcfDepotSoftwareDepotId(payload = {}) {
  const softwareDepotId = document.querySelector("[data-vcf-depot-software-depot-id]");
  const softwareDepotCell = document.querySelector("[data-vcf-depot-software-depot-cell]");
  const softwareDepotMessage = document.querySelector("[data-vcf-depot-software-depot-message]");
  const softwareDepotCopy = document.querySelector("[data-vcf-depot-software-depot-copy]");
  if (softwareDepotId instanceof HTMLElement && payload.software_depot_id !== undefined) {
    const depotId = payload.software_depot_id || "";
    if (softwareDepotId instanceof HTMLInputElement) {
      softwareDepotId.value = depotId;
    } else {
      softwareDepotId.textContent = depotId;
    }
    softwareDepotId.classList.toggle("hidden", !depotId);
    if (softwareDepotCopy instanceof HTMLButtonElement) {
      softwareDepotCopy.dataset.copyValue = depotId;
      softwareDepotCopy.classList.toggle("hidden", !depotId);
    }
    const button = softwareDepotCell?.querySelector("[data-vcf-depot-generate-id-modal-open]");
    if (button instanceof HTMLButtonElement) {
      button.textContent = "↻";
      button.classList.add("icon-button");
      button.classList.remove("compact-button");
      button.setAttribute("aria-label", "Refresh software depot ID");
      button.setAttribute("title", "Refresh software depot ID");
    }
  }
  if (softwareDepotMessage instanceof HTMLElement && (payload.software_depot_id_error !== undefined || payload.software_depot_id_generated_at !== undefined)) {
    if (payload.software_depot_id_error) {
      softwareDepotMessage.textContent = payload.software_depot_id_error;
      softwareDepotMessage.classList.add("error-text");
    } else if (payload.software_depot_id_generated_at) {
      softwareDepotMessage.textContent = `Generated ${new Date(payload.software_depot_id_generated_at).toLocaleString()}.`;
      softwareDepotMessage.classList.remove("error-text");
    } else {
      softwareDepotMessage.textContent = "Upload VCFDT, then submit VCF Offline Depot through Appliance Apply to generate the software depot ID.";
      softwareDepotMessage.classList.remove("error-text");
    }
  }
}

function formatNginxListen(address, port) {
  const rawAddress = String(address || "").trim();
  const normalizedAddress = rawAddress.startsWith("[") && rawAddress.endsWith("]")
    ? rawAddress.slice(1, -1)
    : rawAddress;
  return normalizedAddress.includes(":")
    ? `[${normalizedAddress}]:${port}`
    : `${normalizedAddress}:${port}`;
}

function updateVcfDepotHttpsPreview(payload = {}) {
  const httpsPreview = document.querySelector("[data-vcf-depot-https-preview]");
  if (!(httpsPreview instanceof HTMLElement)) {
    return;
  }
  if (payload.https_config_preview !== undefined) {
    httpsPreview.textContent = payload.https_config_preview;
    highlightConfigPreviewElement(httpsPreview);
    return;
  }
  const hostname = payload.hostname || "depot.atlaso.internal";
  const endpoint = payload.endpoint || hostname;
  const port = payload.port || "443";
  const listenAddresses = Array.isArray(payload.listen_addresses)
    ? payload.listen_addresses
    : String(payload.listen_address || "")
        .split(/[\n,]+/)
        .map((value) => value.trim())
        .filter(Boolean);
  const listenLines = (listenAddresses.length ? listenAddresses : ["0.0.0.0"]).map(
    (listenAddress) => `  listen ${formatNginxListen(listenAddress, port)} ssl;`,
  );
  const depotStorePath = payload.depot_store_path || document.querySelector("[data-vcf-depot-store]")?.textContent || "/mnt/atlaso-vcf-offline-depot";
  const certificateName = payload.server_certificate || hostname;
  const username = payload.http_username || "vcf-depot";
  const authLines = payload.allow_unauthenticated_access
    ? []
    : [
        "    satisfy any;",
        '    auth_basic "VCF Offline Depot";',
        "    auth_basic_user_file /etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd;",
        "    auth_request /_atlaso_depot_auth;",
        "    error_page 401 = /_atlaso_depot_login;",
      ];
  httpsPreview.textContent = [
    "# Managed by Atlaso. Local changes may be overwritten.",
    "# Dry-run preview of desired HTTPS endpoint for the VCF Offline Depot.",
    `# Depot store: ${depotStorePath}`,
    `# VCF endpoint: https://${endpoint}/PROD/`,
    `# Atlaso VCF Offline Depot unauthenticated access: ${payload.allow_unauthenticated_access ? "true" : "false"}`,
    `# Atlaso VCF Offline Depot user: ${payload.allow_unauthenticated_access ? "none" : username}`,
    "",
    "server {",
    ...listenLines,
    `  server_name ${hostname};`,
    `  ssl_certificate /etc/atlaso/vcf-offline-depot/certs/${certificateName}.crt;`,
    `  ssl_certificate_key /etc/atlaso/vcf-offline-depot/certs/${certificateName}.key;`,
    "",
    "  location = / {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location ^~ /static/ {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /favicon.ico {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /manifest.webmanifest {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /service-worker.js {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /ca {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location ^~ /ca/ {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /requests {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location ^~ /requests/ {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /PROD {",
    "    return 301 /PROD/;",
    "  }",
    "",
    "  location = /PROD/login {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /PROD/logout {",
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /_atlaso_depot_auth {",
    "    internal;",
    "    proxy_pass http://127.0.0.1:8000/PROD/auth-check;",
    "    proxy_pass_request_body off;",
    "    proxy_set_header Content-Length \"\";",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Original-URI $request_uri;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /_atlaso_depot_login {",
    "    internal;",
    "    proxy_pass http://127.0.0.1:8000/PROD/auth-failure;",
    "    proxy_pass_request_body off;",
    '    proxy_set_header Content-Length "";',
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Original-URI $request_uri;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "  }",
    "",
    "  location = /PROD/ {",
    ...(payload.allow_unauthenticated_access
      ? []
      : [
          "    satisfy any;",
          '    auth_basic "VCF Offline Depot";',
          "    auth_basic_user_file /etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd;",
          "    auth_request /_atlaso_depot_auth;",
          "    error_page 401 = /_atlaso_depot_login;",
        ]),
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "    proxy_set_header X-Atlaso-Depot-Basic-User $remote_user;",
    "  }",
    "",
    "  location ~ ^/PROD/.*/$ {",
    ...(payload.allow_unauthenticated_access
      ? []
      : [
          "    satisfy any;",
          '    auth_basic "VCF Offline Depot";',
          "    auth_basic_user_file /etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd;",
          "    auth_request /_atlaso_depot_auth;",
          "    error_page 401 = /_atlaso_depot_login;",
        ]),
    "    proxy_pass http://127.0.0.1:8000;",
    "    proxy_set_header Host $host;",
    "    proxy_set_header X-Real-IP $remote_addr;",
    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "    proxy_set_header X-Forwarded-Proto https;",
    "    proxy_set_header X-Atlaso-Depot-Basic-User $remote_user;",
    "  }",
    "",
    "  location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$ {",
    ...authLines,
    `    alias ${depotStorePath.replace(/\/+$/, "")}/PROD/$1;`,
    "    sendfile on;",
    "    tcp_nopush on;",
    "    directio 8m;",
    "    autoindex off;",
    "    types { }",
    "    default_type application/octet-stream;",
    "  }",
    "",
    "  location / {",
    "    return 404;",
    "  }",
    "}",
  ].join("\n") + "\n";
  highlightConfigPreviewElement(httpsPreview);
}

function updateVcfDepotValidation(payload = {}) {
  const status = document.querySelector("[data-vcf-depot-validation-status]");
  const validationPanel = status?.closest(".panel");
  const applyButton = document.querySelector("[data-vcf-depot-apply-button]");
  const configPath = document.querySelector("[data-vcf-depot-config-path]");
  const httpsPreview = document.querySelector("[data-vcf-depot-https-preview]");
  const commandPreview = document.querySelector("[data-vcf-depot-command-preview]");
  const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
  const warnings = Array.isArray(payload.validation_warnings) ? payload.validation_warnings : [];
  if (status instanceof HTMLElement && payload.valid !== undefined) {
    status.textContent = payload.valid ? "valid" : "needs attention";
    status.classList.toggle("good", Boolean(payload.valid));
    status.classList.toggle("warn", !payload.valid);
  }
  if (applyButton instanceof HTMLButtonElement && payload.valid !== undefined) {
    applyButton.disabled = !payload.valid;
  }
  if (configPath instanceof HTMLElement && payload.config_path) {
    configPath.textContent = payload.config_path;
  }
  updateVcfDepotHttpsPreview(payload);
  if (commandPreview instanceof HTMLElement && payload.command_preview !== undefined) {
    commandPreview.textContent = payload.command_preview;
    highlightConfigPreviewElement(commandPreview);
  }
  if (validationPanel instanceof HTMLElement && payload.valid !== undefined) {
    const previewAnchor = validationPanel.querySelector("[data-config-preview-row]");
    let errorList = validationPanel.querySelector("[data-vcf-depot-validation-errors]");
    let message = validationPanel.querySelector("[data-vcf-depot-validation-message]");
    let warningList = validationPanel.querySelector("[data-vcf-depot-validation-warnings]");
    if (payload.valid) {
      if (errorList) {
        errorList.remove();
      }
      if (!(message instanceof HTMLElement)) {
        message = document.createElement("p");
        message.className = "muted";
        message.setAttribute("data-vcf-depot-validation-message", "");
        validationPanel.insertBefore(message, previewAnchor);
      }
      message.textContent = "The desired VCF Offline Depot state passes Atlaso validation. Appliance validation still runs through the allowlisted depot helper before apply.";
    } else {
      if (message) {
        message.remove();
      }
      if (!(errorList instanceof HTMLElement)) {
        errorList = document.createElement("ul");
        errorList.className = "error-list";
        errorList.setAttribute("data-vcf-depot-validation-errors", "");
        validationPanel.insertBefore(errorList, previewAnchor);
      }
      errorList.innerHTML = "";
      errors.forEach((error) => {
        const item = document.createElement("li");
        item.textContent = error;
        errorList.appendChild(item);
      });
    }
    if (!(warningList instanceof HTMLElement)) {
      warningList = document.createElement("ul");
      warningList.className = "warning-list";
      warningList.setAttribute("data-vcf-depot-validation-warnings", "");
      validationPanel.insertBefore(warningList, previewAnchor);
    }
    warningList.innerHTML = "";
    warnings.forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = warning;
      warningList.appendChild(item);
    });
    warningList.classList.toggle("hidden", warnings.length === 0);
  }
}

function initializeVcfDepotSettings(root = document) {
  root.querySelectorAll("[data-vcf-depot-settings]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (form.dataset.vcfDepotSettingsInitialized === "1") return;
    form.dataset.vcfDepotSettingsInitialized = "1";
    const portInput = form.querySelector('input[name="port"]');
    const hostnameInput = form.querySelector('input[name="hostname"]');
    const refresh = () => updateVcfDepotSummary(form);
    [portInput, hostnameInput].forEach((input) => {
      if (input instanceof HTMLElement) {
        input.addEventListener("input", refresh);
        input.addEventListener("change", refresh);
      }
    });
    form.addEventListener("atlaso:autosave-success", (event) => {
      const payload = event.detail || {};
      updateVcfDepotSummary(form, payload);
      updateVcfDepotValidation(payload);
      if (payload.tool_archive_uploaded) {
        window.location.reload();
      }
    });
    refresh();
  });
}

function initializeVcfDepotSoftwareDepotIdGenerator() {
  const modal = document.getElementById("vcf-depot-generate-id-modal");
  document.querySelectorAll("[data-vcf-depot-generate-id-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.showModal();
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-generate-id-modal-cancel]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("cancel");
      }
    });
  });
  const form = modal?.querySelector("form");
  if (form instanceof HTMLFormElement) {
    form.addEventListener("submit", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("submit");
      }
      const submitButton = form.querySelector('button[type="submit"]');
      if (submitButton instanceof HTMLButtonElement) {
        submitButton.disabled = true;
        submitButton.textContent = "Creating task…";
      }
    });
  }
}

function initializeVcfDepotToolResetModal() {
  const modal = document.getElementById("vcf-depot-tool-reset-modal");
  document.querySelectorAll("[data-vcf-depot-tool-reset-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.showModal();
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-tool-reset-modal-cancel]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("cancel");
      }
    });
  });
}

function initializeVcfDepotTokenPaste() {
  const modal = document.getElementById("vcf-depot-token-modal");
  document.querySelectorAll("[data-vcf-depot-token-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.showModal();
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-token-modal-cancel]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("cancel");
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-token-paste]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const button = form.querySelector("button[type='submit']");
    const textarea = form.querySelector('textarea[name="download_token_text"]');
    const fileInput = form.querySelector('input[name="download_token_file"]');
    const status = form.querySelector("[data-vcf-depot-token-paste-status]");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const hasPastedToken = textarea instanceof HTMLTextAreaElement && Boolean(textarea.value.trim());
      const hasTokenFile = fileInput instanceof HTMLInputElement && Boolean(fileInput.files?.length);
      if (!hasPastedToken && !hasTokenFile) {
        if (status instanceof HTMLElement) {
          status.textContent = "Choose a token file or paste token text.";
          status.classList.add("error-text");
        }
        return;
      }
      if (button instanceof HTMLButtonElement) {
        button.disabled = true;
      }
      if (status instanceof HTMLElement) {
        status.textContent = "Staging token file...";
        status.classList.remove("error-text");
      }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { "X-Atlaso-Autosave": "1" },
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || "Download token could not be staged.");
        }
        const settingsForm = document.querySelector("[data-vcf-depot-settings]");
        if (settingsForm instanceof HTMLFormElement) {
          updateVcfDepotSummary(settingsForm, payload);
        }
        updateVcfDepotCredentialStatus(payload);
        updateVcfDepotValidation(payload);
        if (textarea instanceof HTMLTextAreaElement) {
          textarea.value = "";
        }
        if (fileInput instanceof HTMLInputElement) {
          fileInput.value = "";
        }
        form.querySelectorAll("[data-file-upload-name]").forEach((label) => {
          if (label instanceof HTMLElement) {
            label.textContent = "no file selected";
          }
        });
        if (status instanceof HTMLElement) {
          status.textContent = "Token file staged. Contents are hidden.";
          status.classList.remove("error-text");
        }
        if (modal instanceof HTMLDialogElement && modal.open) {
          modal.close("saved");
        }
      } catch (error) {
        if (status instanceof HTMLElement) {
          status.textContent = error instanceof Error ? error.message : "Download token could not be staged.";
          status.classList.add("error-text");
        }
      } finally {
        if (button instanceof HTMLButtonElement) {
          button.disabled = false;
        }
      }
    });
  });
}

function initializeVcfDepotActivationPaste() {
  const modal = document.getElementById("vcf-depot-activation-modal");
  document.querySelectorAll("[data-vcf-depot-activation-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.showModal();
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-activation-modal-cancel]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("cancel");
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-activation-paste]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const button = form.querySelector("button[type='submit']");
    const textarea = form.querySelector('textarea[name="activation_code_text"]');
    const fileInput = form.querySelector('input[name="activation_code_file"]');
    const status = form.querySelector("[data-vcf-depot-activation-paste-status]");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const hasPastedCode = textarea instanceof HTMLTextAreaElement && Boolean(textarea.value.trim());
      const hasCodeFile = fileInput instanceof HTMLInputElement && Boolean(fileInput.files?.length);
      if (!hasPastedCode && !hasCodeFile) {
        if (status instanceof HTMLElement) {
          status.textContent = "Choose an activation file or paste activation-code text.";
          status.classList.add("error-text");
        }
        return;
      }
      if (button instanceof HTMLButtonElement) {
        button.disabled = true;
      }
      if (status instanceof HTMLElement) {
        status.textContent = "Staging activation-code file...";
        status.classList.remove("error-text");
      }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { "X-Atlaso-Autosave": "1" },
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || "Activation code could not be staged.");
        }
        const settingsForm = document.querySelector("[data-vcf-depot-settings]");
        if (settingsForm instanceof HTMLFormElement) {
          updateVcfDepotSummary(settingsForm, payload);
        }
        updateVcfDepotValidation(payload);
        if (textarea instanceof HTMLTextAreaElement) {
          textarea.value = "";
        }
        if (fileInput instanceof HTMLInputElement) {
          fileInput.value = "";
        }
        if (status instanceof HTMLElement) {
          status.textContent = "Activation-code file staged. Contents are hidden.";
          status.classList.remove("error-text");
        }
        if (modal instanceof HTMLDialogElement && modal.open) {
          modal.close("saved");
        }
      } catch (error) {
        if (status instanceof HTMLElement) {
          status.textContent = error instanceof Error ? error.message : "Activation code could not be staged.";
          status.classList.add("error-text");
        }
      } finally {
        if (button instanceof HTMLButtonElement) {
          button.disabled = false;
        }
      }
    });
  });
}

function initializeVcfDepotCredentialsPaste() {
  const modal = document.getElementById("vcf-depot-credentials-modal");
  document.querySelectorAll("[data-vcf-depot-credentials-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.showModal();
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-credentials-modal-cancel]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("cancel");
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-credentials-paste]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const button = form.querySelector("button[type='submit']");
    const textarea = form.querySelector('textarea[name="credential_text"]');
    const fileInput = form.querySelector('input[name="credential_file"]');
    const status = form.querySelector("[data-vcf-depot-credentials-paste-status]");
    const typeSelect = form.querySelector('select[name="credential_type"]');
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const hasPastedCredential = textarea instanceof HTMLTextAreaElement && Boolean(textarea.value.trim());
      const hasCredentialFile = fileInput instanceof HTMLInputElement && Boolean(fileInput.files?.length);
      if (!hasPastedCredential && !hasCredentialFile) {
        if (status instanceof HTMLElement) {
          status.textContent = "Choose a credential file or paste credential text.";
          status.classList.add("error-text");
        }
        return;
      }
      if (button instanceof HTMLButtonElement) {
        button.disabled = true;
      }
      if (status instanceof HTMLElement) {
        status.textContent = "Staging Broadcom credential...";
        status.classList.remove("error-text");
      }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { "X-Atlaso-Autosave": "1" },
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || "Broadcom credential could not be staged.");
        }
        const settingsForm = document.querySelector("[data-vcf-depot-settings]");
        if (settingsForm instanceof HTMLFormElement) {
          updateVcfDepotSummary(settingsForm, payload);
        }
        updateVcfDepotCredentialStatus(payload);
        updateVcfDepotValidation(payload);
        if (textarea instanceof HTMLTextAreaElement) {
          textarea.value = "";
        }
        if (fileInput instanceof HTMLInputElement) {
          fileInput.value = "";
        }
        form.querySelectorAll("[data-file-upload-name]").forEach((label) => {
          if (label instanceof HTMLElement) {
            label.textContent = "no file selected";
          }
        });
        if (status instanceof HTMLElement) {
          const credentialLabel = typeSelect instanceof HTMLSelectElement && typeSelect.value === "activation_code" ? "Activation code" : "Download token";
          status.textContent = `${credentialLabel} staged. Contents are hidden.`;
          status.classList.remove("error-text");
        }
        if (modal instanceof HTMLDialogElement && modal.open) {
          modal.close("saved");
        }
      } catch (error) {
        if (status instanceof HTMLElement) {
          status.textContent = error instanceof Error ? error.message : "Broadcom credential could not be staged.";
          status.classList.add("error-text");
        }
      } finally {
        if (button instanceof HTMLButtonElement) {
          button.disabled = false;
        }
      }
    });
  });
}

function initializeVcfDepotPropertiesEditor() {
  const modal = document.getElementById("vcf-depot-properties-modal");
  document.querySelectorAll("[data-vcf-depot-properties-modal-open]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.showModal();
        const textarea = modal.querySelector("[data-vcf-depot-properties-textarea]");
        if (window.AtlasoMonaco && typeof window.AtlasoMonaco.focus === "function" && textarea instanceof HTMLTextAreaElement) {
          window.AtlasoMonaco.focus(textarea);
        }
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-properties-modal-cancel]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (modal instanceof HTMLDialogElement) {
        modal.close("cancel");
      }
    });
  });
  document.querySelectorAll("[data-vcf-depot-properties-editor]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const button = form.querySelector("button[type='submit']");
    const textarea = form.querySelector("[data-vcf-depot-properties-textarea]");
    const status = form.querySelector("[data-vcf-depot-properties-save-status]");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (textarea instanceof HTMLTextAreaElement && window.AtlasoMonaco) textarea.value = window.AtlasoMonaco.getValue(textarea);
      if (!(textarea instanceof HTMLTextAreaElement) || !textarea.value.trim()) {
        if (status instanceof HTMLElement) {
          status.textContent = "application-prodv2.properties cannot be empty.";
          status.classList.add("error-text");
        }
        return;
      }
      if (button instanceof HTMLButtonElement) {
        button.disabled = true;
      }
      if (status instanceof HTMLElement) {
        status.textContent = "Saving application properties...";
        status.classList.remove("error-text");
      }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { "X-Atlaso-Autosave": "1" },
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.detail || "Application properties could not be saved.");
        }
        const settingsForm = document.querySelector("[data-vcf-depot-settings]");
        if (settingsForm instanceof HTMLFormElement) {
          updateVcfDepotSummary(settingsForm, payload);
        }
        updateVcfDepotValidation(payload);
        if (status instanceof HTMLElement) {
          status.textContent = "Application properties saved as desired state.";
          status.classList.remove("error-text");
        }
        if (modal instanceof HTMLDialogElement && modal.open) {
          modal.close("saved");
        }
      } catch (error) {
        if (status instanceof HTMLElement) {
          status.textContent = error instanceof Error ? error.message : "Application properties could not be saved.";
          status.classList.add("error-text");
        }
      } finally {
        if (button instanceof HTMLButtonElement) {
          button.disabled = false;
        }
      }
    });
  });
}

function initializeFileUploadControls() {
  document.querySelectorAll("[data-file-upload-input]").forEach((input) => {
    if (!(input instanceof HTMLInputElement)) {
      return;
    }
    const control = input.closest(".file-upload-control");
    const fileName = control?.querySelector("[data-file-upload-name]");
    input.addEventListener("change", () => {
      if (fileName instanceof HTMLElement) {
        fileName.textContent = input.files?.[0]?.name || "PEM, CRT, or CER file";
      }
    });
  });
}

function initializeEsxiIsoUploadForms() {
  document.querySelectorAll("[data-esxi-iso-upload]").forEach((form) => {
    if (!(form instanceof HTMLFormElement) || form.dataset.esxiIsoUploadInitialized === "1") {
      return;
    }
    form.dataset.esxiIsoUploadInitialized = "1";
    const fileInput = form.querySelector('input[type="file"][name="iso_file"]');
    const button = form.querySelector("[data-esxi-iso-upload-button]");
    const progress = form.querySelector("[data-esxi-iso-upload-progress]");
    const status = form.querySelector("[data-esxi-iso-upload-status]");
    const setStatus = (message, state = "idle") => {
      if (status instanceof HTMLElement) {
        status.textContent = message;
        status.dataset.state = state;
      }
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!(fileInput instanceof HTMLInputElement) || !fileInput.files || fileInput.files.length < 1) {
        setStatus("Choose an ESXi installer ISO before uploading.", "error");
        return;
      }
      const file = fileInput.files[0];
      if (!file.name.toLowerCase().endsWith(".iso")) {
        setStatus("Choose a .iso installer file.", "error");
        return;
      }
      const xhr = new XMLHttpRequest();
      xhr.open("POST", form.action);
      xhr.setRequestHeader("X-Atlaso-Upload", "1");
      xhr.upload.addEventListener("loadstart", () => {
        if (progress instanceof HTMLProgressElement) {
          progress.hidden = false;
          progress.value = 0;
        }
        if (button instanceof HTMLButtonElement) {
          button.disabled = true;
        }
        setStatus(`Uploading ${file.name}...`, "saving");
      });
      xhr.upload.addEventListener("progress", (progressEvent) => {
        if (progress instanceof HTMLProgressElement && progressEvent.lengthComputable) {
          const percent = Math.max(0, Math.min(100, Math.round((progressEvent.loaded / progressEvent.total) * 100)));
          progress.value = percent;
          setStatus(`Uploading ${file.name}: ${percent}%`, "saving");
        }
      });
      xhr.addEventListener("load", () => {
        let payload = {};
        try {
          payload = xhr.responseText ? JSON.parse(xhr.responseText) : {};
        } catch (_error) {
          payload = {};
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          const uploadedName = payload.name || file.name;
          setStatus(`${uploadedName} uploaded. Refreshing ISO choices...`, "saved");
          rememberActiveTab("atlaso:esxi-pxe:active-tab", "esxi-pxe-isos-panel");
          if (window.location.pathname === "/esxi-pxe") {
            window.location.hash = "esxi-pxe-isos-panel";
            window.location.reload();
          } else {
            window.location.href = "/esxi-pxe#esxi-pxe-isos-panel";
          }
          return;
        }
        const message =
          payload.detail ||
          (xhr.status === 413
            ? "Upload is too large. ESXi installer ISO uploads are limited to 1 GB."
            : `Upload failed with HTTP ${xhr.status}.`);
        setStatus(message, "error");
      });
      xhr.addEventListener("error", () => {
        setStatus("Upload failed before Atlaso received the file. Check appliance connectivity and upload size.", "error");
      });
      xhr.addEventListener("abort", () => {
        setStatus("Upload canceled.", "error");
      });
      xhr.addEventListener("loadend", () => {
        if (button instanceof HTMLButtonElement) {
          button.disabled = false;
        }
      });
      xhr.send(new FormData(form));
    });
  });
}

function initializeTagEditors(root = document) {
  root.querySelectorAll("[data-tag-editor]").forEach((editor) => {
    if (editor instanceof HTMLElement && editor.dataset.tagEditorInitialized === "1") {
      return;
    }
    const input = editor.querySelector("[data-tag-entry]");
    const list = editor.querySelector("[data-tag-list]");
    const toggle = editor.querySelector("[data-tag-menu-toggle]");
    const menu = editor.querySelector("[data-tag-menu]");
    const name = editor.dataset.tagName || "";
    const singleValue = editor.hasAttribute("data-tag-single");
    if (!(editor instanceof HTMLElement) || !(input instanceof HTMLInputElement) || !(list instanceof HTMLElement) || !name) {
      return;
    }
    editor.dataset.tagEditorInitialized = "1";

    const currentValues = () =>
      Array.from(list.querySelectorAll(".tag-token")).map((item) => item.getAttribute("data-value") || "");

    const notifyChanged = () => {
      editor.dispatchEvent(new CustomEvent("tag-editor:change", { bubbles: true }));
    };

    const removeToken = (token) => {
      if (token.hasAttribute("data-tag-locked")) {
        return;
      }
      token.remove();
      refreshMenu();
      input.focus();
      notifyChanged();
    };

    const refreshMenu = () => {
      if (!(menu instanceof HTMLElement)) {
        return;
      }
      const selected = currentValues().map((item) => item.toLowerCase());
      let visibleOptions = 0;
      menu.querySelectorAll("[data-tag-option]").forEach((option) => {
        if (!(option instanceof HTMLElement)) {
          return;
        }
        const value = option.getAttribute("data-tag-option") || "";
        const isHidden = selected.includes(value.toLowerCase());
        option.classList.toggle("hidden", isHidden);
        if (!isHidden) {
          visibleOptions += 1;
        }
      });
      const emptyMessage = menu.dataset.tagEmptyMessage || "No options available.";
      let emptyState = menu.querySelector("[data-tag-empty]");
      if (!(emptyState instanceof HTMLElement)) {
        emptyState = document.createElement("div");
        emptyState.className = "tag-empty-option";
        emptyState.setAttribute("data-tag-empty", "");
        emptyState.setAttribute("role", "note");
        menu.append(emptyState);
      }
      emptyState.textContent = emptyMessage;
      emptyState.classList.toggle("hidden", visibleOptions > 0);
    };

    const displayLabelForValue = (value) => {
      if (!(menu instanceof HTMLElement)) {
        return value;
      }
      const option = [...menu.querySelectorAll("[data-tag-option]")]
        .find((candidate) => candidate.dataset.tagOption === value);
      if (option instanceof HTMLElement) {
        return option.getAttribute("data-tag-label") || option.textContent.trim() || value;
      }
      return value;
    };

    const addValue = (rawValue) => {
      const value = String(rawValue || "").trim().replace(/,$/, "");
      if (!value || currentValues().some((item) => item.toLowerCase() === value.toLowerCase())) {
        return;
      }
      if (singleValue) {
        list.querySelectorAll(".tag-token:not([data-tag-locked])").forEach((token) => token.remove());
      }

      const token = document.createElement("span");
      token.className = "tag-token";
      token.setAttribute("data-value", value);

      const label = document.createElement("span");
      label.textContent = displayLabelForValue(value);

      const remove = document.createElement("button");
      remove.type = "button";
      remove.setAttribute("data-tag-remove", "");
      remove.setAttribute("aria-label", `Remove ${value}`);
      remove.textContent = "×";
      remove.addEventListener("click", () => removeToken(token));

      const hidden = document.createElement("input");
      hidden.type = "hidden";
      hidden.name = name;
      hidden.value = value;

      token.append(label, remove, hidden);
      list.append(token);
      refreshMenu();
      notifyChanged();
    };

    const addInputValues = () => {
      input.value
        .split(/[\n,]+/)
        .map((value) => value.trim())
        .filter(Boolean)
        .forEach(addValue);
      input.value = "";
    };

    list.querySelectorAll("[data-tag-remove]").forEach((button) => {
      button.addEventListener("click", () => {
        const token = button.closest(".tag-token");
        if (token instanceof HTMLElement) {
          removeToken(token);
        }
      });
    });

    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === "," || event.key === "Tab") {
        if (input.value.trim()) {
          event.preventDefault();
          addInputValues();
        }
      } else if (event.key === "Backspace" && !input.value) {
        const removableTokens = list.querySelectorAll(".tag-token:not([data-tag-locked])");
        const lastToken = removableTokens[removableTokens.length - 1];
        if (lastToken instanceof HTMLElement) {
          removeToken(lastToken);
        }
      }
    });

    input.addEventListener("paste", () => {
      window.setTimeout(addInputValues, 0);
    });

    input.addEventListener("blur", addInputValues);
    if (toggle instanceof HTMLButtonElement && menu instanceof HTMLElement) {
      toggle.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        refreshMenu();
        menu.toggleAttribute("hidden");
      });
      menu.querySelectorAll("[data-tag-option]").forEach((option) => {
        option.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          addValue(option.getAttribute("data-tag-option") || "");
          menu.setAttribute("hidden", "");
        });
      });
    }
    editor.addEventListener("click", (event) => {
      if (!(event.target instanceof HTMLElement) || !event.target.closest("[data-tag-menu]")) {
        input.focus();
      }
    });
    refreshMenu();
  });
}

function tagEditorValues(editor) {
  if (!(editor instanceof HTMLElement)) {
    return [];
  }
  return Array.from(editor.querySelectorAll(".tag-token")).map((token) => token.getAttribute("data-value") || "").filter(Boolean);
}

function setTagEditorSingleValue(editor, value) {
  if (!(editor instanceof HTMLElement)) {
    return;
  }
  const list = editor.querySelector("[data-tag-list]");
  const name = editor.dataset.tagName || "";
  if (!(list instanceof HTMLElement) || !name) {
    return;
  }
  list.replaceChildren();
  const trimmedValue = String(value || "").trim();
  if (!trimmedValue) {
    return;
  }
  const token = document.createElement("span");
  token.className = "tag-token";
  token.setAttribute("data-value", trimmedValue);

  const label = document.createElement("span");
  label.textContent = trimmedValue;

  const remove = document.createElement("button");
  remove.type = "button";
  remove.setAttribute("data-tag-remove", "");
  remove.setAttribute("aria-label", `Remove ${trimmedValue}`);
  remove.textContent = "×";
  remove.addEventListener("click", () => {
    token.remove();
    editor.dispatchEvent(new CustomEvent("tag-editor:change", { bubbles: true }));
  });

  const hidden = document.createElement("input");
  hidden.type = "hidden";
  hidden.name = name;
  hidden.value = trimmedValue;
  token.append(label, remove, hidden);
  list.append(token);
}

function addTagEditorValue(editor, value) {
  if (!(editor instanceof HTMLElement)) {
    return;
  }
  const list = editor.querySelector("[data-tag-list]");
  const name = editor.dataset.tagName || "";
  if (!(list instanceof HTMLElement) || !name) {
    return;
  }
  const trimmedValue = String(value || "").trim();
  if (!trimmedValue || tagEditorValues(editor).some((item) => item.toLowerCase() === trimmedValue.toLowerCase())) {
    return;
  }
  const token = document.createElement("span");
  token.className = "tag-token";
  token.setAttribute("data-value", trimmedValue);

  const label = document.createElement("span");
  label.textContent = trimmedValue;

  const remove = document.createElement("button");
  remove.type = "button";
  remove.setAttribute("data-tag-remove", "");
  remove.setAttribute("aria-label", `Remove ${trimmedValue}`);
  remove.textContent = "×";
  remove.addEventListener("click", () => {
    token.remove();
    editor.dispatchEvent(new CustomEvent("tag-editor:change", { bubbles: true }));
  });

  const hidden = document.createElement("input");
  hidden.type = "hidden";
  hidden.name = name;
  hidden.value = trimmedValue;
  token.append(label, remove, hidden);
  list.append(token);
}

function initializeServiceBindEditors(root = document) {
  root.querySelectorAll("[data-service-bind]").forEach((container) => {
    if (!(container instanceof HTMLElement)) {
      return;
    }
    if (container.dataset.serviceBindInitialized === "1") return;
    container.dataset.serviceBindInitialized = "1";
    const interfaceEditor = container.querySelector(".tag-editor[data-service-bind-interface]");
    const addressEditor = container.querySelector(".tag-editor[data-service-bind-address]");
    if (!(interfaceEditor instanceof HTMLElement) || !(addressEditor instanceof HTMLElement)) {
      return;
    }
    let syncing = false;
    const interfaceOptions = () =>
      Array.from(interfaceEditor.querySelectorAll("[data-tag-option]")).map((option) => ({
        name: option.getAttribute("data-tag-option") || "",
        address: option.getAttribute("data-service-bind-address") || "",
      }));
    const addressOptions = () =>
      Array.from(addressEditor.querySelectorAll("[data-tag-option]")).map((option) => ({
        address: option.getAttribute("data-tag-option") || "",
        name: option.getAttribute("data-service-bind-interface") || "",
      }));
    const syncFromInterface = () => {
      if (syncing) {
        return;
      }
      syncing = true;
      tagEditorValues(interfaceEditor).forEach((selectedInterface) => {
        const match = interfaceOptions().find((option) => option.name === selectedInterface);
        if (match?.address) {
          addTagEditorValue(addressEditor, match.address);
        }
      });
      syncing = false;
    };
    const syncFromAddress = () => {
      if (syncing) {
        return;
      }
      syncing = true;
      tagEditorValues(addressEditor).forEach((selectedAddress) => {
        const match = addressOptions().find((option) => option.address === selectedAddress);
        if (match?.name) {
          addTagEditorValue(interfaceEditor, match.name);
        }
      });
      syncing = false;
    };
    interfaceEditor.addEventListener("tag-editor:change", syncFromInterface);
    addressEditor.addEventListener("tag-editor:change", syncFromAddress);
  });
}

function initializeTabs() {
  document.querySelectorAll("[data-tab-target]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    if (button.dataset.tabInitialized === "true") {
      return;
    }
    button.dataset.tabInitialized = "true";
    button.addEventListener("click", () => {
      const targetId = button.dataset.tabTarget;
      if (!targetId) {
        return;
      }
      const tabList = button.closest("[role='tablist']");
      const panel = document.getElementById(targetId);
      if (!tabList || !panel) {
        return;
      }
      if (tabList.classList.contains("zone-tabs") && button.hasAttribute("data-domain")) {
        rememberDnsActiveZone(button.dataset.domain || "");
      }
      rememberActiveTab(tabList.dataset.tabStorageKey || "", targetId);
      if (tabList.dataset.tabStorageKey === "atlaso:esx-storage:active-tab") {
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${targetId}`);
      }
      tabList.querySelectorAll(".tab-button").forEach((item) => {
        item.classList.toggle("active", item === button);
        item.setAttribute("aria-selected", item === button ? "true" : "false");
      });
      const container = panel.parentElement;
      Array.from(container?.children || []).forEach((item) => {
        if (!(item instanceof HTMLElement) || !item.classList.contains("tab-panel")) {
          return;
        }
        item.classList.toggle("active", item === panel);
        if (item === panel) {
          item.removeAttribute("hidden");
        } else {
          item.setAttribute("hidden", "");
        }
      });
      redrawDnsRecordTables(panel);
      redrawLdapDirectoryTables(panel);
      window.requestAnimationFrame(() => {
        panel.querySelectorAll(".tabulator-grid").forEach((element) => {
          if (element.atlasoTabulatorReady) {
            element.atlasoTabulator?.redraw(true);
          }
        });
      });
    });
  });
  const storedDomain = storedDnsActiveZone();
  const storedDomainButton = dnsZoneTabButtonForDomain(storedDomain);
  if (storedDomainButton) {
    storedDomainButton.click();
  }
  const hashTargetId = window.location.hash ? window.location.hash.slice(1) : "";
  const hashTargetPanel = hashTargetId ? document.getElementById(hashTargetId)?.closest(".tab-panel") : null;
  document.querySelectorAll("[data-tab-storage-key]").forEach((tabList) => {
    if (!(tabList instanceof HTMLElement)) {
      return;
    }
    const storageKey = tabList.dataset.tabStorageKey || "";
    let targetId = hashTargetPanel instanceof HTMLElement ? hashTargetPanel.id : hashTargetId;
    let storedTargetId = "";
    try {
      storedTargetId = window.localStorage.getItem(storageKey) || "";
      targetId = targetId || storedTargetId;
    } catch {
      targetId = targetId || "";
    }
    if (!targetId) {
      return;
    }
    let button = tabList.querySelector(`[data-tab-target="${CSS.escape(targetId)}"]`);
    if (!(button instanceof HTMLButtonElement) && storedTargetId) {
      targetId = storedTargetId;
      button = tabList.querySelector(`[data-tab-target="${CSS.escape(targetId)}"]`);
    }
    if (button instanceof HTMLButtonElement) {
      button.click();
    }
  });
}

function initializeLogsPage() {
  const root = document.querySelector("[data-logs-page]");
  if (!(root instanceof HTMLElement)) {
    return;
  }
  const lineSelect = root.querySelector("[data-log-lines]");
  const refreshStatus = root.querySelector("[data-log-refresh-status]");
  const refreshUrl = root.dataset.logRefreshUrl || "/logs/data";
  const allowedLineCounts = new Set(["100", "200", "500"]);
  if (!(lineSelect instanceof HTMLSelectElement)) {
    return;
  }
  try {
    const storedLineCount = window.localStorage.getItem("atlaso:logs:line-count") || "";
    if (allowedLineCounts.has(storedLineCount)) {
      lineSelect.value = storedLineCount;
    }
  } catch {
    // Storage is optional; the server-rendered default remains usable.
  }

  let refreshing = false;
  let refreshQueued = false;
  const refresh = async () => {
    if (refreshing) {
      refreshQueued = true;
      return;
    }
    refreshing = true;
    if (refreshStatus instanceof HTMLElement) {
      refreshStatus.textContent = "Refreshing...";
    }
    try {
      const response = await fetch(`${refreshUrl}?lines=${encodeURIComponent(lineSelect.value)}`, {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Log refresh failed (${response.status})`);
      }
      const payload = await response.json();
      (Array.isArray(payload.sources) ? payload.sources : []).forEach((source) => {
        const panel = document.getElementById(`logs-${source.id}-panel`);
        if (!(panel instanceof HTMLElement)) {
          return;
        }
        const tabButton = root.querySelector(`[data-log-source-tab="${CSS.escape(String(source.id || ""))}"]`);
        if (tabButton instanceof HTMLButtonElement) {
          tabButton.disabled = !source.available;
          tabButton.setAttribute("aria-disabled", source.available ? "false" : "true");
          tabButton.title = `${String(source.path || source.label || "Log source")}${source.available ? "" : " (unavailable)"}`;
        }
        const meta = panel.querySelector("[data-log-meta]");
        if (meta instanceof HTMLElement) {
          const parts = [`${Number(source.size_bytes || 0)} bytes`];
          if (source.updated_at) {
            parts.push(String(source.updated_at));
          }
          if (source.truncated) {
            parts.push("tail view");
          }
          meta.textContent = parts.join(" · ");
        }
        const output = panel.querySelector("[data-log-lines-output]");
        if (output instanceof HTMLElement) {
          output.textContent = source.available
            ? (Array.isArray(source.lines) ? source.lines.join("\n") : "")
            : String(source.error || "Log file has not been written yet.");
          highlightConfigPreviewElement(output);
        }
      });
      const activeButton = root.querySelector("[role='tablist'] .tab-button.active");
      if (activeButton instanceof HTMLButtonElement && activeButton.disabled) {
        const nextButton = root.querySelector("[role='tablist'] .tab-button:not(:disabled)");
        if (nextButton instanceof HTMLButtonElement) {
          nextButton.click();
        }
      }
      if (refreshStatus instanceof HTMLElement) {
        refreshStatus.textContent = `Updated ${new Date().toLocaleTimeString()} · 5s`;
      }
    } catch {
      if (refreshStatus instanceof HTMLElement) {
        refreshStatus.textContent = "Auto-refresh unavailable";
      }
    } finally {
      refreshing = false;
      if (refreshQueued) {
        refreshQueued = false;
        refresh();
      }
    }
  };

  lineSelect.addEventListener("change", () => {
    if (!allowedLineCounts.has(lineSelect.value)) {
      lineSelect.value = "100";
    }
    try {
      window.localStorage.setItem("atlaso:logs:line-count", lineSelect.value);
    } catch {
      // Storage is optional.
    }
    refresh();
  });
  refresh();
  window.setInterval(refresh, 5000);
}

function initializeAuditEventsTable() {
  const tableElement = document.getElementById("audit-events-table");
  if (!(tableElement instanceof HTMLElement) || typeof Tabulator === "undefined") {
    return;
  }
  const fallback = document.getElementById(tableElement.dataset.fallbackId || "");
  try {
    const rows = JSON.parse(tableElement.dataset.auditEvents || "[]");
    const rowHeight = 30;
    const rowPitch = rowHeight + 1;
    const gridChromeHeight = 88;
    const pageSizeForHeight = () => Math.max(5, Math.floor(Math.max(0, tableElement.clientHeight - gridChromeHeight) / rowPitch));
    const atlasoGridOptions29 = {
      data: rows,
      index: "id",
      layout: "fitColumns",
      height: "100%",
      renderVertical: "virtual",
      rowHeight,
      placeholder: "No audit events yet.",
      pagination: true,
      paginationMode: "local",
      paginationSize: pageSizeForHeight(),
      columns: [
        { title: "Time", field: "created_at", width: 170, headerFilter: "input" },
        { title: "Actor", field: "actor", width: 130, headerFilter: "input" },
        { title: "Action", field: "action", minWidth: 190, headerFilter: "input" },
        { title: "Resource", field: "resource", minWidth: 180, headerFilter: "input" },
        { title: "Success", field: "success", width: 100, hozAlign: "center", formatter: atlasoBooleanFormatter, headerFilter: "list", headerFilterParams: { values: { "": "All", true: "Yes", false: "No" } } },
        { title: "Detail", field: "detail", minWidth: 280, widthGrow: 2, formatter: "plaintext", tooltip: true, headerFilter: "input" },
      ],
    };
    const table = window.AtlasoUiPatterns.createGrid({
      element: tableElement,
      pattern: "read-only",
      options: atlasoGridOptions29,
    }).table;
    if (!table) return;
    const resizeObserver = new ResizeObserver(() => {
      const nextPageSize = pageSizeForHeight();
      if (table.getPageSize() !== nextPageSize) {
        table.setPageSize(nextPageSize);
      }
    });
    resizeObserver.observe(tableElement);
  } catch (_error) {
    tableElement.classList.add("hidden");
    fallback?.classList.remove("hidden");
  }
}

function applianceApplyModalElements() {
  const modal = document.getElementById("appliance-apply-modal");
  return {
    modal,
    title: modal?.querySelector("[data-appliance-apply-modal-title]"),
    kicker: modal?.querySelector("[data-appliance-apply-modal-kicker]"),
    subtitle: modal?.querySelector("[data-appliance-apply-modal-subtitle]"),
    status: modal?.querySelector("[data-appliance-apply-modal-status]"),
    error: modal?.querySelector("[data-appliance-apply-modal-error]"),
    connectionWarning: modal?.querySelector("[data-appliance-apply-connection-warning]"),
    review: modal?.querySelector("[data-appliance-apply-review]"),
    live: modal?.querySelector("[data-appliance-apply-live]"),
    reviewList: modal?.querySelector("[data-appliance-apply-review-list]"),
    reviewForm: modal?.querySelector("[data-appliance-apply-review-form]"),
    selectionSummary: modal?.querySelector("[data-appliance-apply-selection-summary]"),
    submit: modal?.querySelector("[data-appliance-apply-submit]"),
    liveSummary: modal?.querySelector("[data-appliance-apply-live-summary]"),
    cancel: modal?.querySelector("[data-appliance-apply-cancel]"),
    resultClose: modal?.querySelector("[data-appliance-apply-result-close]"),
  };
}

function showApplianceApplyModal(modal) {
  if (modal instanceof HTMLDialogElement && !modal.open) {
    modal.showModal();
  }
}

function clearApplianceApplyAutoClose() {
  window.clearTimeout(applianceApplyAutoCloseTimer);
  applianceApplyAutoCloseTimer = 0;
}

function scheduleApplianceApplyAutoClose(task) {
  clearApplianceApplyAutoClose();
  const { modal } = applianceApplyModalElements();
  if (!(modal instanceof HTMLDialogElement) || task?.status !== "succeeded") return;
  const taskId = String(task.id || "");
  applianceApplyAutoCloseTimer = window.setTimeout(() => {
    if (
      modal.open
      && modal.dataset.active !== "true"
      && modal.dataset.taskId === taskId
      && modal.dataset.taskStatus === "succeeded"
    ) {
      modal.close();
    }
  }, APPLIANCE_APPLY_SUCCESS_AUTO_CLOSE_MS);
}

function setApplianceApplyModalError(message = "") {
  const error = applianceApplyModalElements().error;
  if (error instanceof HTMLElement) {
    error.textContent = message;
    error.classList.toggle("hidden", !message);
  }
}

function applianceApplyReviewRow(unit) {
  const row = document.createElement("article");
  row.className = "appliance-apply-review-row";
  row.dataset.applyUnitId = unit.id || "";
  row.dataset.applyConnectionWarnings = JSON.stringify(Array.isArray(unit.connection_warnings) ? unit.connection_warnings : []);

  const head = document.createElement("div");
  head.className = "appliance-apply-review-row-head";
  const label = document.createElement("label");
  label.className = "apply-unit-select";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.name = "selected_units";
  checkbox.value = unit.id || "";
  checkbox.checked = Boolean(unit.selected && unit.valid);
  checkbox.disabled = !unit.valid;
  checkbox.dataset.applianceApplyReviewCheckbox = "";
  const labelText = document.createElement("span");
  const strong = document.createElement("strong");
  strong.textContent = unit.label || unit.id || "Component";
  const small = document.createElement("small");
  small.textContent = unit.config_path || "";
  labelText.append(strong, small);
  label.append(checkbox, labelText);

  const actions = document.createElement("div");
  actions.className = "apply-unit-actions";
  const validity = document.createElement("span");
  validity.className = `status-pill ${unit.valid ? "good" : "warn"}`;
  validity.textContent = unit.valid ? "valid" : "needs attention";
  const edit = document.createElement("a");
  edit.className = "text-link";
  edit.href = unit.page_url || "/dashboard";
  edit.textContent = "Edit";
  actions.append(validity, edit);
  head.append(label, actions);

  const summary = document.createElement("div");
  summary.className = "apply-unit-summary";
  (unit.summary || []).forEach((item) => {
    const pill = document.createElement("span");
    pill.textContent = String(item);
    summary.append(pill);
  });
  row.append(head, summary);

  if (Array.isArray(unit.format_volumes) && unit.format_volumes.length) {
    const formatPanel = document.createElement("div");
    formatPanel.className = "alert warning esx-storage-format-confirmations";
    const title = document.createElement("strong");
    title.textContent = "Destructive disk initialization authorization";
    formatPanel.append(title);
    unit.format_volumes.forEach((volume) => {
      const fingerprint = volume.fingerprint || {};
      const label = document.createElement("label");
      label.className = "form-field";
      const caption = document.createElement("span");
      caption.className = "field-label";
      caption.textContent = `${volume.name}: ${volume.stable_device_id} · ${fingerprint.model || "model unknown"} · serial ${fingerprint.serial || "unknown"} · WWN ${fingerprint.wwn || "unknown"} · ${Number(fingerprint.size_bytes || 0).toLocaleString()} bytes`;
      const input = document.createElement("input");
      input.type = "text";
      input.placeholder = volume.confirmation || `FORMAT ${volume.name}`;
      input.autocomplete = "off";
      input.dataset.esxFormatConfirmation = "";
      input.dataset.expected = volume.confirmation || `FORMAT ${volume.name}`;
      const hidden = document.createElement("input");
      hidden.type = "hidden";
      hidden.name = "format_confirmations";
      hidden.disabled = true;
      hidden.value = JSON.stringify({ volume_id: volume.id, confirmation: input.dataset.expected });
      input.addEventListener("input", () => {
        hidden.disabled = input.value !== input.dataset.expected;
        updateApplianceApplySelection();
      });
      label.append(caption, input, hidden);
      formatPanel.append(label);
    });
    row.append(formatPanel);
  }

  const messages = [...(unit.validation_errors || []), ...(unit.validation_warnings || [])];
  if (messages.length) {
    const alert = document.createElement("div");
    alert.className = `alert ${unit.validation_errors?.length ? "error" : "warning"}`;
    messages.forEach((message) => {
      const line = document.createElement("div");
      line.textContent = String(message);
      alert.append(line);
    });
    row.append(alert);
  }

  const details = document.createElement("details");
  details.className = "config-diff";
  const detailsSummary = document.createElement("summary");
  detailsSummary.textContent = unit.config_diff ? "Config diff" : "Current config preview";
  const pre = document.createElement("pre");
  const code = document.createElement("code");
  code.className = unit.config_diff ? "language-diff" : "";
  code.textContent = unit.config_diff || unit.config_preview || "No rendered configuration changes.";
  pre.append(code);
  details.append(detailsSummary, pre);
  row.append(details);
  highlightConfigPreviewElement(code);
  return row;
}

function updateApplianceApplySelection() {
  const { modal, selectionSummary, submit, connectionWarning } = applianceApplyModalElements();
  if (!(modal instanceof HTMLDialogElement)) return;
  const selectedCheckboxes = Array.from(modal.querySelectorAll("[data-appliance-apply-review-checkbox]:checked"));
  const selected = selectedCheckboxes.length;
  const incompleteFormatConfirmations = selectedCheckboxes.some((checkbox) => {
    const row = checkbox.closest("[data-apply-unit-id]");
    if (!(row instanceof HTMLElement)) return false;
    return Array.from(row.querySelectorAll("[data-esx-format-confirmation]")).some((input) => input instanceof HTMLInputElement && input.value !== input.dataset.expected);
  });
  if (selectionSummary instanceof HTMLElement) {
    selectionSummary.textContent = incompleteFormatConfirmations
      ? `${selected} component${selected === 1 ? "" : "s"} selected · complete disk format confirmation`
      : `${selected} component${selected === 1 ? "" : "s"} selected`;
  }
  if (submit instanceof HTMLButtonElement) {
    submit.disabled = selected === 0 || incompleteFormatConfirmations;
  }
  if (connectionWarning instanceof HTMLElement) {
    const messages = new Set();
    selectedCheckboxes.forEach((checkbox) => {
      const row = checkbox.closest("[data-apply-unit-id]");
      if (!(row instanceof HTMLElement)) return;
      try {
        const warnings = JSON.parse(row.dataset.applyConnectionWarnings || "[]");
        if (Array.isArray(warnings)) warnings.forEach((warning) => messages.add(String(warning)));
      } catch (_error) {
        // Ignore malformed optional warning metadata and keep the apply review usable.
      }
    });
    connectionWarning.replaceChildren();
    if (messages.size) {
      const title = document.createElement("strong");
      title.textContent = "Management connection warning";
      connectionWarning.append(title);
      messages.forEach((message) => {
        const line = document.createElement("div");
        line.textContent = message;
        connectionWarning.append(line);
      });
    }
    connectionWarning.classList.toggle("hidden", messages.size === 0);
  }
}

async function openApplianceApplyReview() {
  const elements = applianceApplyModalElements();
  if (!(elements.modal instanceof HTMLDialogElement)) return;
  clearApplianceApplyAutoClose();
  elements.modal.dataset.active = "false";
  delete elements.modal.dataset.taskId;
  delete elements.modal.dataset.taskStatus;
  elements.review?.classList.remove("hidden");
  elements.live?.classList.add("hidden");
  if (elements.title instanceof HTMLElement) elements.title.textContent = "Review appliance changes";
  if (elements.kicker instanceof HTMLElement) elements.kicker.textContent = "Desired state";
  if (elements.subtitle instanceof HTMLElement) elements.subtitle.textContent = "Select valid components, inspect their rendered differences, then submit one appliance task.";
  if (elements.status instanceof HTMLElement) {
    elements.status.className = "status-pill muted";
    elements.status.textContent = "loading";
  }
  if (elements.submit instanceof HTMLButtonElement) {
    elements.submit.classList.add("hidden");
    elements.submit.disabled = true;
  }
  if (elements.selectionSummary instanceof HTMLElement) {
    elements.selectionSummary.textContent = "Loading appliance changes…";
  }
  setApplianceApplyModalError("");
  if (elements.connectionWarning instanceof HTMLElement) {
    elements.connectionWarning.replaceChildren();
    elements.connectionWarning.classList.add("hidden");
  }
  showApplianceApplyModal(elements.modal);
  try {
    const response = await fetch("/appliance-apply/review", { credentials: "same-origin", headers: { Accept: "application/json" } });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "Unable to load appliance changes.");
    if (payload.active_task) {
      applianceApplyActiveJobId = payload.active_task.id || "";
      renderApplianceApplyTask(payload.active_task);
      return;
    }
    const units = Array.isArray(payload.units) ? payload.units : [];
    if (elements.reviewList instanceof HTMLElement) {
      elements.reviewList.replaceChildren(...units.map(applianceApplyReviewRow));
      if (!units.length) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.innerHTML = "<h2>No pending appliance changes</h2><p class=\"muted\">All apply units match the last successful baseline.</p>";
        elements.reviewList.replaceChildren(empty);
      }
    }
    if (elements.status instanceof HTMLElement) {
      elements.status.className = `status-pill ${units.length ? "warn" : "good"}`;
      elements.status.textContent = `${units.length} changed`;
    }
    if (elements.submit instanceof HTMLButtonElement) {
      elements.submit.classList.toggle("hidden", units.length === 0);
    }
    updateApplianceApplySelection();
  } catch (error) {
    setApplianceApplyModalError(error instanceof Error ? error.message : "Unable to load appliance changes.");
  }
}

function applianceApplyDuration(task) {
  const start = Date.parse(task.started_at || task.created_at || "");
  const finish = Date.parse(task.finished_at || "") || Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(finish)) return "—";
  const seconds = Math.max(0, Math.round((finish - start) / 1000));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function renderApplianceApplyStepDetail(task) {
  const detail = document.querySelector("[data-appliance-apply-step-detail]");
  if (!(detail instanceof HTMLElement) || !task) return;
  detail.classList.remove("hidden");
  const title = detail.querySelector("[data-appliance-apply-step-detail-title]");
  const meta = detail.querySelector("[data-appliance-apply-step-detail-meta]");
  const status = detail.querySelector("[data-appliance-apply-step-detail-status]");
  const error = detail.querySelector("[data-appliance-apply-step-detail-error]");
  const result = detail.querySelector("[data-appliance-apply-step-detail-result]");
  if (title instanceof HTMLElement) title.textContent = task.is_step ? task.label : task.type_label;
  if (meta instanceof HTMLElement) meta.textContent = `${task.id} · ${applianceApplyDuration(task)}`;
  if (status instanceof HTMLElement) {
    status.className = `status-pill ${task.status_pill || "muted"}`;
    status.textContent = task.status || "unknown";
  }
  if (error instanceof HTMLElement) {
    error.textContent = task.error || "";
    error.classList.toggle("hidden", !task.error);
  }
  if (result instanceof HTMLElement) {
    result.textContent = task.result_json || "{}";
    highlightConfigPreviewElement(result);
  }
}

function renderApplianceApplyTask(task) {
  const elements = applianceApplyModalElements();
  if (!(elements.modal instanceof HTMLDialogElement) || !task) return;
  const active = taskStatusActive(task.status);
  elements.modal.dataset.active = active ? "true" : "false";
  elements.modal.dataset.taskId = String(task.id || "");
  elements.modal.dataset.taskStatus = String(task.status || "");
  elements.review?.classList.add("hidden");
  elements.live?.classList.remove("hidden");
  if (elements.kicker instanceof HTMLElement) elements.kicker.textContent = "Master appliance task";
  if (elements.title instanceof HTMLElement) elements.title.textContent = task.type_label || "Appliance Apply";
  if (elements.subtitle instanceof HTMLElement) elements.subtitle.textContent = task.id || "";
  if (elements.status instanceof HTMLElement) {
    elements.status.className = `status-pill ${task.status_pill || "muted"}`;
    elements.status.textContent = task.state || task.status || "unknown";
  }
  if (elements.liveSummary instanceof HTMLElement) {
    const children = Array.isArray(task._children) ? task._children : [];
    const complete = children.filter((child) => !taskStatusActive(child.status) && child.status !== "pending").length;
    elements.liveSummary.textContent = active
      ? `${complete} of ${children.length} components finished · changes are globally locked`
      : `${children.length} components · appliance changes are unlocked`;
  }
  if (elements.cancel instanceof HTMLButtonElement) {
    elements.cancel.classList.toggle("hidden", !task.can_cancel);
    elements.cancel.disabled = !task.can_cancel;
    elements.cancel.dataset.taskId = task.id || "";
  }
  if (elements.resultClose instanceof HTMLButtonElement) {
    elements.resultClose.classList.toggle("hidden", active);
  }
  const grid = document.getElementById("appliance-apply-live-grid");
  if (grid instanceof HTMLElement && typeof window.Tabulator === "function") {
    const columns = [
      { title: "Status", field: "status", width: 150, formatter: (cell) => taskStatusPillHtml(cell.getRow().getData()) },
      { title: "Task / component", field: "label", minWidth: 260, formatter: (cell) => escapeHtml(cell.getRow().getData().is_step ? cell.getValue() || "" : cell.getRow().getData().type_label || "Appliance Apply") },
      { title: "State", field: "state", minWidth: 170, formatter: (cell) => escapeHtml(cell.getValue() || "") },
      { title: "Progress", field: "progress_percent", width: 105, formatter: (cell) => `${Number(cell.getValue() || 0)}%` },
      { title: "Duration", field: "duration", width: 105, formatter: (cell) => applianceApplyDuration(cell.getRow().getData()) },
    ];
    if (!applianceApplyModalTable) {
      const atlasoGridOptions30 = {
        data: [task],
        index: "id",
        layout: "fitColumns",
        dataTree: true,
        dataTreeStartExpanded: true,
        selectableRows: 1,
        columns,
      };
      applianceApplyModalTable = window.AtlasoUiPatterns.createGrid({
        element: grid,
        pattern: "read-only",
        onOpenRow: (rowData) => renderApplianceApplyStepDetail(rowData),
        options: atlasoGridOptions30,
      }).table;
      applianceApplyModalTable?.on("rowClick", (_event, row) => renderApplianceApplyStepDetail(row.getData()));
    } else {
      applianceApplyModalTable.replaceData([task]);
    }
  }
  showApplianceApplyModal(elements.modal);
  scheduleApplianceApplyAutoClose(task);
}

function refreshCurrentWorkflowAfterApplianceApply(task) {
  if (task?.status !== "succeeded" || window.location.pathname !== "/esx-storage") return;
  window.setTimeout(() => window.location.reload(), 300);
}

async function submitApplianceApplyForm(form) {
  const elements = applianceApplyModalElements();
  if (!(form instanceof HTMLFormElement) || !(elements.modal instanceof HTMLDialogElement)) return;
  setApplianceApplyModalError("");
  if (elements.submit instanceof HTMLButtonElement) {
    elements.submit.disabled = true;
    elements.submit.textContent = "Creating task…";
  }
  try {
    const response = await fetch("/appliance-apply", {
      method: "POST",
      body: new FormData(form),
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "Appliance changes could not be submitted.");
    applianceApplyActiveJobId = payload.job_id || payload.task?.id || "";
    renderApplianceApplyTask(payload.task);
    refreshApplianceApplySidebar().catch(() => {});
  } catch (error) {
    setApplianceApplyModalError(error instanceof Error ? error.message : "Appliance changes could not be submitted.");
  } finally {
    if (elements.submit instanceof HTMLButtonElement) {
      elements.submit.disabled = false;
      elements.submit.textContent = "Submit appliance changes";
    }
  }
}

async function pollGlobalApplianceApply() {
  window.clearTimeout(applianceApplyGlobalPollTimer);
  if (document.visibilityState === "hidden") {
    applianceApplyGlobalPollTimer = window.setTimeout(pollGlobalApplianceApply, 5000);
    return;
  }
  let delay = 2000;
  try {
    const response = await fetch("/appliance-apply/status", { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("Unable to read appliance apply status.");
    const payload = await response.json();
    updateApplianceApplySidebar(payload);
    if (payload.active_task) {
      applianceApplyActiveJobId = payload.active_task.id || "";
      renderApplianceApplyTask(payload.active_task);
      delay = 2000;
    } else if (applianceApplyActiveJobId) {
      const jobId = applianceApplyActiveJobId;
      const taskResponse = await fetch(`/tasks/${encodeURIComponent(jobId)}/status`, { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (taskResponse.ok) {
        const taskPayload = await taskResponse.json();
        renderApplianceApplyTask(taskPayload.task);
        refreshCurrentWorkflowAfterApplianceApply(taskPayload.task);
      }
      applianceApplyActiveJobId = "";
    }
  } catch (_error) {
    delay = 2000;
  }
  applianceApplyGlobalPollTimer = window.setTimeout(pollGlobalApplianceApply, delay);
}

function initializeApplianceApplyProgress() {
  const elements = applianceApplyModalElements();
  if (!(elements.modal instanceof HTMLDialogElement)) return;
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-appliance-apply-open]");
    if (!trigger) return;
    event.preventDefault();
    openApplianceApplyReview().catch(() => {});
  });
  elements.modal.addEventListener("cancel", (event) => {
    if (elements.modal.dataset.active === "true") event.preventDefault();
  });
  elements.modal.addEventListener("close", clearApplianceApplyAutoClose);
  elements.modal.querySelector("[data-appliance-apply-modal-close]")?.addEventListener("click", () => {
    if (elements.modal.dataset.active !== "true") elements.modal.close();
  });
  elements.resultClose?.addEventListener("click", () => elements.modal.close());
  elements.reviewList?.addEventListener("change", updateApplianceApplySelection);
  elements.reviewForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    submitApplianceApplyForm(elements.reviewForm).catch(() => {});
  });
  elements.cancel?.addEventListener("click", async () => {
    const taskId = elements.cancel?.dataset.taskId || "";
    if (!taskId) return;
    const confirmed = await requestConfirmation({
      title: "Cancel appliance apply",
      message: "The running component will finish safely. Remaining components will be skipped and the global lock will remain until cancellation completes.",
      label: "Request cancellation",
    });
    if (!confirmed) return;
    const body = new URLSearchParams();
    body.set("csrf", elements.modal.dataset.csrf || "");
    const response = await fetch(`/tasks/${encodeURIComponent(taskId)}/cancel`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
    });
    const payload = await response.json();
    if (!response.ok) {
      setApplianceApplyModalError(payload.detail || "Unable to request cancellation.");
      return;
    }
    renderApplianceApplyTask(payload.task);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "hidden") pollGlobalApplianceApply().catch(() => {});
  });
  pollGlobalApplianceApply().catch(() => {});
  if (window.location.hash === "#appliance-apply-review") {
    openApplianceApplyReview().catch(() => {});
  }
}

function monitorFinite(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function formatMonitorPercent(value) {
  const number = monitorFinite(value);
  return number === null ? "--" : `${number.toFixed(number >= 10 ? 0 : 1)}%`;
}

function formatMonitorBytes(value) {
  const number = monitorFinite(value);
  if (number === null) {
    return "--";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Math.max(0, number);
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatMonitorRate(value) {
  const number = monitorFinite(value);
  return number === null ? "--" : `${formatMonitorBytes(number)}/s`;
}

function formatMonitorNumber(value) {
  const number = monitorFinite(value);
  return number === null ? "--" : number.toLocaleString();
}

function monitorSetText(root, selector, value) {
  const node = root.querySelector(selector);
  if (node instanceof HTMLElement) {
    node.textContent = value;
  }
}

function formatServerTime(value) {
  if (!value) {
    return "Server --:--:-- UTC";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Server --:--:-- UTC";
  }
  const pad = (part) => String(part).padStart(2, "0");
  return `Server ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`;
}

function updateServerTime(value) {
  const node = document.querySelector("[data-server-time]");
  if (!(node instanceof HTMLElement)) {
    return;
  }
  node.dataset.serverTimeIso = value || "";
  node.textContent = formatServerTime(value);
}

function initializeServerTime() {
  const node = document.querySelector("[data-server-time]");
  if (!(node instanceof HTMLElement) || node.dataset.serverTimeInitialized === "true") {
    return;
  }
  node.dataset.serverTimeInitialized = "true";

  let serverBaseMs = Date.parse(node.dataset.serverTimeIso || "");
  let clientBaseMs = Date.now();
  if (!Number.isFinite(serverBaseMs)) {
    serverBaseMs = clientBaseMs;
  }

  const render = () => {
    const estimated = new Date(serverBaseMs + (Date.now() - clientBaseMs));
    node.textContent = formatServerTime(estimated.toISOString());
  };

  const sync = async () => {
    try {
      const response = await fetch("/server-time", {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        return;
      }
      const payload = await response.json();
      const nextBaseMs = Date.parse(payload.server_time || payload.iso || "");
      if (Number.isFinite(nextBaseMs)) {
        serverBaseMs = nextBaseMs;
        clientBaseMs = Date.now();
        node.dataset.serverTimeIso = new Date(serverBaseMs).toISOString();
        render();
      }
    } catch (_error) {
      // Keep the local ticking estimate; the next minute sync will retry.
    }
  };

  render();
  window.setInterval(render, 1000);
  window.setInterval(sync, 60000);
}

function monitorSeriesPoints(rows, fields) {
  return (Array.isArray(rows) ? rows : []).map((row) => {
    const point = { time: new Date(row.sampled_at || 0).getTime() };
    fields.forEach((field) => {
      point[field] = monitorFinite(row[field]);
    });
    return point;
  }).filter((point) => Number.isFinite(point.time));
}

const MONITOR_SERIES_COLORS = ["#2563eb", "#0f766e", "#d97706", "#9333ea", "#dc2626", "#0891b2", "#65a30d", "#c026d3"];
const MONITOR_CHART_INTERACTIONS = new WeakMap();

function monitorNearestChartTarget(interaction, pointerX, pointerY) {
  let nearest = null;
  const consider = (target, distance) => {
    const preferDetail = nearest && distance === nearest.distance && nearest.target.line.aggregate && !target.line.aggregate;
    if (distance <= 196 && (!nearest || distance < nearest.distance || preferDetail)) nearest = { distance, target };
  };
  interaction.hitTargets.forEach((target) => {
    consider(target, ((target.x - pointerX) ** 2) + ((target.y - pointerY) ** 2));
  });
  interaction.hitSegments.forEach((segment) => {
    const dx = segment.end.x - segment.start.x;
    const dy = segment.end.y - segment.start.y;
    const lengthSquared = (dx ** 2) + (dy ** 2);
    const projection = lengthSquared > 0
      ? Math.max(0, Math.min(1, (((pointerX - segment.start.x) * dx) + ((pointerY - segment.start.y) * dy)) / lengthSquared))
      : 0;
    const x = segment.start.x + (dx * projection);
    const y = segment.start.y + (dy * projection);
    consider(
      {
        line: segment.line,
        time: segment.start.time + ((segment.end.time - segment.start.time) * projection),
        value: segment.start.value + ((segment.end.value - segment.start.value) * projection),
        x,
        y,
      },
      ((x - pointerX) ** 2) + ((y - pointerY) ** 2),
    );
  });
  return nearest?.target || null;
}

function monitorHistoryChartData(groups, dimensions) {
  const rowsByTime = new Map();
  const lines = [];
  (Array.isArray(groups) ? groups : []).forEach((group, groupIndex) => {
    const aggregate = Boolean(group.aggregate);
    const color = group.color || MONITOR_SERIES_COLORS[groupIndex % MONITOR_SERIES_COLORS.length];
    dimensions.forEach((dimension) => {
      const field = `series_${groupIndex}_${dimension.field}`;
      lines.push({
        field,
        label: [group.name, dimension.label].filter(Boolean).join(" "),
        color: dimension.color || color,
        dash: dimension.dash || [],
        lineWidth: Number(dimension.lineWidth || group.lineWidth || (aggregate ? 3 : 1)),
        alpha: Number(dimension.alpha || group.alpha || (aggregate ? 0.45 : 1)),
        aggregate,
      });
      (Array.isArray(group.points) ? group.points : []).forEach((point) => {
        const sampledAt = point.sampled_at || "";
        if (!sampledAt) return;
        const row = rowsByTime.get(sampledAt) || { sampled_at: sampledAt };
        row[field] = point[dimension.field];
        rowsByTime.set(sampledAt, row);
      });
    });
  });
  const rows = Array.from(rowsByTime.values()).sort((left, right) => new Date(left.sampled_at).getTime() - new Date(right.sampled_at).getTime());
  return { rows, lines };
}

function drawMonitorChart(canvas, rows, lines, options = {}) {
  if (!(canvas instanceof HTMLCanvasElement)) {
    return;
  }
  let interaction = MONITOR_CHART_INTERACTIONS.get(canvas);
  if (!interaction) {
    interaction = { dragging: false, geometry: null, highlightedField: "", highlightedTime: null, highlightedValue: null, hitSegments: [], hitTargets: [], legendTargets: [], lines: [], options: {}, pinned: false, rows: [], selectionEndX: null, selectionStartX: null, suppressClick: false };
    MONITOR_CHART_INTERACTIONS.set(canvas, interaction);
    canvas.addEventListener("pointerdown", (event) => {
      const geometry = interaction.geometry;
      if (typeof interaction.options.onAreaZoom !== "function" || !geometry) return;
      const bounds = canvas.getBoundingClientRect();
      const pointerX = event.clientX - bounds.left;
      const pointerY = event.clientY - bounds.top;
      if (pointerX < geometry.left || pointerX > geometry.right || pointerY < geometry.top || pointerY > geometry.bottom) return;
      interaction.dragging = true;
      interaction.selectionStartX = Math.max(geometry.left, Math.min(geometry.right, pointerX));
      interaction.selectionEndX = interaction.selectionStartX;
      interaction.highlightedField = "";
      interaction.highlightedTime = null;
      interaction.highlightedValue = null;
      canvas.removeAttribute("title");
      canvas.setPointerCapture?.(event.pointerId);
      event.preventDefault();
    });
    canvas.addEventListener("pointermove", (event) => {
      const bounds = canvas.getBoundingClientRect();
      const pointerX = event.clientX - bounds.left;
      const pointerY = event.clientY - bounds.top;
      if (interaction.dragging && interaction.geometry) {
        interaction.selectionEndX = Math.max(interaction.geometry.left, Math.min(interaction.geometry.right, pointerX));
        drawMonitorChart(canvas, interaction.rows, interaction.lines, interaction.options);
        return;
      }
      if (interaction.pinned) return;
      const nearest = monitorNearestChartTarget(interaction, pointerX, pointerY);
      const nextField = nearest?.line.field || "";
      const nextTime = nearest?.time ?? null;
      const nextValue = nearest?.value ?? null;
      if (nextField === interaction.highlightedField && nextTime === interaction.highlightedTime && nextValue === interaction.highlightedValue) return;
      interaction.highlightedField = nextField;
      interaction.highlightedTime = nextTime;
      interaction.highlightedValue = nextValue;
      if (nearest) {
        const formattedValue = interaction.options.formatY ? interaction.options.formatY(nearest.value) : String(nearest.value);
        const formattedTime = new Date(nearest.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        canvas.title = `${nearest.line.label}: ${formattedValue} at ${formattedTime}`;
      } else {
        canvas.removeAttribute("title");
      }
      drawMonitorChart(canvas, interaction.rows, interaction.lines, interaction.options);
    });
    const clearHighlight = () => {
      if (interaction.dragging || interaction.pinned) return;
      if (!interaction.highlightedField) return;
      interaction.highlightedField = "";
      interaction.highlightedTime = null;
      interaction.highlightedValue = null;
      canvas.removeAttribute("title");
      drawMonitorChart(canvas, interaction.rows, interaction.lines, interaction.options);
    };
    canvas.addEventListener("pointerleave", clearHighlight);
    canvas.addEventListener("pointerout", clearHighlight);
    const finishAreaSelection = (event) => {
      if (!interaction.dragging || !interaction.geometry) return;
      const geometry = interaction.geometry;
      const startX = interaction.selectionStartX;
      const endX = interaction.selectionEndX;
      interaction.dragging = false;
      interaction.selectionStartX = null;
      interaction.selectionEndX = null;
      canvas.releasePointerCapture?.(event.pointerId);
      if (Number.isFinite(startX) && Number.isFinite(endX) && Math.abs(endX - startX) >= 12) {
        interaction.suppressClick = true;
        window.setTimeout(() => { interaction.suppressClick = false; }, 0);
        const timeForX = (x) => geometry.minTime + ((x - geometry.left) / geometry.plotWidth) * (geometry.maxTime - geometry.minTime);
        interaction.options.onAreaZoom({
          startTime: timeForX(Math.min(startX, endX)),
          endTime: timeForX(Math.max(startX, endX)),
          fullMinTime: geometry.fullMinTime,
          fullMaxTime: geometry.fullMaxTime,
        });
        return;
      }
      drawMonitorChart(canvas, interaction.rows, interaction.lines, interaction.options);
    };
    canvas.addEventListener("pointerup", finishAreaSelection);
    canvas.addEventListener("pointercancel", finishAreaSelection);
    canvas.addEventListener("click", (event) => {
      if (interaction.suppressClick) {
        interaction.suppressClick = false;
        return;
      }
      const bounds = canvas.getBoundingClientRect();
      const pointerX = event.clientX - bounds.left;
      const pointerY = event.clientY - bounds.top;
      const legendTarget = interaction.legendTargets.find((item) => pointerX >= item.left && pointerX <= item.right && pointerY >= item.top && pointerY <= item.bottom);
      if (legendTarget) {
        const selecting = !interaction.pinned || interaction.highlightedField !== legendTarget.line.field;
        interaction.pinned = selecting;
        interaction.highlightedField = selecting ? legendTarget.line.field : "";
        interaction.highlightedTime = null;
        interaction.highlightedValue = null;
        if (selecting) canvas.title = `${legendTarget.line.label} (selected)`;
        else canvas.removeAttribute("title");
        drawMonitorChart(canvas, interaction.rows, interaction.lines, interaction.options);
        return;
      }
      const target = monitorNearestChartTarget(interaction, pointerX, pointerY);
      interaction.pinned = Boolean(target);
      interaction.highlightedField = target?.line.field || "";
      interaction.highlightedTime = target?.time ?? null;
      interaction.highlightedValue = target?.value ?? null;
      if (target) {
        const formattedValue = interaction.options.formatY ? interaction.options.formatY(target.value) : String(target.value);
        const formattedTime = new Date(target.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        canvas.title = `${target.line.label}: ${formattedValue} at ${formattedTime} (selected)`;
      } else {
        canvas.removeAttribute("title");
      }
      drawMonitorChart(canvas, interaction.rows, interaction.lines, interaction.options);
    });
  }
  interaction.rows = rows;
  interaction.lines = lines;
  interaction.options = options;
  interaction.hitSegments = [];
  interaction.hitTargets = [];
  interaction.legendTargets = [];
  const bounds = canvas.getBoundingClientRect();
  const width = Math.max(320, Math.floor(bounds.width || canvas.clientWidth || 640));
  const height = Math.max(180, Math.floor(bounds.height || canvas.clientHeight || 240));
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.floor(width * ratio);
  canvas.height = Math.floor(height * ratio);
  const context = canvas.getContext("2d");
  if (!context) {
    return;
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);

  context.font = "11px system-ui, sans-serif";
  const legendPositions = [];
  let legendX = 44;
  let legendY = 12;
  lines.forEach((line) => {
    const itemWidth = context.measureText(line.label).width + 42;
    if (legendX > 44 && legendX + itemWidth > width - 18) {
      legendX = 44;
      legendY += 16;
    }
    legendPositions.push({ itemWidth, line, x: legendX, y: legendY });
    legendX += itemWidth;
  });
  const padding = { top: Math.max(18, legendY + 8), right: 18, bottom: 30, left: 44 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const allPoints = monitorSeriesPoints(rows, lines.map((line) => line.field));
  const fullMinTime = allPoints.length ? Math.min(...allPoints.map((point) => point.time)) : null;
  const fullMaxTime = allPoints.length ? Math.max(...allPoints.map((point) => point.time)) : null;
  let points = allPoints;
  if (allPoints.length && Number(options.zoom || 1) > 1) {
    const fullSpan = Math.max(1, fullMaxTime - fullMinTime);
    const viewSpan = fullSpan / Number(options.zoom);
    const requestedCenter = Number(options.zoomCenterTime);
    const hasRequestedCenter = options.zoomCenterTime !== null && options.zoomCenterTime !== undefined && Number.isFinite(requestedCenter);
    const center = hasRequestedCenter ? Math.max(fullMinTime, Math.min(fullMaxTime, requestedCenter)) : fullMaxTime;
    let viewMinTime = center - (viewSpan / 2);
    let viewMaxTime = center + (viewSpan / 2);
    if (viewMinTime < fullMinTime) {
      viewMaxTime += fullMinTime - viewMinTime;
      viewMinTime = fullMinTime;
    }
    if (viewMaxTime > fullMaxTime) {
      viewMinTime -= viewMaxTime - fullMaxTime;
      viewMaxTime = fullMaxTime;
    }
    points = allPoints.filter((point) => point.time >= viewMinTime && point.time <= viewMaxTime);
  }
  const values = points.flatMap((point) => lines.map((line) => point[line.field])).filter((value) => value !== null);
  if (!points.length || !values.length) {
    interaction.geometry = null;
    context.fillStyle = "#64748b";
    context.font = "13px system-ui, sans-serif";
    context.fillText("Waiting for samples", padding.left, padding.top + 24);
    return;
  }

  const minTime = Math.min(...points.map((point) => point.time));
  const maxTime = Math.max(...points.map((point) => point.time));
  const rawMax = Math.max(...values, options.max || 0);
  const maxValue = options.max ? options.max : Math.max(1, rawMax * 1.12);
  const minValue = options.min || 0;
  const timeSpan = Math.max(1, maxTime - minTime);
  const valueSpan = Math.max(1, maxValue - minValue);
  const xFor = (time) => padding.left + ((time - minTime) / timeSpan) * plotWidth;
  const yFor = (value) => padding.top + plotHeight - ((value - minValue) / valueSpan) * plotHeight;
  interaction.geometry = {
    bottom: padding.top + plotHeight,
    fullMaxTime,
    fullMinTime,
    left: padding.left,
    maxTime,
    minTime,
    plotWidth,
    right: padding.left + plotWidth,
    top: padding.top,
  };

  context.strokeStyle = "#e2e8f0";
  context.lineWidth = 1;
  context.fillStyle = "#64748b";
  context.font = "11px system-ui, sans-serif";
  for (let index = 0; index <= 4; index += 1) {
    const y = padding.top + (plotHeight * index) / 4;
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
    const labelValue = maxValue - ((maxValue - minValue) * index) / 4;
    const label = options.formatY ? options.formatY(labelValue) : labelValue.toFixed(0);
    context.fillText(label, 8, y + 4);
  }

  const drawLines = [...lines].sort((left, right) => Number(right.aggregate) - Number(left.aggregate));
  drawLines.forEach((line) => {
    const highlighted = line.field === interaction.highlightedField;
    context.strokeStyle = line.color;
    context.lineWidth = highlighted ? Math.max(Number(line.lineWidth || 2) + 2, 4) : Number(line.lineWidth || 2);
    context.globalAlpha = highlighted ? 1 : Number(line.alpha || 1);
    context.setLineDash(line.dash || []);
    context.beginPath();
    let hasPoint = false;
    let previousTarget = null;
    points.forEach((point) => {
      const value = point[line.field];
      if (value === null) {
        previousTarget = null;
        return;
      }
      const x = xFor(point.time);
      const y = yFor(value);
      const target = { line, time: point.time, value, x, y };
      interaction.hitTargets.push(target);
      if (previousTarget) interaction.hitSegments.push({ line, start: previousTarget, end: target });
      previousTarget = target;
      if (!hasPoint) {
        context.moveTo(x, y);
        hasPoint = true;
      } else {
        context.lineTo(x, y);
      }
    });
    if (hasPoint) {
      context.stroke();
    }
  });
  context.globalAlpha = 1;
  context.setLineDash([]);

  const highlightedLine = lines.find((line) => line.field === interaction.highlightedField);
  if (highlightedLine && Number.isFinite(interaction.highlightedTime) && Number.isFinite(interaction.highlightedValue) && interaction.highlightedTime >= minTime && interaction.highlightedTime <= maxTime) {
    const highlightedPoint = { line: highlightedLine, x: xFor(interaction.highlightedTime), y: yFor(interaction.highlightedValue) };
    context.fillStyle = "#ffffff";
    context.strokeStyle = highlightedPoint.line.color;
    context.lineWidth = 3;
    context.beginPath();
    context.arc(highlightedPoint.x, highlightedPoint.y, 5, 0, Math.PI * 2);
    context.fill();
    context.stroke();
  }

  if (interaction.dragging && Number.isFinite(interaction.selectionStartX) && Number.isFinite(interaction.selectionEndX)) {
    const selectionLeft = Math.min(interaction.selectionStartX, interaction.selectionEndX);
    const selectionWidth = Math.abs(interaction.selectionEndX - interaction.selectionStartX);
    context.fillStyle = "rgba(37, 99, 235, 0.14)";
    context.strokeStyle = "#2563eb";
    context.lineWidth = 1;
    context.fillRect(selectionLeft, padding.top, selectionWidth, plotHeight);
    context.strokeRect(selectionLeft, padding.top, selectionWidth, plotHeight);
  }

  const start = new Date(minTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const end = new Date(maxTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  context.fillStyle = "#64748b";
  context.fillText(start, padding.left, height - 10);
  context.textAlign = "right";
  context.fillText(end, width - padding.right, height - 10);
  context.textAlign = "left";

  legendPositions.forEach(({ itemWidth, line, x, y }) => {
    interaction.legendTargets.push({ bottom: y + 5, left: x - 3, line, right: x + itemWidth - 8, top: y - 13 });
    const highlighted = line.field === interaction.highlightedField;
    context.strokeStyle = line.color;
    context.lineWidth = highlighted ? Math.max(Number(line.lineWidth || 2) + 2, 4) : Number(line.lineWidth || 2);
    context.setLineDash(line.dash || []);
    context.beginPath();
    context.moveTo(x, y - 2);
    context.lineTo(x + 10, y - 2);
    context.stroke();
    context.fillStyle = "#334155";
    context.font = `${highlighted ? "700 " : ""}11px system-ui, sans-serif`;
    context.fillText(line.label, x + 14, y);
  });
  context.font = "11px system-ui, sans-serif";
  context.setLineDash([]);
}

function renderMonitorNetworkTable(tbody, rows) {
  if (!(tbody instanceof HTMLElement)) {
    return;
  }
  const networks = Array.isArray(rows) ? rows : [];
  if (!networks.length) {
    tbody.replaceChildren(Object.assign(document.createElement("tr"), { innerHTML: '<td colspan="6" class="muted">No interfaces sampled</td>' }));
    return;
  }
  tbody.replaceChildren(...networks.map((network) => {
    const row = document.createElement("tr");
    const errors = Number(network.rx_errors || 0) + Number(network.tx_errors || 0);
    const drops = Number(network.rx_dropped || 0) + Number(network.tx_dropped || 0);
    [network.name || "--", network.oper_state || "unknown", formatMonitorRate(network.rx_bytes_per_sec), formatMonitorRate(network.tx_bytes_per_sec), formatMonitorNumber(errors), formatMonitorNumber(drops)].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });
    return row;
  }));
}

function renderMonitorDiskActivityTable(tbody, rows) {
  if (!(tbody instanceof HTMLElement)) return;
  const devices = Array.isArray(rows) ? rows : [];
  if (!devices.length) {
    tbody.replaceChildren(Object.assign(document.createElement("tr"), { innerHTML: '<td colspan="3" class="muted">No devices sampled</td>' }));
    return;
  }
  tbody.replaceChildren(...devices.map((device) => {
    const row = document.createElement("tr");
    [device.device || device.name || "--", formatMonitorRate(device.read_bytes_per_sec), formatMonitorRate(device.write_bytes_per_sec)].forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });
    return row;
  }));
}

const MONITOR_CHART_TITLES = {
  cpu: "CPU Utilization",
  memory: "Memory Pressure",
  network: "Network Throughput",
  disk: "Disk Activity",
};

function drawMonitorChartType(canvas, type, payload, chartOptions = {}) {
  if (type === "cpu") {
    const chart = monitorHistoryChartData(
      [
        { name: "Total", points: payload.cpu, aggregate: true, color: "#0f172a" },
        ...(Array.isArray(payload.cpu_cores) ? payload.cpu_cores : []),
      ],
      [{ field: "percent", label: "" }],
    );
    drawMonitorChart(canvas, chart.rows, chart.lines, { min: 0, max: 100, formatY: formatMonitorPercent, ...chartOptions });
    return;
  }
  if (type === "memory") {
    drawMonitorChart(canvas, payload.memory, [{ field: "used_percent", label: "Memory", color: "#0f766e" }], { min: 0, max: 100, formatY: formatMonitorPercent, ...chartOptions });
    return;
  }
  if (type === "network") {
    const chart = monitorHistoryChartData([
      { name: "Total", points: payload.network_totals, aggregate: true, color: "#0f172a" },
      ...(Array.isArray(payload.networks) ? payload.networks : []),
    ], [
      { field: "rx_bytes_per_sec", label: "RX" },
      { field: "tx_bytes_per_sec", label: "TX", dash: [5, 3] },
    ]);
    drawMonitorChart(canvas, chart.rows, chart.lines, { min: 0, formatY: formatMonitorBytes, ...chartOptions });
    return;
  }
  if (type === "disk") {
    const chart = monitorHistoryChartData([
      { name: "Total", points: payload.disk_io, aggregate: true, color: "#0f172a" },
      ...(Array.isArray(payload.disk_devices) ? payload.disk_devices : []),
    ], [
      { field: "read_bytes_per_sec", label: "Read" },
      { field: "write_bytes_per_sec", label: "Write", dash: [5, 3] },
    ]);
    drawMonitorChart(canvas, chart.rows, chart.lines, { min: 0, formatY: formatMonitorBytes, ...chartOptions });
    return;
  }
}

function renderMonitorPage(root, payload) {
  const summary = payload.summary || {};
  const cpu = summary.cpu || {};
  const memory = summary.memory || {};
  const network = summary.network || {};
  const virt = payload.virtualization || {};
  monitorSetText(root, "[data-monitor-cpu-current]", formatMonitorPercent(cpu.current_percent));
  monitorSetText(root, "[data-monitor-cpu-detail]", `Load ${cpu.load1 ?? "--"} on ${cpu.cpu_count || "--"} vCPU`);
  monitorSetText(root, "[data-monitor-cpu-peak]", `peak ${formatMonitorPercent(cpu.peak_percent)}`);
  monitorSetText(root, "[data-monitor-memory-current]", formatMonitorPercent(memory.current_percent));
  monitorSetText(root, "[data-monitor-memory-detail]", `${formatMonitorBytes(memory.available_bytes)} available`);
  monitorSetText(root, "[data-monitor-memory-peak]", `peak ${formatMonitorPercent(memory.peak_percent)}`);
  monitorSetText(root, "[data-monitor-network-current]", `${formatMonitorRate(network.rx_bytes_per_sec)} down`);
  monitorSetText(root, "[data-monitor-network-detail]", `${formatMonitorRate(network.tx_bytes_per_sec)} up, ${network.interface_count || 0} interfaces`);
  monitorSetText(root, "[data-monitor-virt-detected]", virt.detected || "unknown");
  monitorSetText(root, "[data-monitor-virt-product]", [virt.sys_vendor, virt.product_name].filter(Boolean).join(" / ") || "--");
  monitorSetText(root, "[data-monitor-virt-tools]", virt.vmtools_version || "--");
  monitorSetText(root, "[data-monitor-virt-hostname]", virt.hostname || "--");
  monitorSetText(root, "[data-monitor-sample-count]", `${payload.sample_count || 0} samples`);
  if (payload.enabled === false) {
    monitorSetText(root, "[data-monitor-sample-count]", "disabled");
  }
  updateServerTime(payload.server_time || payload.generated_at);

  Object.keys(MONITOR_CHART_TITLES).forEach((type) => {
    drawMonitorChartType(root.querySelector(`[data-monitor-chart="${type}"]`), type, payload);
  });
  renderMonitorNetworkTable(root.querySelector("[data-monitor-network-table]"), payload.networks);
  renderMonitorDiskActivityTable(root.querySelector("[data-monitor-disk-activity-table]"), payload.disk_devices);
}

function initializeMonitorPage() {
  const root = document.querySelector("[data-monitor-page]");
  if (!(root instanceof HTMLElement)) {
    return;
  }
  let hours = 6;
  let latestPayload = null;
  let loading = false;
  let expandedType = "";
  let expandedZoomPercent = 100;
  let expandedZoomCenterTime = null;
  const status = root.querySelector("[data-monitor-status]");
  const buttons = Array.from(root.querySelectorAll("[data-monitor-range]")).filter((button) => button instanceof HTMLButtonElement);
  const modal = root.querySelector("[data-monitor-chart-modal]");
  const modalCanvas = root.querySelector("[data-monitor-expanded-chart]");
  const zoomInButton = root.querySelector("[data-monitor-chart-zoom-in]");
  const zoomOutButton = root.querySelector("[data-monitor-chart-zoom-out]");
  const zoomPercentInput = root.querySelector("[data-monitor-chart-zoom-percent]");
  const captureZoomCenter = () => {
    const highlightedTime = MONITOR_CHART_INTERACTIONS.get(modalCanvas)?.highlightedTime;
    if (highlightedTime !== null && highlightedTime !== undefined && Number.isFinite(highlightedTime)) expandedZoomCenterTime = highlightedTime;
  };
  const applyAreaZoom = ({ startTime, endTime, fullMinTime, fullMaxTime }) => {
    const selectedSpan = Math.max(1, endTime - startTime);
    const fullSpan = Math.max(1, fullMaxTime - fullMinTime);
    expandedZoomPercent = Math.max(100, Math.min(800, Math.round((fullSpan / selectedSpan) * 100)));
    expandedZoomCenterTime = startTime + (selectedSpan / 2);
    renderExpandedChart();
  };
  const renderExpandedChart = () => {
    if (!latestPayload || !expandedType || !(modal instanceof HTMLDialogElement) || !modal.open) return;
    monitorSetText(root, "[data-monitor-chart-modal-title]", MONITOR_CHART_TITLES[expandedType] || "Chart");
    monitorSetText(root, "[data-monitor-chart-modal-range]", `Monitor chart · ${hours}h`);
    if (zoomPercentInput instanceof HTMLInputElement) zoomPercentInput.value = String(expandedZoomPercent);
    if (zoomInButton instanceof HTMLButtonElement) zoomInButton.disabled = expandedZoomPercent >= 800;
    if (zoomOutButton instanceof HTMLButtonElement) zoomOutButton.disabled = expandedZoomPercent <= 100;
    drawMonitorChartType(modalCanvas, expandedType, latestPayload, { onAreaZoom: applyAreaZoom, zoom: expandedZoomPercent / 100, zoomCenterTime: expandedZoomCenterTime });
  };
  const setStatus = (value) => {
    if (status instanceof HTMLElement) {
      status.textContent = value;
    }
  };
  const load = async () => {
    if (loading) {
      return;
    }
    loading = true;
    setStatus("Refreshing metrics");
    try {
      const response = await fetch(`/monitor/data?hours=${hours}`, { credentials: "same-origin" });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      latestPayload = await response.json();
      renderMonitorPage(root, latestPayload);
      renderExpandedChart();
      if (latestPayload.enabled === false) {
        setStatus("Monitoring disabled");
        return;
      }
      const sampleTime = latestPayload.last_sample_at ? new Date(latestPayload.last_sample_at) : null;
      setStatus(sampleTime ? `Last sample ${sampleTime.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}` : "Waiting for samples");
    } catch (error) {
      setStatus(`Monitor unavailable: ${error.message}`);
    } finally {
      loading = false;
    }
  };
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      hours = Number(button.dataset.monitorRange || 6);
      expandedZoomPercent = 100;
      expandedZoomCenterTime = null;
      buttons.forEach((candidate) => candidate.classList.toggle("active", candidate === button));
      load();
    });
  });
  root.querySelectorAll("[data-monitor-chart-expand]").forEach((button) => {
    button.addEventListener("click", () => {
      expandedType = button.dataset.monitorChartExpand || "";
      if (!MONITOR_CHART_TITLES[expandedType] || !(modal instanceof HTMLDialogElement)) return;
      expandedZoomPercent = 100;
      expandedZoomCenterTime = null;
      modal.showModal();
      window.requestAnimationFrame(renderExpandedChart);
    });
  });
  zoomInButton?.addEventListener("click", () => {
    captureZoomCenter();
    expandedZoomPercent = Math.min(800, expandedZoomPercent + 25);
    renderExpandedChart();
  });
  zoomOutButton?.addEventListener("click", () => {
    expandedZoomPercent = Math.max(100, expandedZoomPercent - 25);
    if (expandedZoomPercent === 100) expandedZoomCenterTime = null;
    renderExpandedChart();
  });
  const applyZoomPercentInput = ({ clamp = false } = {}) => {
    if (!(zoomPercentInput instanceof HTMLInputElement) || !zoomPercentInput.value.trim()) return;
    const requested = Number(zoomPercentInput.value);
    if (!Number.isFinite(requested) || (!clamp && (requested < 100 || requested > 800))) return;
    expandedZoomPercent = Math.max(100, Math.min(800, Math.round(requested)));
    if (expandedZoomPercent > 100) captureZoomCenter();
    else expandedZoomCenterTime = null;
    renderExpandedChart();
  };
  zoomPercentInput?.addEventListener("input", () => applyZoomPercentInput());
  zoomPercentInput?.addEventListener("change", () => applyZoomPercentInput({ clamp: true }));
  zoomPercentInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") event.currentTarget.blur();
  });
  root.querySelector("[data-monitor-chart-modal-close]")?.addEventListener("click", () => modal?.close());
  modal?.addEventListener("click", (event) => {
    if (event.target === modal) modal.close();
  });
  modal?.addEventListener("close", () => {
    expandedType = "";
  });
  window.addEventListener("resize", () => {
    if (latestPayload) {
      renderMonitorPage(root, latestPayload);
      renderExpandedChart();
    }
  });
  load();
  window.setInterval(load, 5000);
}

function initializeHistoryBackButtons() {
  document.querySelectorAll("[data-history-back]").forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }
    button.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
        return;
      }
      window.location.assign(button.dataset.historyFallback || "/");
    });
  });
}

function initializeVcfVaultCredentialPickers() {
  const dataElement = document.getElementById("vcf-vault-credential-options");
  let vaults = [];
  try {
    vaults = JSON.parse(dataElement?.textContent || "[]");
  } catch (_error) {
    vaults = [];
  }
  const byVaultId = new Map(vaults.map((vault) => [String(vault.id), vault]));
  document.querySelectorAll("[data-vcf-vault-credential-picker]").forEach((picker) => {
    const form = picker.closest("form");
    const vaultSelect = picker.querySelector("[data-vcf-credential-vault]");
    const entrySelect = picker.querySelector("[data-vcf-credential-entry]");
    const status = picker.querySelector("[data-vcf-credential-status]");
    if (!(form instanceof HTMLFormElement) || !(vaultSelect instanceof HTMLSelectElement) || !(entrySelect instanceof HTMLSelectElement)) return;
    const addressControl = form.elements.namedItem(picker.dataset.addressField || "");
    const usernameControl = form.elements.namedItem(picker.dataset.usernameField || "");
    const passwordControl = form.elements.namedItem(picker.dataset.passwordField || "");
    const portControl = form.elements.namedItem(picker.dataset.portField || "");
    const passwordWasRequired = passwordControl instanceof HTMLInputElement && passwordControl.required;
    const passwordPlaceholder = passwordControl instanceof HTMLInputElement ? passwordControl.placeholder : "";
    const emitChange = (control) => {
      control?.dispatchEvent(new Event("input", { bubbles: true }));
      control?.dispatchEvent(new Event("change", { bubbles: true }));
    };
    const setManualMode = (message = "") => {
      if (addressControl instanceof HTMLInputElement) {
        addressControl.readOnly = false;
      }
      if (passwordControl instanceof HTMLInputElement) {
        passwordControl.disabled = false;
        passwordControl.required = passwordWasRequired;
        passwordControl.placeholder = passwordPlaceholder;
      }
      if (status instanceof HTMLElement) {
        status.textContent = message || (vaults.length ? "Manual credentials are active." : "No vault keys are available to this account.");
      }
    };
    const fillEntryOptions = () => {
      const vault = byVaultId.get(vaultSelect.value);
      entrySelect.replaceChildren(new Option(vault ? "Choose a key and HTTP/HTTPS URI" : "Choose a vault first", ""));
      let endpointCount = 0;
      (vault?.entries || []).forEach((entry) => {
        const username = entry.username ? ` — ${entry.username}` : "";
        (entry.uris || []).filter((uri) => /^https?:\/\//i.test(uri)).forEach((endpoint) => {
          const option = new Option(`${entry.key}${username} — ${endpoint}`, String(entry.id));
          option.dataset.endpoint = endpoint;
          entrySelect.append(option);
          endpointCount += 1;
        });
      });
      if (vault && endpointCount === 0) {
        entrySelect.replaceChildren(new Option("No HTTP/HTTPS credentials available", ""));
      }
      entrySelect.disabled = !vault || endpointCount === 0;
      setManualMode(vault && endpointCount === 0 ? "This vault has no keys with an HTTP or HTTPS URI. Continue with manual credentials." : "");
    };
    const applyEntry = () => {
      const vault = byVaultId.get(vaultSelect.value);
      const entry = (vault?.entries || []).find((candidate) => String(candidate.id) === entrySelect.value);
      if (!entry) {
        setManualMode();
        return;
      }
      const endpoint = entrySelect.selectedOptions[0]?.dataset.endpoint || "";
      let parsedEndpoint = null;
      try {
        parsedEndpoint = endpoint ? new URL(endpoint) : null;
      } catch (_error) {
        // URI validation occurs when the vault entry is saved.
      }
      if (addressControl instanceof HTMLInputElement && parsedEndpoint) {
        const useFullUrl = picker.dataset.addressMode === "url";
        addressControl.value = useFullUrl
          ? endpoint
          : portControl instanceof HTMLInputElement
            ? parsedEndpoint.hostname
            : parsedEndpoint.host;
        addressControl.readOnly = true;
        emitChange(addressControl);
      }
      if (usernameControl instanceof HTMLInputElement) {
        usernameControl.value = entry.username || "";
        emitChange(usernameControl);
      }
      if (portControl instanceof HTMLInputElement && parsedEndpoint) {
        portControl.value = parsedEndpoint.port || (parsedEndpoint.protocol === "http:" ? "80" : "443");
        emitChange(portControl);
      }
      if (passwordControl instanceof HTMLInputElement) {
        passwordControl.value = "";
        passwordControl.required = false;
        passwordControl.disabled = true;
        passwordControl.placeholder = "Stored vault password will be used";
      }
      if (status instanceof HTMLElement) {
        status.textContent = `Using ${vault.name} / ${entry.key}. The server address is locked to the vault URI and the stored password is never loaded into this page.`;
      }
    };
    vaultSelect.addEventListener("change", fillEntryOptions);
    entrySelect.addEventListener("change", applyEntry);
    form.addEventListener("reset", () => window.setTimeout(() => {
      fillEntryOptions();
      setManualMode();
    }, 0));
    fillEntryOptions();
  });
}

function hasSelectedVcfVaultCredential(form) {
  if (!(form instanceof HTMLFormElement)) return false;
  const vault = form.elements.namedItem("credential_vault_id");
  const entry = form.elements.namedItem("credential_entry_id");
  return vault instanceof HTMLSelectElement
    && entry instanceof HTMLSelectElement
    && Boolean(vault.value)
    && Boolean(entry.value);
}

function initializeVcfTrustForm() {
  const form = document.querySelector("[data-vcf-trust-form]");
  if (!(form instanceof HTMLFormElement)) {
    return;
  }
  const dialog = document.getElementById("vcf-trust-modal");
  const confirmedTls = form.querySelector("[data-vcf-trust-confirmed-tls-fingerprint]");
  const tlsConfirmation = form.querySelector("[data-vcf-trust-tls-confirmation]");
  const tlsCheckbox = form.querySelector("[data-vcf-trust-tls-confirm]");
  const tlsFingerprint = form.querySelector("[data-vcf-trust-tls-fingerprint]");
  const reviewTarget = form.querySelector("[data-vcf-trust-review-target]");
  const reviewPort = form.querySelector("[data-vcf-trust-review-port]");
  const reviewRole = form.querySelector("[data-vcf-trust-review-role]");
  const reviewVersion = form.querySelector("[data-vcf-trust-review-version]");
  const errors = form.querySelector("[data-vcf-trust-form-errors]");
  const submit = form.querySelector("[data-vcf-trust-submit]");
  const next = form.querySelector("[data-vcf-trust-next]");
  let wizard;
  let inspectedTls = "";
  const steps = [
    { id: "credential", title: "Choose a credential source", description: "Use a saved vault key or continue with a one-time manual login." },
    { id: "target", title: "Target and root CA", description: "Confirm the VCF server address and review the active Atlaso root CA." },
    { id: "tls", title: "Verify the TLS fingerprint", description: "Confirm the observed SHA-256 fingerprint before Atlaso uses credentials." },
    { id: "api", title: "API credentials", description: "Enter the one-time VCF API administrator credentials used to inspect and import the root CA." },
    { id: "review", title: "Review and queue", description: "Review the verified target, then queue the certificate trust task." },
  ];
  const showError = (message) => {
    if (errors instanceof HTMLElement) {
      errors.textContent = message;
      errors.classList.toggle("hidden", !message);
    }
  };
  const resetConfirmation = () => {
    if (confirmedTls instanceof HTMLInputElement) {
      confirmedTls.value = "";
    }
    inspectedTls = "";
    tlsConfirmation?.classList.add("hidden");
    if (tlsCheckbox instanceof HTMLInputElement) {
      tlsCheckbox.checked = false;
      tlsCheckbox.required = false;
    }
    if (reviewTarget instanceof HTMLElement) reviewTarget.textContent = "Not inspected yet";
    if (reviewPort instanceof HTMLElement) reviewPort.textContent = "443";
    if (reviewRole instanceof HTMLElement) reviewRole.textContent = "Inspect target to verify";
    if (reviewVersion instanceof HTMLElement) reviewVersion.textContent = "Inspect target to verify";
  };
  const applyTargetInspection = (payload) => {
    const previouslyConfirmedTls = confirmedTls instanceof HTMLInputElement ? confirmedTls.value : "";
    inspectedTls = payload.tls_fingerprint || payload.fingerprint || "";
    const isConfirmedTls = Boolean(
      inspectedTls
      && previouslyConfirmedTls
      && previouslyConfirmedTls.toUpperCase() === inspectedTls.toUpperCase()
    );
    if (reviewTarget instanceof HTMLElement) reviewTarget.textContent = payload.address || form.elements.address.value || "";
    if (reviewPort instanceof HTMLElement) reviewPort.textContent = String(payload.port || "443");
    const pendingTlsConfirmation = inspectedTls && !payload.appliance;
    if (reviewRole instanceof HTMLElement) reviewRole.textContent = payload.appliance?.role || (pendingTlsConfirmation ? "After TLS confirmation" : "Not inspected yet");
    if (reviewVersion instanceof HTMLElement) reviewVersion.textContent = payload.appliance?.version || (pendingTlsConfirmation ? "After TLS confirmation" : "Not inspected yet");
    if (tlsFingerprint instanceof HTMLElement) tlsFingerprint.textContent = inspectedTls;
    tlsConfirmation?.classList.toggle("hidden", !inspectedTls);
    if (tlsCheckbox instanceof HTMLInputElement) {
      tlsCheckbox.checked = isConfirmedTls;
      tlsCheckbox.required = Boolean(inspectedTls);
    }
    if (confirmedTls instanceof HTMLInputElement) {
      confirmedTls.value = isConfirmedTls ? inspectedTls : "";
    }
  };
  const inspectTarget = async ({ probeOnly = false } = {}) => {
    if (!(await wizard.validate("target"))) return false;
    if (!probeOnly && !(await wizard.validate("api"))) return false;
    showError("");
    if (next instanceof HTMLButtonElement) {
      next.disabled = true;
      next.textContent = "Inspecting…";
    }
    try {
      const response = await fetch("/vcf-helper/trust-root-ca/inspect-target", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
          csrf: form.elements.csrf.value,
          address: form.elements.address.value,
          api_username: form.elements.api_username.value,
          api_password: form.elements.api_password.value,
          credential_vault_id: form.elements.credential_vault_id.value,
          credential_entry_id: form.elements.credential_entry_id.value,
          confirmed_tls_fingerprint: confirmedTls instanceof HTMLInputElement ? confirmedTls.value : "",
        }),
      });
      const payload = await response.json();
      if (response.status === 409 || payload.status === "tls-confirmation-required") {
        applyTargetInspection(payload);
        wizard.showStep("tls", { unlock: true });
        return "tls";
      }
      if (!response.ok) {
        const messages = Array.isArray(payload.errors) ? payload.errors : [payload.detail || payload.error || "Could not inspect the target VCF API."];
        showError(messages.join(" "));
        return false;
      }
      applyTargetInspection(payload);
      wizard.setHighestStep("review");
      return "ready";
    } catch (_error) {
      showError("Could not inspect the target VCF API. Check connectivity and try again.");
      return false;
    } finally {
      if (next instanceof HTMLButtonElement) {
        next.disabled = false;
        next.textContent = "Next";
      }
    }
  };
  wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps,
    onNext: async ({ step }) => {
      if (step.id === "target") {
        if (confirmedTls instanceof HTMLInputElement) confirmedTls.value = "";
        const state = await inspectTarget({ probeOnly: true });
        return state === "tls" ? "tls" : false;
      }
      if (step.id === "tls") {
        if (hasSelectedVcfVaultCredential(form)) {
          const state = await inspectTarget();
          return state === "ready" ? "review" : state === "tls" ? "tls" : false;
        }
        return "api";
      }
      if (step.id === "api") {
        const state = await inspectTarget();
        return state === "ready" ? "review" : state === "tls" ? "tls" : false;
      }
      return true;
    },
    onSubmit: async () => {
      showError("");
      if (submit instanceof HTMLButtonElement) submit.textContent = "Queueing task…";
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          credentials: "same-origin",
          headers: { "X-Atlaso-VCF-Trust": "1" },
        });
        const payload = await response.json();
        if (response.status === 409 && payload.status === "tls-confirmation-required") {
          applyTargetInspection(payload);
          wizard.showStep("tls", { unlock: true });
          if (submit instanceof HTMLButtonElement) submit.textContent = "Run trust task";
          return { ok: false };
        }
        if (!response.ok) {
          const messages = Array.isArray(payload.errors) ? payload.errors : [payload.error || "The VCF trust task could not be queued."];
          if (submit instanceof HTMLButtonElement) submit.textContent = "Run trust task";
          return { ok: false, message: messages.join(" ") };
        }
        if (submit instanceof HTMLButtonElement) submit.textContent = "Task queued";
        wizard.markClean();
        window.location.assign(payload.redirect || `/tasks?job_id=${encodeURIComponent(payload.job_id || "")}`);
        return { ok: true, close: false };
      } catch (_error) {
        if (submit instanceof HTMLButtonElement) submit.textContent = "Run trust task";
        return { ok: false, message: "The request could not be completed. Check connectivity and try again." };
      }
    },
    closeOnSubmit: false,
    onClose: () => {
      form.reset();
      resetConfirmation();
    },
  });
  tlsCheckbox?.addEventListener("change", () => {
    if (!(confirmedTls instanceof HTMLInputElement) || !(tlsCheckbox instanceof HTMLInputElement)) return;
    confirmedTls.value = tlsCheckbox.checked ? inspectedTls : "";
  });
  if (dialog instanceof HTMLDialogElement && dialog.hasAttribute("data-vcf-trust-auto-open") && !dialog.open) {
    wizard.open({ reset: false });
  }
}

async function vcfHelperJson(url, method, payload) {
  const response = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: method === "GET" ? undefined : JSON.stringify(payload),
  });
  let data = {};
  try { data = await response.json(); } catch (_error) { data = {}; }
  if (!response.ok && ![409].includes(response.status)) {
    const detail = typeof data.detail === "string" ? data.detail : "The VCF Helper request failed.";
    throw new Error(detail);
  }
  return { response, data };
}

function fillVcfInventorySelect(select, rows, emptyLabel = "") {
  if (!(select instanceof HTMLSelectElement)) return;
  select.replaceChildren();
  if (emptyLabel) select.append(new Option(emptyLabel, ""));
  (Array.isArray(rows) ? rows : []).forEach((row) => select.append(new Option(row.name || row.id, row.id)));
}

function initializeVcfSddcDeployment() {
  const form = document.querySelector("[data-vcf-sddc-deploy-form]");
  const dialog = document.getElementById("vcf-sddc-deploy-modal");
  if (!(form instanceof HTMLFormElement) || !(dialog instanceof HTMLDialogElement)) return;
  const open = document.querySelector("[data-vcf-sddc-deploy-open]");
  const next = form.querySelector("[data-vcf-sddc-next]");
  const submit = form.querySelector("[data-vcf-sddc-submit]");
  const errors = form.querySelector("[data-vcf-sddc-errors]");
  const confirmation = form.querySelector("[data-vcf-sddc-confirmation]");
  const destination = form.querySelector("[data-vcf-sddc-destination]");
  const propertyContainer = form.querySelector("[data-vcf-sddc-properties]");
  const networkContainer = form.querySelector("[data-vcf-sddc-networks]");
  const ovaSelect = form.querySelector("[data-vcf-sddc-ova]");
  const vmName = form.querySelector("[data-vcf-sddc-vm-name]");
  const tlsFingerprint = form.querySelector("[data-vcf-sddc-tls-fingerprint]");
  const tlsConfirmation = form.querySelector("[data-vcf-sddc-tls-confirmation]");
  const tlsConfirmationFingerprint = form.querySelector("[data-vcf-sddc-tls-confirmation-fingerprint]");
  const tlsConfirmInput = form.querySelector("[data-vcf-sddc-tls-confirm]");
  const configureDepot = form.querySelector("[data-vcf-sddc-configure-depot]");
  const applyTrust = form.querySelector("[data-vcf-sddc-apply-trust]");
  const powerOn = form.querySelector("[data-vcf-sddc-power-on]");
  const postPowerOptions = [...form.querySelectorAll("[data-vcf-sddc-post-power-option]")];
  const depotPasswordRow = form.querySelector("[data-vcf-sddc-depot-password]");
  const assignmentMode = form.querySelector("[data-vcf-sddc-assignment-mode]");
  const dhcpZoneRow = form.querySelector("[data-vcf-sddc-dhcp-zone-row]");
  const dhcpZoneSelect = form.querySelector("[data-vcf-sddc-dhcp-zone]");
  const autoHostnameRow = form.querySelector("[data-vcf-sddc-auto-hostname-row]");
  const autoHostname = form.querySelector("[data-vcf-sddc-auto-hostname]");
  const autoIpRow = form.querySelector("[data-vcf-sddc-auto-ip-row]");
  const autoIp = form.querySelector("[data-vcf-sddc-auto-ip]");
  const taskPanel = form.querySelector("[data-vcf-sddc-task]");
  let activeJob = "";
  let currentOva = null;
  let pollTimer = 0;
  let ovas = [];
  let dhcpAssignment = { available: false, scopes: [] };
  let autoHostnameTouched = false;
  let pendingTlsAction = null;
  let pendingTlsFingerprint = "";
  let wizard;
  const steps = [
    { id: "source", title: "vCenter / ESXi information", description: "Choose the SDDC Manager OVA and the vSphere endpoint used for discovery and import." },
    { id: "resources", title: "Resources and VM name", description: "Select the destination placement, datastore, network mapping, disk mode, and VM name." },
    { id: "address", title: "Address assignment and hostname", description: "Use manual OVF networking values or pre-fill address details from a Atlaso DHCP zone." },
    { id: "properties", title: "OVF properties", description: "Review and complete the appliance OVF properties before deployment." },
    { id: "followup", title: "Post-deployment options", description: "Choose power-on behavior and optional DNS, trust, and offline-depot follow-up actions." },
  ];
  try { ovas = JSON.parse(form.dataset.ovas || "[]"); } catch (_error) { ovas = []; }
  try { dhcpAssignment = JSON.parse(form.dataset.dhcpAssignment || "{}"); } catch (_error) { dhcpAssignment = { available: false, scopes: [] }; }

  const showError = (message) => {
    if (errors instanceof HTMLElement) { errors.textContent = message; errors.classList.toggle("hidden", !message); }
  };
  const showConfirmation = (message) => {
    if (confirmation instanceof HTMLElement) { confirmation.textContent = message; confirmation.classList.toggle("hidden", !message); }
  };
  const showTaskError = (message) => {
    const taskError = form.querySelector("[data-vcf-sddc-task-error]");
    if (taskError instanceof HTMLElement) { taskError.textContent = message; taskError.classList.toggle("hidden", !message); }
  };
  const showTlsConfirmation = (fingerprint, action) => {
    pendingTlsFingerprint = fingerprint || "";
    pendingTlsAction = action;
    if (tlsConfirmationFingerprint instanceof HTMLElement) tlsConfirmationFingerprint.textContent = pendingTlsFingerprint;
    if (tlsConfirmInput instanceof HTMLInputElement) tlsConfirmInput.checked = false;
    tlsConfirmation?.classList.remove("hidden");
  };
  const hideTlsConfirmation = () => {
    tlsConfirmation?.classList.add("hidden");
    pendingTlsAction = null;
    pendingTlsFingerprint = "";
  };
  const selectedOva = () => ovas.find((row) => row.path === ovaSelect?.value) || null;
  const propertyControl = (key) => propertyContainer instanceof HTMLElement ? propertyContainer.querySelector(`[data-ovf-key="${CSS.escape(key)}"]`) : null;
  const selectedDhcpScope = () => (dhcpAssignment.scopes || []).find((row) => String(row.id) === String(dhcpZoneSelect?.value)) || null;
  const hostLabelFromVmName = (scope) => {
    const rawName = String(vmName?.value || "").trim();
    const domain = String(scope?.domain_name || "").trim().toLowerCase();
    if (domain && rawName.toLowerCase().endsWith(`.${domain}`)) return rawName.slice(0, -(domain.length + 1));
    return rawName.split(".")[0] || rawName || "sddcm";
  };
  const fqdnForAutoHost = (scope) => {
    const host = String(autoHostname?.value || "").trim().replace(/\.$/, "");
    if (!host) return "";
    if (host.includes(".")) return host;
    return scope?.domain_name ? `${host}.${scope.domain_name}` : host;
  };
  const syncOva = () => {
    currentOva = selectedOva();
    if (vmName instanceof HTMLInputElement && currentOva) vmName.value = currentOva.vm_name || "";
  };
  const setPropertyValue = (key, value) => {
    const control = propertyControl(key);
    if (control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement) {
      control.value = value || "";
      control.dispatchEvent(new Event("change", { bubbles: true }));
    }
  };
  const syncPostPowerOptions = () => {
    const enabled = !(powerOn instanceof HTMLInputElement) || powerOn.checked;
    postPowerOptions.forEach((row) => {
      const control = row.querySelector("input, select, textarea");
      if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement)) return;
      if (!control.dataset.baseDisabled) control.dataset.baseDisabled = control.disabled ? "true" : "false";
      if (!enabled && control instanceof HTMLInputElement && control.type === "checkbox") control.checked = false;
      control.disabled = !enabled || control.dataset.baseDisabled === "true";
    });
    depotPasswordRow?.classList.toggle("hidden", !enabled || !(configureDepot instanceof HTMLInputElement && configureDepot.checked));
  };
  const applyDhcpAssignment = (options = {}) => {
    const automatic = assignmentMode?.value === "automatic";
    [dhcpZoneRow, autoHostnameRow, autoIpRow].forEach((row) => row?.classList.toggle("hidden", !automatic));
    if (!automatic) return;
    const scope = selectedDhcpScope();
    if (!scope) return;
    if (!autoHostnameTouched || options.refreshHostname) {
      if (autoHostname instanceof HTMLInputElement) autoHostname.value = hostLabelFromVmName(scope);
    }
    if (autoIp instanceof HTMLInputElement && options.refreshIp !== false) autoIp.value = scope.suggested_ipv4 || "";
    setPropertyValue("ip_address_version", "IPv4");
    setPropertyValue("vami.hostname", fqdnForAutoHost(scope));
    setPropertyValue("ip0", autoIp instanceof HTMLInputElement ? autoIp.value : scope.suggested_ipv4 || "");
    setPropertyValue("netmask0", scope.netmask || "");
    setPropertyValue("gateway", scope.gateway || "");
    setPropertyValue("DNS", scope.dns_server || "");
    setPropertyValue("domain", scope.domain_name || "");
    setPropertyValue("searchpath", scope.domain_name || "");
    if (scope.ntp_server) setPropertyValue("guestinfo.ntp", scope.ntp_server);
  };
  const renderProperties = (properties) => {
    if (!(propertyContainer instanceof HTMLElement)) return;
    propertyContainer.replaceChildren();
    (properties || []).forEach((property) => {
      const label = document.createElement("label");
      const heading = document.createElement("span"); heading.className = "field-label";
      const title = document.createElement("span"); title.textContent = property.label || property.key;
      const help = document.createElement("button"); help.type = "button"; help.className = "help-icon"; help.textContent = "i";
      help.dataset.help = [property.description, property.qualifiers].filter(Boolean).join(" ");
      heading.append(title, help); label.append(heading);
      const values = [...String(property.qualifiers || "").matchAll(/"([^"]+)"/g)].map((match) => match[1]);
      let control;
      if (values.length) {
        control = document.createElement("select"); values.forEach((value) => control.append(new Option(value, value)));
      } else {
        control = document.createElement("input"); control.type = property.password ? "password" : "text";
        if (property.password) control.autocomplete = "new-password";
        const minLen = String(property.qualifiers || "").match(/MinLen\((\d+)\)/);
        const maxLen = String(property.qualifiers || "").match(/MaxLen\((\d+)\)/);
        if (minLen) control.minLength = Number(minLen[1]);
        if (maxLen) control.maxLength = Number(maxLen[1]);
      }
      control.dataset.ovfKey = property.key; control.value = property.default || "";
      if (["ROOT_PASSWORD", "LOCAL_USER_PASSWORD", "vami.hostname"].includes(property.key)) control.required = true;
      label.append(control); propertyContainer.append(label);
    });
    const updatePropertyRequirements = () => {
      const version = propertyControl("ip_address_version")?.value || "IPv4";
      const ipv4Required = version.includes("IPv4");
      const ipv6Required = version.includes("IPv6");
      ["ip0", "netmask0", "gateway", "DNS"].forEach((key) => { const control = propertyControl(key); if (control) control.required = ipv4Required; });
      ["ipv6", "ipv6_prefix", "ipv6_gateway"].forEach((key) => { const control = propertyControl(key); if (control) control.required = ipv6Required; });
    };
    propertyContainer.querySelector('[data-ovf-key="ip_address_version"]')?.addEventListener("change", updatePropertyRequirements);
    updatePropertyRequirements();
    applyDhcpAssignment({ refreshIp: true });
  };
  const renderNetworks = (networks, inventoryNetworks) => {
    if (!(networkContainer instanceof HTMLElement)) return;
    networkContainer.replaceChildren();
    (networks || []).forEach((networkName) => {
      const label = document.createElement("label");
      const heading = document.createElement("span"); heading.className = "field-label";
      const title = document.createElement("span"); title.textContent = `${networkName} mapping`;
      const help = document.createElement("button"); help.type = "button"; help.className = "help-icon"; help.textContent = "i"; help.dataset.help = "Maps the source OVA network to a vSphere network.";
      heading.append(title, help); label.append(heading);
      const select = document.createElement("select"); select.dataset.ovaNetwork = networkName; select.required = true;
      fillVcfInventorySelect(select, inventoryNetworks); label.append(select); networkContainer.append(label);
    });
  };
  const parseEndpoint = () => {
    const raw = String(form.elements.address.value || "").trim();
    const endpoint = raw.replace(/^https?:\/\//i, "");
    if (endpoint.startsWith("[") && endpoint.includes("]")) {
      const closing = endpoint.indexOf("]");
      const host = endpoint.slice(1, closing);
      const rest = endpoint.slice(closing + 1);
      const parsedPort = rest.startsWith(":") ? Number(rest.slice(1)) : 443;
      return { address: host, port: Number.isInteger(parsedPort) && parsedPort > 0 ? parsedPort : 443 };
    }
    const slashless = endpoint.split("/")[0];
    const colonParts = slashless.split(":");
    if (colonParts.length === 2 && /^\d+$/.test(colonParts[1])) {
      return { address: colonParts[0], port: Number(colonParts[1]) };
    }
    return { address: slashless, port: 443 };
  };
  const basePayload = () => {
    const endpoint = parseEndpoint();
    return {
      csrf: form.elements.csrf.value,
      ova_path: form.elements.ova_path.value,
      address: endpoint.address,
      port: endpoint.port,
      username: form.elements.username.value.trim(),
      password: form.elements.password.value,
      credential_vault_id: form.elements.credential_vault_id.value,
      credential_entry_id: form.elements.credential_entry_id.value,
      confirmed_tls_fingerprint: form.elements.confirmed_tls_fingerprint.value,
    };
  };
  const poll = async () => {
    if (!activeJob) return;
    try {
      const { data } = await vcfHelperJson(`/vcf-helper/sddc-manager/tasks/${encodeURIComponent(activeJob)}`, "GET", {});
      form.querySelector("[data-vcf-sddc-task-status]").textContent = data.status;
      form.querySelector("[data-vcf-sddc-state]").textContent = data.result?.state || data.status;
      form.querySelector("[data-vcf-sddc-progress]").textContent = `${data.progress_percent}%`;
      showTaskError(data.error || "");
      if (["pending", "running"].includes(data.status)) pollTimer = window.setTimeout(poll, 2000);
    } catch (error) { showTaskError(error.message); }
  };

  ovaSelect?.addEventListener("change", syncOva);
  vmName?.addEventListener("input", () => {
    if (assignmentMode?.value === "automatic" && !autoHostnameTouched) applyDhcpAssignment({ refreshHostname: true, refreshIp: false });
  });
  assignmentMode?.addEventListener("change", () => applyDhcpAssignment({ refreshHostname: true, refreshIp: true }));
  dhcpZoneSelect?.addEventListener("change", () => applyDhcpAssignment({ refreshHostname: true, refreshIp: true }));
  autoHostname?.addEventListener("input", () => { autoHostnameTouched = true; applyDhcpAssignment({ refreshIp: false }); });
  autoIp?.addEventListener("input", () => applyDhcpAssignment({ refreshIp: false }));
  powerOn?.addEventListener("change", syncPostPowerOptions);
  applyTrust?.addEventListener("change", syncPostPowerOptions);
  configureDepot?.addEventListener("change", syncPostPowerOptions);
  syncPostPowerOptions();
  const handleDiscover = async () => {
    if (!(await wizard.validate("source"))) return false;
    showError(""); showConfirmation("");
    if (next instanceof HTMLButtonElement) {
      next.disabled = true;
      next.textContent = "Discovering…";
    }
    try {
      const { response, data } = await vcfHelperJson("/vcf-helper/sddc-manager/inventory", "POST", basePayload());
      if (response.status === 409 && data.status === "tls-confirmation-required") {
        showTlsConfirmation(data.fingerprint || "", handleDiscover);
        return;
      }
      currentOva = data.ova;
      fillVcfInventorySelect(form.elements.resource_pool_id, data.inventory?.resource_pools);
      fillVcfInventorySelect(form.elements.datastore_id, data.inventory?.datastores);
      fillVcfInventorySelect(form.elements.folder_id, data.inventory?.folders, "Default VM folder");
      fillVcfInventorySelect(form.elements.host_id, data.inventory?.hosts, "Automatic placement");
      renderNetworks(data.ova?.networks, data.inventory?.networks);
      renderProperties(data.ova?.properties);
      wizard.setHighestStep("followup");
      wizard.showStep("resources", { unlock: true });
      return true;
    } catch (error) {
      showError(error.message);
      return false;
    } finally {
      if (next instanceof HTMLButtonElement) {
        next.disabled = false;
        next.textContent = "Next";
      }
    }
  };
  const handleSubmit = async () => {
    showError(""); showTaskError("");
    const properties = {}; form.querySelectorAll("[data-ovf-key]").forEach((control) => { properties[control.dataset.ovfKey] = control.value; });
    const networkIds = {}; form.querySelectorAll("[data-ova-network]").forEach((control) => { networkIds[control.dataset.ovaNetwork] = control.value; });
    const shouldPowerOn = !(form.elements.power_on instanceof HTMLInputElement) || form.elements.power_on.checked;
    const payload = {
      ...basePayload(), vm_name: form.elements.vm_name.value, properties,
      destination: { resource_pool_id: form.elements.resource_pool_id.value, datastore_id: form.elements.datastore_id.value, folder_id: form.elements.folder_id.value, host_id: form.elements.host_id.value, network_ids: networkIds },
      options: { power_on: shouldPowerOn, add_dns: form.elements.add_dns.checked, apply_trust: shouldPowerOn && form.elements.apply_trust.checked, configure_offline_depot: shouldPowerOn && form.elements.configure_offline_depot.checked, disk_provisioning: form.elements.disk_provisioning.value },
      depot_password: form.elements.depot_password.value,
    };
    try {
      const { response, data } = await vcfHelperJson("/vcf-helper/sddc-manager/deploy", "POST", payload);
      if (response.status === 409 && data.status === "tls-confirmation-required") {
        showTlsConfirmation(data.fingerprint || "", handleSubmit);
        return { ok: false };
      }
      activeJob = data.job_id;
      wizard.markClean();
      window.location.assign(`/tasks?job_id=${encodeURIComponent(activeJob)}`);
      return { ok: true, close: false };
    } catch (error) {
      return { ok: false, message: error.message };
    }
  };
  wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps,
    onNext: async ({ step }) => {
      if (step.id !== "source") return true;
      await handleDiscover();
      return false;
    },
    onOpen: () => {
      syncOva();
      autoHostnameTouched = false;
      hideTlsConfirmation();
      showError("");
      showConfirmation("");
      syncPostPowerOptions();
    },
    onSubmit: handleSubmit,
    closeOnSubmit: false,
  });
  open?.addEventListener("click", (event) => wizard.open({ launcher: event.currentTarget }));
  tlsConfirmInput?.addEventListener("change", async () => {
    if (!(tlsConfirmInput instanceof HTMLInputElement) || !tlsConfirmInput.checked) return;
    if (tlsFingerprint instanceof HTMLInputElement) tlsFingerprint.value = pendingTlsFingerprint;
    const action = pendingTlsAction;
    hideTlsConfirmation();
    if (typeof action === "function") await action();
  });
  syncOva();
}

function initializeVcfTargetDepotHelper() {
  const form = document.querySelector("[data-vcf-target-depot-form]");
  const dialog = document.getElementById("vcf-target-depot-modal");
  if (!(form instanceof HTMLFormElement) || !(dialog instanceof HTMLDialogElement)) return;
  const errors = form.querySelector("[data-vcf-target-depot-errors]");
  const tls = form.querySelector("[data-vcf-target-depot-tls-fingerprint]");
  const submit = form.querySelector("[data-vcf-target-depot-submit]");
  const next = form.querySelector("[data-vcf-target-depot-next]");
  const tlsConfirmation = form.querySelector("[data-vcf-target-depot-tls-confirmation]");
  const tlsConfirm = form.querySelector("[data-vcf-target-depot-tls-confirm]");
  const tlsConfirmationFingerprint = form.querySelector("[data-vcf-target-depot-tls-confirmation-fingerprint]");
  const reviewTarget = form.querySelector("[data-vcf-target-depot-review-target]");
  const reviewPort = form.querySelector("[data-vcf-target-depot-review-port]");
  const reviewRole = form.querySelector("[data-vcf-target-depot-review-role]");
  const reviewVersion = form.querySelector("[data-vcf-target-depot-review-version]");
  const reviewTls = form.querySelector("[data-vcf-target-depot-review-tls]");
  const queueTarget = form.querySelector("[data-vcf-target-depot-queue-target]");
  const queueAction = form.querySelector("[data-vcf-target-depot-queue-action]");
  let wizard;
  let inspected = null;
  let inspectedTls = "";
  const steps = [
    { id: "credential", title: "Choose a credential source", description: "Use a saved vault key or continue with a one-time manual login." },
    { id: "target", title: "Target and local depot", description: "Choose the remote VCF appliance and review the local Atlaso depot endpoint." },
    { id: "tls", title: "Verify the server fingerprint", description: "Confirm the observed TLS fingerprint out of band before Atlaso resolves or sends credentials." },
    { id: "api", title: "API credentials", description: "Enter the one-time VCF API administrator credentials." },
    { id: "depot", title: "Depot credentials", description: "Enter the one-time password for the configured Atlaso depot HTTP user." },
    { id: "review", title: "Review current settings", description: "Review the sanitized current target depot configuration." },
    { id: "queue", title: "Queue configuration", description: "Start the background task and continue monitoring from Operations → Tasks." },
  ];
  const showError = (message) => { errors.textContent = message; errors.classList.toggle("hidden", !message); };
  const payload = () => ({ csrf: form.elements.csrf.value, address: form.elements.address.value.trim(), api_username: form.elements.api_username.value.trim(), api_password: form.elements.api_password.value, credential_vault_id: form.elements.credential_vault_id.value, credential_entry_id: form.elements.credential_entry_id.value, depot_password: form.elements.depot_password.value, confirmed_tls_fingerprint: form.elements.confirmed_tls_fingerprint.value, replace_existing: form.elements.replace_existing.checked });
  const resetInspection = () => {
    if (tls instanceof HTMLInputElement) tls.value = "";
    inspected = null;
    inspectedTls = "";
    tlsConfirmation?.classList.add("hidden");
    if (tlsConfirm instanceof HTMLInputElement) {
      tlsConfirm.checked = false;
      tlsConfirm.required = false;
    }
    showError("");
  };
  const renderCurrentDepot = (data) => {
    const hasTargetDetails = Boolean(data.target?.appliance);
    inspected = hasTargetDetails ? data : null;
    const previouslyConfirmedTls = tls instanceof HTMLInputElement ? tls.value : "";
    inspectedTls = data.tls_fingerprint || data.fingerprint || "";
    const isConfirmedTls = Boolean(
      inspectedTls
      && previouslyConfirmedTls
      && previouslyConfirmedTls.toUpperCase() === inspectedTls.toUpperCase()
    );
    if (tls instanceof HTMLInputElement) tls.value = isConfirmedTls ? inspectedTls : "";
    if (reviewTarget instanceof HTMLElement) reviewTarget.textContent = data.target?.address || data.address || form.elements.address.value || "";
    if (reviewPort instanceof HTMLElement) reviewPort.textContent = String(data.port || "443");
    const pendingTlsConfirmation = inspectedTls && !hasTargetDetails;
    if (reviewRole instanceof HTMLElement) reviewRole.textContent = data.target?.appliance?.role || (pendingTlsConfirmation ? "After TLS confirmation" : "Not inspected yet");
    if (reviewVersion instanceof HTMLElement) reviewVersion.textContent = data.target?.appliance?.version || (pendingTlsConfirmation ? "After TLS confirmation" : "Not inspected yet");
    if (reviewTls instanceof HTMLElement) reviewTls.textContent = inspectedTls || "not available";
    if (queueTarget instanceof HTMLElement) queueTarget.textContent = reviewTarget?.textContent || "";
    if (queueAction instanceof HTMLElement) queueAction.textContent = data.replacement_required ? "Replace existing depot and sync metadata" : "Configure or verify Atlaso depot and sync metadata";
    if (tlsConfirmationFingerprint instanceof HTMLElement) tlsConfirmationFingerprint.textContent = inspectedTls;
    tlsConfirmation?.classList.toggle("hidden", !inspectedTls);
    if (tlsConfirm instanceof HTMLInputElement) {
      tlsConfirm.checked = isConfirmedTls;
      tlsConfirm.required = Boolean(inspectedTls);
    }
    const current = data.target?.depot || {};
    const values = form.querySelector("[data-vcf-target-depot-current-values]");
    if (values instanceof HTMLElement) {
      values.replaceChildren();
      [["Hostname", current.hostname || "not configured"], ["Port", current.port || ""], ["URL", current.url || ""], ["User", current.username || ""], ["Status", current.status || ""]].forEach(([label, value]) => {
        const row = document.createElement("div");
        const key = document.createElement("span"); key.textContent = label;
        const strong = document.createElement("strong"); strong.textContent = value;
        row.append(key, strong); values.append(row);
      });
    }
    form.querySelector("[data-vcf-target-depot-current]")?.classList.toggle("hidden", !hasTargetDetails);
    const replaceRow = form.querySelector("[data-vcf-target-depot-replace-row]");
    replaceRow?.classList.toggle("hidden", !hasTargetDetails || !data.replacement_required);
    if (form.elements.replace_existing instanceof HTMLInputElement) {
      form.elements.replace_existing.required = Boolean(hasTargetDetails && data.replacement_required);
      if (!hasTargetDetails) {
        form.elements.replace_existing.checked = false;
      }
    }
  };
  const inspect = async () => {
    showError("");
    if (next instanceof HTMLButtonElement) {
      next.disabled = true;
      next.textContent = "Inspecting…";
    }
    try {
      const { response, data } = await vcfHelperJson("/vcf-helper/offline-depot/inspect-target", "POST", payload());
      if (response.status === 409 && data.status === "tls-confirmation-required") {
        renderCurrentDepot(data);
        return "tls";
      }
      renderCurrentDepot(data);
      return "ready";
    } catch (error) {
      showError(error.message);
      return false;
    } finally {
      if (next instanceof HTMLButtonElement) {
        next.disabled = false;
        next.textContent = "Next";
      }
    }
  };
  wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps,
    onNext: async ({ step }) => {
      if (step.id === "target") {
        const state = await inspect();
        return state === "tls" ? "tls" : state === "ready"
          ? (hasSelectedVcfVaultCredential(form) ? "depot" : "api")
          : false;
      }
      if (step.id === "tls") {
        if (!(tlsConfirm instanceof HTMLInputElement) || !tlsConfirm.checked || !inspectedTls) {
          return false;
        }
        if (tls instanceof HTMLInputElement) tls.value = inspectedTls;
        return hasSelectedVcfVaultCredential(form) ? "depot" : "api";
      }
      if (step.id === "depot") {
        const state = await inspect();
        return state === "ready" ? "review" : state === "tls" ? "tls" : false;
      }
      if (step.id === "review") {
        if (!inspected && !(tls instanceof HTMLInputElement && tls.value)) {
          const state = await inspect();
          if (state !== "ready") return state === "tls" ? "tls" : false;
        }
        return "queue";
      }
      return true;
    },
    onOpen: resetInspection,
    onClose: resetInspection,
    onSubmit: async () => {
      showError("");
      if (submit instanceof HTMLButtonElement) submit.textContent = "Queueing task…";
      try {
        const { response, data } = await vcfHelperJson("/vcf-helper/offline-depot/configure", "POST", payload());
        if (response.status === 409 && data.status === "replacement-confirmation-required") {
          form.querySelector("[data-vcf-target-depot-replace-row]")?.classList.remove("hidden");
          wizard.showStep("review", { unlock: true });
          if (submit instanceof HTMLButtonElement) submit.textContent = "Configure and sync";
          return { ok: false, message: "Confirm replacement of the existing target depot, then queue again." };
        }
        if (response.status === 409 && data.status === "tls-confirmation-required") {
          renderCurrentDepot(data);
          wizard.showStep("tls", { unlock: true });
          if (submit instanceof HTMLButtonElement) submit.textContent = "Configure and sync";
          return { ok: false };
        }
        wizard.markClean();
        window.location.assign(`/tasks?job_id=${encodeURIComponent(data.job_id || "")}`);
        return { ok: true, close: false };
      } catch (error) {
        if (submit instanceof HTMLButtonElement) submit.textContent = "Configure and sync";
        return { ok: false, message: error.message };
      }
    },
    closeOnSubmit: false,
  });
  document.querySelector("[data-vcf-target-depot-open]")?.addEventListener("click", (event) => {
    wizard.open({ launcher: event.currentTarget });
  });
  tlsConfirm?.addEventListener("change", async () => {
    if (!(tlsConfirm instanceof HTMLInputElement) || !(tls instanceof HTMLInputElement)) return;
    tls.value = tlsConfirm.checked ? inspectedTls : "";
  });
}

function escapeDashboardHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function dashboardTimeMarkup(value) {
  const raw = String(value || "");
  const parsed = new Date(raw);
  const label = Number.isNaN(parsed.getTime())
    ? "Not recorded"
    : parsed.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  return `<time datetime="${escapeDashboardHtml(raw)}">${escapeDashboardHtml(label)}</time>`;
}

function dashboardSnapshotMarkup(snapshot) {
  const overall = snapshot.overall || {};
  const readiness = snapshot.readiness || { active: false, items: [] };
  const attention = Array.isArray(snapshot.attention_items) ? snapshot.attention_items : [];
  const pending = snapshot.pending_changes || { count: 0, invalid_count: 0, units: [] };
  const tasks = snapshot.tasks || { pending: 0, running: 0 };
  const services = snapshot.services || { enabled: 0, running: 0, unhealthy: 0, exceptions: [] };
  const network = snapshot.network || { management: {}, configured: 0, vlans: 0, missing_or_down: 0, exceptions: [] };
  const activity = Array.isArray(snapshot.recent_activity) ? snapshot.recent_activity : [];
  const action = overall.primary_action || { label: "Open monitor", url: "/monitor" };
  const fqdn = overall.fqdn && overall.fqdn !== overall.hostname ? ` · ${escapeDashboardHtml(overall.fqdn)}` : "";
  const readinessRows = (readiness.items || []).map((item) => `
    <a href="${escapeDashboardHtml(item.url)}" class="dashboard-readiness-row ${item.complete ? "complete" : "incomplete"}">
      <span class="dashboard-check" aria-hidden="true">${item.complete ? "✓" : "·"}</span>
      <span><strong>${escapeDashboardHtml(item.label)}</strong><small>${escapeDashboardHtml(item.summary)}</small></span>
      <span class="status-pill ${item.complete ? "good" : "warn"}">${item.complete ? "Ready" : "Next"}</span>
    </a>`).join("");
  const attentionRows = attention.map((item) => `
    <a href="${escapeDashboardHtml(item.url)}" class="dashboard-attention-row">
      <span class="status-pill ${escapeDashboardHtml(item.severity)}">${item.severity === "error" ? "Critical" : "Warning"}</span>
      <span><strong>${escapeDashboardHtml(item.title)}</strong><small>${escapeDashboardHtml(item.summary)}</small></span>
      ${dashboardTimeMarkup(item.timestamp)}
    </a>`).join("");
  const pendingUnits = (pending.units || []).slice(0, 4).map((unit) => `<a href="${escapeDashboardHtml(unit.url)}">${escapeDashboardHtml(unit.label)}</a>`).join("");
  const pendingMore = (pending.units || []).length > 4 ? `<a href="/dashboard#appliance-apply-review" data-appliance-apply-open>+${(pending.units || []).length - 4} more</a>` : "";
  const serviceExceptions = (services.exceptions || []).map((item) => `<a href="${escapeDashboardHtml(item.url)}"><span>${escapeDashboardHtml(item.name)}</span><span class="status-pill warn">${escapeDashboardHtml(item.state)}</span></a>`).join("");
  const networkExceptions = (network.exceptions || []).map((item) => `<a href="${escapeDashboardHtml(item.url)}"><span>${escapeDashboardHtml(item.name)}</span><span class="status-pill warn">${escapeDashboardHtml(item.state)}</span></a>`).join("");
  const activityRows = activity.map((item) => `
    <a class="dashboard-activity-row" href="${escapeDashboardHtml(item.url)}">
      <span class="dashboard-activity-source">${escapeDashboardHtml(item.source)}</span>
      <strong>${escapeDashboardHtml(item.title)}</strong>
      <span class="status-pill ${escapeDashboardHtml(item.outcome_pill)}">${escapeDashboardHtml(item.outcome)}</span>
      <span>${escapeDashboardHtml(item.actor)}</span>
      ${dashboardTimeMarkup(item.timestamp)}
    </a>`).join("");
  return `
    <div class="dashboard-stale-notice" data-dashboard-stale hidden role="status">Live refresh is unavailable. Showing the last successful dashboard snapshot.</div>
    <section class="dashboard-status-band ${escapeDashboardHtml(overall.state)}" aria-labelledby="dashboard-overall-state">
      <div class="dashboard-status-main"><span class="dashboard-status-mark" aria-hidden="true"></span><div><p class="kicker">Appliance status</p><h2 id="dashboard-overall-state">${escapeDashboardHtml(overall.label)}</h2><p>${escapeDashboardHtml(overall.hostname)}${fqdn}</p></div></div>
      <div class="dashboard-status-meta" aria-label="Dashboard status details">
        <span><strong>${overall.dry_run ? "Dry-run" : "Live apply"}</strong><small>${overall.dry_run ? "Adapters record command intent" : "Host changes are enabled"}</small></span>
        <span><strong>Last refreshed</strong><small>${dashboardTimeMarkup(snapshot.generated_at)}</small></span>
      </div>
      <a class="button primary" href="${escapeDashboardHtml(action.url)}">${escapeDashboardHtml(action.label)}</a>
    </section>
    <section class="dashboard-primary-grid">
      <article class="panel dashboard-attention-panel">
        <div class="panel-head compact"><div><h2>${readiness.active ? "Setup readiness" : "Needs attention"}</h2><p class="muted">${readiness.active ? "Complete the appliance foundation before normal operations." : "Actionable exceptions in operator priority order."}</p></div>${readiness.active ? "" : `<span class="status-pill ${attention.length ? "warn" : "good"}">${attention.length} ${attention.length === 1 ? "item" : "items"}</span>`}</div>
        ${readiness.active ? `<div class="dashboard-readiness-list">${readinessRows}</div>` : ""}
        ${attention.length ? `${readiness.active ? '<h3 class="dashboard-subheading">Actionable exceptions</h3>' : ""}<div class="dashboard-attention-list">${attentionRows}</div>` : readiness.active ? "" : '<div class="dashboard-empty-state"><strong>No actionable exceptions</strong><span>Enabled services, configured interfaces, recent tasks, and changed apply units look healthy.</span></div>'}
      </article>
      <article class="panel dashboard-changes-panel">
        <div class="panel-head compact"><div><h2>Changes &amp; Tasks</h2><p class="muted">Desired-state drift and work in progress.</p></div></div>
        <a class="dashboard-summary-row" href="/dashboard#appliance-apply-review" data-appliance-apply-open><span><strong>Pending appliance changes</strong><small>Valid changed units ready for review</small></span><span class="dashboard-summary-value">${Number(pending.count) || 0}</span></a>
        ${(pending.units || []).length ? `<div class="dashboard-unit-links" aria-label="Valid pending apply units">${pendingUnits}${pendingMore}</div>` : '<p class="dashboard-inline-empty">No valid pending changes.</p>'}
        ${pending.invalid_count ? `<p class="dashboard-invalid-note"><span class="status-pill error">${Number(pending.invalid_count) || 0} invalid</span> Kept in Needs attention until resolved.</p>` : ""}
        <a class="dashboard-summary-row" href="/tasks"><span><strong>Tasks</strong><small>Pending and running work</small></span><span class="dashboard-task-counts"><b>${Number(tasks.pending) || 0}</b> pending <b>${Number(tasks.running) || 0}</b> running</span></a>
        <div class="dashboard-panel-actions"><a class="text-link" href="/dashboard#appliance-apply-review" data-appliance-apply-open>Review changes</a><a class="text-link" href="/tasks">Open tasks</a></div>
      </article>
    </section>
    <section class="dashboard-snapshot-grid">
      <article class="panel dashboard-snapshot-panel">
        <div class="panel-head compact"><div><h2>Services</h2><p class="muted">Enabled runtime state; exceptions only.</p></div><a class="text-link" href="/services">Open services</a></div>
        <div class="dashboard-count-strip"><span><strong>${Number(services.enabled) || 0}</strong><small>Enabled</small></span><span><strong>${Number(services.running) || 0}</strong><small>Running</small></span><span><strong>${Number(services.unhealthy) || 0}</strong><small>Unhealthy</small></span></div>
        <div class="dashboard-exception-list">${serviceExceptions || '<p class="dashboard-inline-empty">No enabled service exceptions.</p>'}</div>
      </article>
      <article class="panel dashboard-snapshot-panel">
        <div class="panel-head compact"><div><h2>Network</h2><p class="muted">Management path and configured interfaces.</p></div><a class="text-link" href="/physical-interfaces">Open interfaces</a></div>
        <div class="dashboard-management-row"><span><strong>${escapeDashboardHtml(network.management?.name || "Not discovered")}</strong><small>${escapeDashboardHtml(network.management?.address || "No management address")}</small></span><span class="status-pill ${network.management?.healthy ? "good" : "warn"}">${escapeDashboardHtml(network.management?.link || "missing")}</span></div>
        <div class="dashboard-count-strip network"><span><strong>${Number(network.configured) || 0}</strong><small>Configured</small></span><span><strong>${Number(network.vlans) || 0}</strong><small>VLANs</small></span><span><strong>${Number(network.missing_or_down) || 0}</strong><small>Missing / down</small></span></div>
        <div class="dashboard-exception-list">${networkExceptions || '<p class="dashboard-inline-empty">No configured interface exceptions.</p>'}</div>
      </article>
    </section>
    <section class="panel dashboard-activity-panel">
      <div class="panel-head compact"><div><h2>Recent activity</h2><p class="muted">Tasks and audit events in one chronological view.</p></div><div class="dashboard-activity-links"><a class="text-link" href="/tasks">Tasks</a><a class="text-link" href="/audit-log">Audit events</a></div></div>
      <div class="dashboard-activity-list">${activityRows || '<div class="dashboard-empty-state"><strong>No recent activity</strong><span>Tasks and operator audit events will appear here.</span></div>'}</div>
    </section>`;
}

function initializeDashboard() {
  const root = document.querySelector("[data-dashboard]");
  if (!(root instanceof HTMLElement)) return;
  const refreshUrl = root.dataset.refreshUrl || "/dashboard/data";
  let timer = 0;
  let refreshing = false;
  const schedule = () => {
    window.clearTimeout(timer);
    if (document.visibilityState !== "hidden") timer = window.setTimeout(refresh, 30000);
  };
  const markStale = () => {
    root.classList.add("is-stale");
    const stale = root.querySelector("[data-dashboard-stale]");
    if (stale instanceof HTMLElement) stale.hidden = false;
  };
  const refresh = async () => {
    if (refreshing || document.visibilityState === "hidden") return;
    refreshing = true;
    root.setAttribute("aria-busy", "true");
    const activeElement = document.activeElement;
    const focusedHref = activeElement instanceof HTMLAnchorElement && root.contains(activeElement)
      ? activeElement.getAttribute("href")
      : "";
    const focusedText = focusedHref ? activeElement.textContent?.trim() || "" : "";
    try {
      const response = await fetch(refreshUrl, { headers: { Accept: "application/json" }, credentials: "same-origin" });
      if (!response.ok) throw new Error(`Dashboard refresh failed (${response.status})`);
      const snapshot = await response.json();
      root.innerHTML = dashboardSnapshotMarkup(snapshot);
      root.classList.remove("is-stale");
      if (focusedHref) {
        const focusTarget = Array.from(root.querySelectorAll("a[href]")).find((link) =>
          link.getAttribute("href") === focusedHref && link.textContent?.trim() === focusedText
        );
        if (focusTarget instanceof HTMLElement) focusTarget.focus({ preventScroll: true });
      }
      refreshApplianceApplySidebar().catch(() => {});
    } catch {
      markStale();
    } finally {
      refreshing = false;
      root.removeAttribute("aria-busy");
      schedule();
    }
  };
  document.addEventListener("visibilitychange", () => {
    window.clearTimeout(timer);
    if (document.visibilityState !== "hidden") refresh();
  });
  schedule();
}

function initializeVcfLdapHelper() {
  const dialog = document.getElementById("vcf-ldap-modal");
  if (!(dialog instanceof HTMLDialogElement)) return;
  const openButton = document.querySelector("[data-vcf-ldap-open]");
  const form = dialog.querySelector("[data-vcf-ldap-wizard-form]");
  const organizationSelect = dialog.querySelector("[data-vcf-ldap-organization-select]");
  const generateDialog = document.getElementById("ldap-generate-modal");
  const generateOpen = document.querySelector("[data-ldap-generate-open]");
  const generateForm = generateDialog?.querySelector("[data-ldap-generate-form]");
  const generateOrganization = generateDialog?.querySelector("[data-ldap-generate-organization]");
  let ldapWizard = null;
  if (form instanceof HTMLFormElement && window.AtlasoUiPatterns) {
    const setVcfAction = () => {
      const action = form.elements.namedItem("vcf_ldap_action");
      const value = action instanceof RadioNodeList ? action.value : "inspect";
      form.action = value === "configure"
        ? form.dataset.vcfLdapConfigureUrl
        : form.dataset.vcfLdapInspectUrl;
    };
    ldapWizard = window.AtlasoUiPatterns.createWizard({
      form,
      dialog,
      steps: [
        { id: "organization", title: "Choose the LDAP organization", description: "Review the isolated suffix and mandatory VCF mapping." },
        { id: "connection", title: "Identify the VCF tenant", description: "Set the VCF Automation endpoint and organization identity." },
        { id: "trust", title: "Provide transient trust details", description: "Enter the administrator credential and confirm the presented TLS identity." },
        { id: "review", title: "Choose the VCF action", description: "Inspect current state or configure and verify the reviewed LDAP settings." },
      ],
      discardTitle: "Discard VCF LDAP setup?",
      discardMessage: "The transient connection details entered in this wizard will be lost.",
      prepareReview: () => {
        renderAtlasoWizardReview(form, [
          { label: "LDAP organization", field: "ldap_organization_id" },
          { label: "VCF URL", field: "target_url" },
          { label: "VCF organization ID", field: "vcf_organization_id" },
          { label: "VCF organization name", field: "vcf_organization_name" },
          { label: "TLS fingerprint", value: () => form.elements.confirmed_tls_fingerprint?.value.trim() || "Inspect before configuration" },
          { label: "Replace existing", field: "replace_existing" },
        ]);
        setVcfAction();
      },
    });
    form.querySelectorAll('input[name="vcf_ldap_action"]').forEach((control) => control.addEventListener("change", setVcfAction));
    setVcfAction();
    openButton?.addEventListener("click", () => ldapWizard.open({ launcher: openButton }));
  }
  if (organizationSelect instanceof HTMLSelectElement) {
    organizationSelect.addEventListener("change", () => {
      const query = new URLSearchParams({ ldap_vcf: "1", ldap_organization_id: organizationSelect.value });
      window.location.assign(`/vcf-helper?${query.toString()}`);
    });
  }
  if (generateDialog instanceof HTMLDialogElement) {
    let generateWizard = null;
    const focusGenerateDialog = () => {
      window.requestAnimationFrame(() => {
        const target = generateDialog.querySelector('[aria-label="Save generated credentials"]')
          || generateDialog.querySelector("[data-ldap-generate-user-count]");
        if (target instanceof HTMLElement) {
          target.focus({ preventScroll: true });
          if (target instanceof HTMLInputElement) target.select();
        }
      });
    };
    const openGenerateDialog = () => {
      if (generateWizard) generateWizard.open({ launcher: generateOpen });
      else generateDialog.showModal();
      focusGenerateDialog();
    };
    const clearGeneratedResult = () => {
      generateDialog.querySelectorAll("[data-ldap-generated-result]").forEach((element) => element.remove());
      generateDialog.removeAttribute("data-ldap-generate-auto-open");
    };
    generateOpen?.addEventListener("click", openGenerateDialog);
    generateDialog.addEventListener("close", clearGeneratedResult);
    if (generateForm instanceof HTMLFormElement && generateOrganization instanceof HTMLSelectElement) {
      const recoverButton = generateForm.querySelector("[data-ldap-recover-missing]");
      const actionInput = generateForm.querySelector("[data-ldap-generate-action]");
      const updateGenerateAction = () => {
        generateForm.action = `/ldap/organizations/${encodeURIComponent(generateOrganization.value)}/generate-directory`;
      };
      generateOrganization.addEventListener("change", updateGenerateAction);
      updateGenerateAction();
      if (window.AtlasoUiPatterns) {
        generateWizard = window.AtlasoUiPatterns.createWizard({
          form: generateForm,
          dialog: generateDialog,
          steps: [
            { id: "organization", title: "Choose the LDAP organization", description: "Select the isolated suffix that receives synthetic directory entries." },
            { id: "size", title: "Size the test directory", description: "Choose how many complete users and groups Atlaso should generate." },
            { id: "review", title: "Review directory generation", description: "Confirm the counts and one-time credential boundary." },
          ],
          discardTitle: "Discard directory generation?",
          discardMessage: "The selected organization and directory sizes will be reset.",
          prepareReview: () => renderAtlasoWizardReview(generateForm, [
            { label: "LDAP organization", value: () => generateOrganization.selectedOptions[0]?.textContent?.trim() || "" },
            { label: "Users", field: "user_count" },
            { label: "Groups", field: "group_count" },
            { label: "Passwords", value: () => "Shown once after generation" },
          ]),
          onStepChange: ({ step }) => {
            recoverButton?.classList.toggle("hidden", step.id !== "review");
          },
        });
      }
      recoverButton?.addEventListener("click", () => {
        if (actionInput instanceof HTMLInputElement) actionInput.value = "stage_missing";
        generateForm.requestSubmit();
      });
    }
    if (generateDialog.hasAttribute("data-ldap-generate-auto-open") && !generateDialog.open) {
      window.history.replaceState(window.history.state, "", "/vcf-helper");
      if (generateWizard) generateWizard.open({ reset: false, step: "review", highestStep: "review" });
      else openGenerateDialog();
      focusGenerateDialog();
    }
  }
  if (dialog.hasAttribute("data-vcf-ldap-auto-open") && !dialog.open) {
    if (ldapWizard) {
      const hasResult = Boolean(dialog.querySelector("[data-vcf-ldap-review] + .alert, section[data-atlaso-wizard-step='review'] .config-preview"));
      ldapWizard.open({ reset: false, step: hasResult ? "review" : "organization", highestStep: hasResult ? "review" : "organization" });
    } else dialog.showModal();
  }
}

function initializeLdapBindSecretModal() {
  const dialog = document.getElementById("ldap-bind-secret-modal");
  if (!(dialog instanceof HTMLDialogElement)) return;
  dialog.querySelector("[data-ldap-bind-secret-close]")?.addEventListener("click", () => dialog.close());
  if (dialog.hasAttribute("data-ldap-bind-secret-auto-open") && !dialog.open) {
    dialog.showModal();
  }
}

function initializeAutomationTables() {
  if (typeof Tabulator === "undefined") return;

  const parseTableData = (elementId) => {
    const element = document.getElementById(elementId);
    if (!(element instanceof HTMLScriptElement)) return [];
    try {
      const value = JSON.parse(element.textContent || "[]");
      return Array.isArray(value) ? value : [];
    } catch (_error) {
      return [];
    }
  };
  const submitForm = (prefix, id) => {
    const form = document.getElementById(`${prefix}-${id}`);
    if (form instanceof HTMLFormElement) form.requestSubmit();
  };
  const scheduleModal = document.getElementById("automation-schedule-modal");
  const scheduleForm = document.querySelector("[data-automation-schedule-form]");
  const scriptCreateDialog = document.getElementById("automation-script-create-dialog");
  const scriptCreateForm = document.querySelector("[data-automation-script-create-form]");
  const scriptModal = document.getElementById("automation-script-modal");
  const scriptRunModal = document.getElementById("automation-script-run-modal");
  const scriptRunForm = document.querySelector("[data-automation-script-run-form]");
  const scriptDiffModal = document.getElementById("automation-script-diff-modal");
  let activeScriptRow = null;
  let activeScriptInterpreter = "bash";
  let scriptCreateWizard = null;
  let openScriptCreateWizard = null;
  const openAutomationModal = (modal) => {
    if (!(modal instanceof HTMLDialogElement)) return;
    modal.showModal();
    window.requestAnimationFrame(() => modal.querySelector("input:not([type='hidden']), select, textarea")?.focus({ preventScroll: true }));
  };
  scriptModal?.querySelector("[data-automation-script-modal-cancel]")?.addEventListener("click", () => scriptModal.close());
  if (scriptModal instanceof HTMLDialogElement) {
    const scriptFileInput = scriptModal.querySelector("[data-automation-script-file]");
    const scriptTextarea = scriptModal.querySelector("#automation-script-content");
    const scriptImportStatus = scriptModal.querySelector("[data-automation-script-import-status]");
    const scriptLanguage = scriptModal.querySelector("[data-automation-script-language]");
    const scriptModalTitle = scriptModal.querySelector("#automation-script-modal-title");
    const scriptModalDescription = scriptModal.querySelector("[data-automation-script-source-description]");
    const scriptConfirm = scriptModal.querySelector("[data-automation-script-source-confirm]");
    const setScriptEditorValue = (value) => {
      if (!(scriptTextarea instanceof HTMLTextAreaElement)) return;
      if (window.AtlasoMonaco && typeof window.AtlasoMonaco.setValue === "function") {
        window.AtlasoMonaco.setValue(scriptTextarea, value);
      } else {
        scriptTextarea.value = value;
        scriptTextarea.dispatchEvent(new Event("input", { bubbles: true }));
      }
    };
    const scriptEditorValue = () => {
      if (!(scriptTextarea instanceof HTMLTextAreaElement)) return "";
      return window.AtlasoMonaco?.getValue(scriptTextarea) ?? scriptTextarea.value;
    };
    const updateScriptLanguage = (interpreter) => {
      activeScriptInterpreter = ["bash", "powershell", "python"].includes(interpreter) ? interpreter : "bash";
      if (scriptLanguage instanceof HTMLElement) scriptLanguage.textContent = activeScriptInterpreter;
      if (scriptTextarea instanceof HTMLTextAreaElement) {
        scriptTextarea.dataset.scriptInterpreter = activeScriptInterpreter;
        scriptTextarea.setAttribute("aria-label", `${activeScriptInterpreter} managed script source code`);
      }
    };
    const openScriptSourceEditor = (row) => {
      if (!row || !(scriptTextarea instanceof HTMLTextAreaElement)) return;
      const data = row.getData();
      activeScriptRow = row;
      updateScriptLanguage(data.interpreter || "bash");
      setScriptEditorValue(data.source_content || "");
      if (scriptFileInput instanceof HTMLInputElement) scriptFileInput.value = "";
      if (scriptModalTitle instanceof HTMLElement) scriptModalTitle.textContent = `New ${data.name} revision`;
      if (scriptModalDescription instanceof HTMLElement) {
        scriptModalDescription.textContent = `Edit or import source for a new immutable revision. Revision ${data.latest_revision} remains unchanged.`;
      }
      if (scriptConfirm instanceof HTMLButtonElement) scriptConfirm.textContent = "Create new disabled revision";
      if (scriptImportStatus instanceof HTMLElement) {
        scriptImportStatus.textContent = "Paste code or import a .sh, .bash, .py, .ps1, or .txt file (maximum 1 MiB).";
        scriptImportStatus.classList.remove("error-text");
      }
      scriptModal.showModal();
      window.requestAnimationFrame(() => {
        if (window.AtlasoMonaco && typeof window.AtlasoMonaco.focus === "function") window.AtlasoMonaco.focus(scriptTextarea);
        else scriptTextarea.focus({ preventScroll: true });
      });
    };
    scriptModal.atlasoOpenSourceEditor = openScriptSourceEditor;
    if (scriptFileInput instanceof HTMLInputElement && scriptTextarea instanceof HTMLTextAreaElement) {
      scriptFileInput.addEventListener("change", async () => {
        const file = scriptFileInput.files?.[0];
        if (!file) return;
        if (file.size > 1024 * 1024) {
          scriptFileInput.value = "";
          if (scriptImportStatus instanceof HTMLElement) {
            scriptImportStatus.textContent = "Choose a script file no larger than 1 MiB.";
            scriptImportStatus.classList.add("error-text");
          }
          return;
        }
        const extension = file.name.toLowerCase().split(".").pop() || "";
        const interpreterByExtension = { sh: "bash", bash: "bash", py: "python", ps1: "powershell" };
        const inferredInterpreter = interpreterByExtension[extension];
        if (inferredInterpreter) updateScriptLanguage(inferredInterpreter);
        const fileText = await file.text();
        setScriptEditorValue(fileText);
        if (window.AtlasoMonaco && typeof window.AtlasoMonaco.focus === "function") window.AtlasoMonaco.focus(scriptTextarea);
        else scriptTextarea.focus();
        if (scriptImportStatus instanceof HTMLElement) {
          const interpreterNote = inferredInterpreter ? `; interpreter set to ${inferredInterpreter}` : "";
          scriptImportStatus.textContent = `${file.name} loaded into the editor${interpreterNote}. Review it before creating the revision.`;
          scriptImportStatus.classList.remove("error-text");
        }
      });
    }
    if (scriptConfirm instanceof HTMLButtonElement) {
      scriptConfirm.addEventListener("click", () => {
        if (!activeScriptRow) return;
        const content = scriptEditorValue();
        if (!content.trim()) {
          if (scriptImportStatus instanceof HTMLElement) {
            scriptImportStatus.textContent = "Script content is required.";
            scriptImportStatus.classList.add("error-text");
          }
          return;
        }
        const data = activeScriptRow.getData();
        const revisionForm = document.getElementById(`automation-script-revision-${data.id}`);
        if (!(revisionForm instanceof HTMLFormElement)) return;
        revisionForm.elements.interpreter.value = activeScriptInterpreter;
        revisionForm.elements.timeout_seconds.value = String(data.timeout_seconds || 3600);
        revisionForm.elements.content.value = content;
        scriptConfirm.disabled = true;
        scriptConfirm.textContent = "Creating revision…";
        revisionForm.requestSubmit();
      });
    }
  }

  if (scriptCreateDialog instanceof HTMLDialogElement && scriptCreateForm instanceof HTMLFormElement) {
    const scriptCreateFile = scriptCreateForm.querySelector("[data-automation-script-create-file]");
    const scriptCreateContent = scriptCreateForm.querySelector("#automation-script-create-content");
    const scriptCreateInterpreter = scriptCreateForm.querySelector("[data-automation-script-create-interpreter]");
    const scriptCreateLanguage = scriptCreateForm.querySelector("[data-automation-script-create-language]");
    const scriptCreateImportStatus = scriptCreateForm.querySelector("[data-automation-script-create-import-status]");
    const scriptCreateFullscreenButton = scriptCreateForm.querySelector("[data-automation-script-create-fullscreen]");
    const scriptCreateFullscreenDialog = document.getElementById("automation-script-create-fullscreen-dialog");
    const scriptCreateFullscreenContent = document.getElementById("automation-script-create-fullscreen-content");
    const scriptCreateFullscreenLanguage = document.querySelector("[data-automation-script-fullscreen-language]");
    const scriptCreateFullscreenClose = document.querySelector("[data-automation-script-fullscreen-close]");
    const normalizedScriptInterpreter = (value) => (
      ["bash", "powershell", "python"].includes(value) ? value : "bash"
    );
    const setScriptCreateEditorValue = (value) => {
      if (!(scriptCreateContent instanceof HTMLTextAreaElement)) return;
      if (window.AtlasoMonaco && typeof window.AtlasoMonaco.setValue === "function") {
        window.AtlasoMonaco.setValue(scriptCreateContent, value);
      } else {
        scriptCreateContent.value = value;
        scriptCreateContent.dispatchEvent(new Event("input", { bubbles: true }));
      }
    };
    const scriptCreateEditorValue = () => {
      if (!(scriptCreateContent instanceof HTMLTextAreaElement)) return "";
      return window.AtlasoMonaco?.getValue(scriptCreateContent) ?? scriptCreateContent.value;
    };
    const updateScriptCreateLanguage = (value) => {
      const interpreter = normalizedScriptInterpreter(value);
      const editorLanguage = { bash: "shell", powershell: "powershell", python: "python" }[interpreter];
      if (scriptCreateInterpreter instanceof HTMLSelectElement) scriptCreateInterpreter.value = interpreter;
      if (scriptCreateLanguage instanceof HTMLElement) scriptCreateLanguage.textContent = interpreter;
      if (scriptCreateFullscreenLanguage instanceof HTMLElement) scriptCreateFullscreenLanguage.textContent = interpreter;
      if (scriptCreateContent instanceof HTMLTextAreaElement) {
        scriptCreateContent.dataset.scriptInterpreter = interpreter;
        scriptCreateContent.dataset.monacoLanguage = editorLanguage;
        scriptCreateContent.setAttribute("aria-label", `${interpreter} managed script source code`);
        if (typeof window.AtlasoMonaco?.setLanguage === "function") {
          window.AtlasoMonaco.setLanguage(scriptCreateContent, editorLanguage);
        }
      }
      if (scriptCreateFullscreenContent instanceof HTMLTextAreaElement) {
        scriptCreateFullscreenContent.dataset.scriptInterpreter = interpreter;
        scriptCreateFullscreenContent.dataset.monacoLanguage = editorLanguage;
        scriptCreateFullscreenContent.setAttribute("aria-label", `Full-screen ${interpreter} managed script source code`);
        if (typeof window.AtlasoMonaco?.setLanguage === "function") {
          window.AtlasoMonaco.setLanguage(scriptCreateFullscreenContent, editorLanguage);
        }
      }
    };
    const resetScriptCreateImportStatus = () => {
      if (!(scriptCreateImportStatus instanceof HTMLElement)) return;
      scriptCreateImportStatus.textContent = "Paste code or import a .sh, .bash, .py, .ps1, or .txt file (maximum 1 MiB).";
      scriptCreateImportStatus.classList.remove("error-text");
    };
    if (scriptCreateFile instanceof HTMLInputElement && scriptCreateContent instanceof HTMLTextAreaElement) {
      scriptCreateFile.addEventListener("change", async () => {
        const file = scriptCreateFile.files?.[0];
        if (!file) return;
        if (file.size > 1024 * 1024) {
          scriptCreateFile.value = "";
          if (scriptCreateImportStatus instanceof HTMLElement) {
            scriptCreateImportStatus.textContent = "Choose a script file no larger than 1 MiB.";
            scriptCreateImportStatus.classList.add("error-text");
          }
          return;
        }
        const extension = file.name.toLowerCase().split(".").pop() || "";
        const interpreterByExtension = { sh: "bash", bash: "bash", py: "python", ps1: "powershell" };
        const inferredInterpreter = interpreterByExtension[extension];
        if (inferredInterpreter) updateScriptCreateLanguage(inferredInterpreter);
        setScriptCreateEditorValue(await file.text());
        if (scriptCreateImportStatus instanceof HTMLElement) {
          const interpreterNote = inferredInterpreter ? `; interpreter set to ${inferredInterpreter}` : "";
          scriptCreateImportStatus.textContent = `${file.name} loaded into the editor${interpreterNote}. Review it before creating the revision.`;
          scriptCreateImportStatus.classList.remove("error-text");
        }
      });
    }
    if (
      scriptCreateFullscreenButton instanceof HTMLButtonElement
      && scriptCreateFullscreenDialog instanceof HTMLDialogElement
      && scriptCreateFullscreenContent instanceof HTMLTextAreaElement
    ) {
      let fullscreenCommitted = true;
      const fullScreenEditorValue = () => (
        window.AtlasoMonaco?.getValue(scriptCreateFullscreenContent)
        ?? scriptCreateFullscreenContent.value
      );
      const commitFullscreenValue = () => {
        if (fullscreenCommitted) return;
        setScriptCreateEditorValue(fullScreenEditorValue());
        fullscreenCommitted = true;
      };
      scriptCreateFullscreenButton.addEventListener("click", () => {
        setScriptCreateEditorValue(scriptCreateEditorValue());
        if (window.AtlasoMonaco && typeof window.AtlasoMonaco.setValue === "function") {
          window.AtlasoMonaco.setValue(scriptCreateFullscreenContent, scriptCreateEditorValue());
        } else {
          scriptCreateFullscreenContent.value = scriptCreateEditorValue();
        }
        updateScriptCreateLanguage(scriptCreateInterpreter?.value || "bash");
        fullscreenCommitted = false;
        scriptCreateFullscreenDialog.showModal();
        window.requestAnimationFrame(() => {
          if (typeof window.AtlasoMonaco?.focus === "function") {
            window.AtlasoMonaco.focus(scriptCreateFullscreenContent);
          } else {
            scriptCreateFullscreenContent.focus();
          }
        });
      });
      scriptCreateFullscreenClose?.addEventListener("click", () => {
        commitFullscreenValue();
        scriptCreateFullscreenDialog.close();
        window.requestAnimationFrame(() => {
          if (typeof window.AtlasoMonaco?.focus === "function") {
            window.AtlasoMonaco.focus(scriptCreateContent);
          }
        });
      });
      scriptCreateFullscreenDialog.addEventListener("close", commitFullscreenValue);
    }
    scriptCreateInterpreter?.addEventListener("change", () => updateScriptCreateLanguage(scriptCreateInterpreter.value));
    scriptCreateWizard = window.AtlasoUiPatterns.createWizard({
      form: scriptCreateForm,
      dialog: scriptCreateDialog,
      steps: [
        { id: "identity", title: "Name the managed script", description: "Give the script an operator-visible identity and purpose." },
        { id: "runtime", title: "Choose the runtime", description: "Select its allowlisted interpreter and bounded timeout." },
        { id: "source", title: "Add the first revision", description: "Enter or import the immutable source stored as revision 1." },
        { id: "review", title: "Review managed-script creation", description: "Confirm the disabled revision before saving it." },
      ],
      discardTitle: "Discard managed script?",
      discardMessage: "The script identity, runtime, and source entered in this wizard will be lost.",
      onOpen: () => {
        updateScriptCreateLanguage("bash");
        scriptCreateForm.elements.timeout_seconds.value = "3600";
        setScriptCreateEditorValue("");
        if (scriptCreateFile instanceof HTMLInputElement) scriptCreateFile.value = "";
        resetScriptCreateImportStatus();
      },
      validateStep: ({ step }) => {
        if (step.id !== "source") return { valid: true };
        const content = scriptCreateEditorValue();
        if (!content.trim()) {
          return { valid: false, field: "content", message: "Script content is required." };
        }
        if (scriptCreateContent instanceof HTMLTextAreaElement) scriptCreateContent.value = content;
        return { valid: true };
      },
      prepareReview: () => {
        const content = scriptCreateEditorValue();
        if (scriptCreateContent instanceof HTMLTextAreaElement) scriptCreateContent.value = content;
        const lines = content ? content.split(/\r?\n/).length : 0;
        renderAtlasoWizardReview(scriptCreateForm, [
          { label: "Script", field: "name" },
          { label: "Description", field: "description" },
          { label: "Interpreter", field: "interpreter" },
          { label: "Timeout", value: () => `${scriptCreateForm.elements.timeout_seconds.value} seconds` },
          { label: "Initial source", value: () => `${lines} ${lines === 1 ? "line" : "lines"}` },
          { label: "Revision state", value: () => "Disabled" },
        ]);
      },
      onSubmit: async () => {
        if (scriptCreateContent instanceof HTMLTextAreaElement) {
          scriptCreateContent.value = scriptCreateEditorValue();
        }
        const response = await fetch(scriptCreateForm.action, {
          method: "POST",
          body: new FormData(scriptCreateForm),
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            "X-Atlaso-Wizard": "1",
          },
        });
        const responseText = await response.text();
        let payload = {};
        try {
          payload = responseText ? JSON.parse(responseText) : {};
        } catch (_error) {
          payload = {};
        }
        if (!response.ok) throw new Error(payload.detail || "The managed script could not be created.");
        try {
          window.localStorage.setItem("atlaso:automation:workspace-tab", "scripts");
        } catch {
          // The hash still restores the Managed Scripts workspace when storage is unavailable.
        }
        window.location.assign("/automation#scripts");
        return { valid: true };
      },
    });
    openScriptCreateWizard = (launcher) => scriptCreateWizard.open({ launcher });
  }

  const updateScriptRunGuidance = (interpreter) => {
    if (!(scriptRunModal instanceof HTMLDialogElement)) return;
    const argumentsInput = scriptRunModal.querySelector("[data-automation-script-run-arguments]");
    const hint = scriptRunModal.querySelector("[data-automation-script-run-hint]");
    const normalized = ["bash", "powershell", "python"].includes(interpreter) ? interpreter : "bash";
    const marker = normalized === "powershell" ? "`" : "\\";
    const label = normalized === "powershell" ? "PowerShell" : normalized === "python" ? "Python" : "Bash";
    if (argumentsInput instanceof HTMLTextAreaElement) {
      argumentsInput.placeholder = normalized === "powershell"
        ? "-Server `\n'vcf.example.internal' `\n-Port 443"
        : "--server \\\n'vcf.example.internal' \\\n--port 443";
    }
    if (hint instanceof HTMLElement) hint.textContent = `${label}: enter one logical command line; end a visual continuation line with ${marker}. Arguments are passed literally without shell evaluation.`;
  };
  const openScriptRunModal = (data) => {
    if (!(scriptRunModal instanceof HTMLDialogElement) || !(scriptRunForm instanceof HTMLFormElement) || !data?.latest_revision_id) return;
    scriptRunForm.reset();
    scriptRunForm.action = `/automation/scripts/revisions/${encodeURIComponent(data.latest_revision_id)}/run`;
    const name = scriptRunModal.querySelector("[data-automation-script-run-name]");
    const revision = scriptRunModal.querySelector("[data-automation-script-run-revision]");
    const interpreter = scriptRunModal.querySelector("[data-automation-script-run-interpreter]");
    if (name instanceof HTMLElement) name.textContent = data.name || "—";
    if (revision instanceof HTMLElement) revision.textContent = `r${data.latest_revision || 0}`;
    if (interpreter instanceof HTMLElement) interpreter.textContent = data.interpreter || "—";
    updateScriptRunGuidance(data.interpreter || "bash");
    scriptRunModal.showModal();
    window.requestAnimationFrame(() => scriptRunModal.querySelector("[data-automation-script-run-arguments]")?.focus({ preventScroll: true }));
  };
  scriptRunModal?.querySelector("[data-automation-script-run-cancel]")?.addEventListener("click", () => scriptRunModal.close());

  const scriptDiffLanguage = (interpreter) => {
    if (interpreter === "powershell") return "atlaso-powershell";
    if (interpreter === "python") return "atlaso-python";
    return "atlaso-bash";
  };
  const highlightScriptDiffLine = (line, interpreter) => {
    registerAtlasoPrismLanguages();
    const language = scriptDiffLanguage(interpreter);
    const grammar = window.Prism?.languages?.[language];
    return grammar && typeof window.Prism.highlight === "function"
      ? window.Prism.highlight(String(line || ""), grammar, language)
      : escapeHtml(String(line || ""));
  };
  const sideBySideRevisionDiff = (previousContent, currentContent) => {
    const previousLines = String(previousContent || "").replaceAll("\r\n", "\n").split("\n");
    const currentLines = String(currentContent || "").replaceAll("\r\n", "\n").split("\n");
    const operations = [];
    if (previousLines.length * currentLines.length <= 250000) {
      const matrix = Array.from({ length: previousLines.length + 1 }, () => new Uint32Array(currentLines.length + 1));
      for (let left = previousLines.length - 1; left >= 0; left -= 1) {
        for (let right = currentLines.length - 1; right >= 0; right -= 1) {
          matrix[left][right] = previousLines[left] === currentLines[right]
            ? matrix[left + 1][right + 1] + 1
            : Math.max(matrix[left + 1][right], matrix[left][right + 1]);
        }
      }
      let left = 0;
      let right = 0;
      while (left < previousLines.length || right < currentLines.length) {
        if (left < previousLines.length && right < currentLines.length && previousLines[left] === currentLines[right]) {
          operations.push({ type: "same", line: previousLines[left] });
          left += 1;
          right += 1;
        } else if (right < currentLines.length && (left >= previousLines.length || matrix[left][right + 1] >= matrix[left + 1][right])) {
          operations.push({ type: "added", line: currentLines[right] });
          right += 1;
        } else {
          operations.push({ type: "removed", line: previousLines[left] });
          left += 1;
        }
      }
    } else {
      const lineCount = Math.max(previousLines.length, currentLines.length);
      for (let index = 0; index < lineCount; index += 1) {
        const previousLine = previousLines[index];
        const currentLine = currentLines[index];
        if (previousLine === currentLine) operations.push({ type: "same", line: previousLine || "" });
        else {
          if (previousLine !== undefined) operations.push({ type: "removed", line: previousLine });
          if (currentLine !== undefined) operations.push({ type: "added", line: currentLine });
        }
      }
    }
    const rows = [];
    let previousNumber = 1;
    let currentNumber = 1;
    let operationIndex = 0;
    while (operationIndex < operations.length) {
      const operation = operations[operationIndex];
      if (operation.type === "same") {
        rows.push({
          kind: "same",
          previous: { number: previousNumber, line: operation.line },
          current: { number: currentNumber, line: operation.line },
        });
        previousNumber += 1;
        currentNumber += 1;
        operationIndex += 1;
        continue;
      }
      const removed = [];
      const added = [];
      while (operationIndex < operations.length && operations[operationIndex].type !== "same") {
        const changedOperation = operations[operationIndex];
        if (changedOperation.type === "removed") removed.push(changedOperation.line);
        if (changedOperation.type === "added") added.push(changedOperation.line);
        operationIndex += 1;
      }
      const changedRowCount = Math.max(removed.length, added.length);
      for (let changedIndex = 0; changedIndex < changedRowCount; changedIndex += 1) {
        const previousLine = removed[changedIndex];
        const currentLine = added[changedIndex];
        rows.push({
          kind: "changed",
          previous: previousLine === undefined ? null : { number: previousNumber, line: previousLine },
          current: currentLine === undefined ? null : { number: currentNumber, line: currentLine },
        });
        if (previousLine !== undefined) previousNumber += 1;
        if (currentLine !== undefined) currentNumber += 1;
      }
    }
    const compactRows = [];
    let rowIndex = 0;
    while (rowIndex < rows.length) {
      if (rows[rowIndex].kind !== "same") {
        compactRows.push(rows[rowIndex]);
        rowIndex += 1;
        continue;
      }
      let sameRunEnd = rowIndex;
      while (sameRunEnd < rows.length && rows[sameRunEnd].kind === "same") sameRunEnd += 1;
      const sameRunLength = sameRunEnd - rowIndex;
      if (sameRunLength > 12) {
        compactRows.push(...rows.slice(rowIndex, rowIndex + 3));
        compactRows.push({ kind: "collapsed", count: sameRunLength - 6 });
        compactRows.push(...rows.slice(sameRunEnd - 3, sameRunEnd));
      } else {
        compactRows.push(...rows.slice(rowIndex, sameRunEnd));
      }
      rowIndex = sameRunEnd;
    }
    return {
      rows: compactRows,
      addedCount: operations.filter((operation) => operation.type === "added").length,
      removedCount: operations.filter((operation) => operation.type === "removed").length,
    };
  };
  const appendRevisionDiffCell = (rowElement, side, entry, state, interpreter) => {
    const lineNumber = document.createElement("span");
    lineNumber.className = `automation-diff-line-number ${side}`;
    lineNumber.textContent = entry ? String(entry.number) : "";
    lineNumber.setAttribute("role", "cell");
    const code = document.createElement("code");
    code.className = `automation-diff-code ${state} language-${scriptDiffLanguage(interpreter)}`;
    code.setAttribute("role", "cell");
    if (entry) code.innerHTML = highlightScriptDiffLine(entry.line, interpreter);
    rowElement.append(lineNumber, code);
  };
  let activeScriptDiffData = null;
  const revisionCreatedLabel = (revision) => {
    const parsed = new Date(revision?.created_at || "");
    if (Number.isNaN(parsed.getTime())) return "date unavailable";
    return `${parsed.toLocaleString([], { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" })} UTC`;
  };
  const revisionOptionLabel = (revision) => `r${revision.revision} · ${revisionCreatedLabel(revision)} · ${revision.enabled ? "enabled" : "disabled"}`;
  const renderScriptRevisionDiff = () => {
    if (!(scriptDiffModal instanceof HTMLDialogElement) || !activeScriptDiffData) return;
    const revisions = Array.isArray(activeScriptDiffData.revisions) ? activeScriptDiffData.revisions : [];
    const previousSelect = scriptDiffModal.querySelector("[data-automation-script-diff-previous]");
    const currentSelect = scriptDiffModal.querySelector("[data-automation-script-diff-current]");
    if (!(previousSelect instanceof HTMLSelectElement) || !(currentSelect instanceof HTMLSelectElement)) return;
    const previous = revisions.find((revision) => String(revision.id) === previousSelect.value);
    const current = revisions.find((revision) => String(revision.id) === currentSelect.value);
    if (!previous || !current) return;
    const comparison = sideBySideRevisionDiff(previous.content, current.content);
    const description = scriptDiffModal.querySelector("[data-automation-script-diff-description]");
    const scriptName = scriptDiffModal.querySelector("[data-automation-script-diff-name]");
    const addedCount = scriptDiffModal.querySelector("[data-automation-script-diff-added]");
    const removedCount = scriptDiffModal.querySelector("[data-automation-script-diff-removed]");
    const previousTitle = scriptDiffModal.querySelector("[data-automation-script-diff-previous-title]");
    const currentTitle = scriptDiffModal.querySelector("[data-automation-script-diff-current-title]");
    const previousMeta = scriptDiffModal.querySelector("[data-automation-script-diff-previous-meta]");
    const currentMeta = scriptDiffModal.querySelector("[data-automation-script-diff-current-meta]");
    const diffTable = scriptDiffModal.querySelector("[data-automation-script-diff-table]");
    const extension = current.interpreter === "powershell" ? "ps1" : current.interpreter === "python" ? "py" : "sh";
    if (description instanceof HTMLElement) description.textContent = `Immutable source comparison from r${previous.revision} (${revisionCreatedLabel(previous)}) to r${current.revision} (${revisionCreatedLabel(current)}). Unchanged runs are collapsed.`;
    if (scriptName instanceof HTMLElement) scriptName.textContent = `${activeScriptDiffData.name}.${extension}`;
    if (addedCount instanceof HTMLElement) addedCount.textContent = `+${comparison.addedCount}`;
    if (removedCount instanceof HTMLElement) removedCount.textContent = `-${comparison.removedCount}`;
    if (previousTitle instanceof HTMLElement) previousTitle.textContent = `r${previous.revision} · previous`;
    if (currentTitle instanceof HTMLElement) currentTitle.textContent = `r${current.revision} · current`;
    if (previousMeta instanceof HTMLElement) previousMeta.textContent = `${revisionCreatedLabel(previous)} · ${previous.interpreter} · ${previous.enabled ? "enabled" : "disabled"}`;
    if (currentMeta instanceof HTMLElement) currentMeta.textContent = `${revisionCreatedLabel(current)} · ${current.interpreter} · ${current.enabled ? "enabled" : "disabled"}`;
    if (diffTable instanceof HTMLElement) {
      diffTable.replaceChildren();
      comparison.rows.forEach((row) => {
        if (row.kind === "collapsed") {
          const collapsed = document.createElement("div");
          collapsed.className = "automation-revision-diff-collapse";
          collapsed.setAttribute("role", "row");
          collapsed.textContent = `${row.count} unchanged lines`;
          diffTable.append(collapsed);
          return;
        }
        const rowElement = document.createElement("div");
        rowElement.className = `automation-revision-diff-row ${row.kind}`;
        rowElement.setAttribute("role", "row");
        appendRevisionDiffCell(rowElement, "previous", row.previous, row.kind === "changed" && row.previous ? "removed" : row.previous ? "same" : "empty", previous.interpreter);
        appendRevisionDiffCell(rowElement, "current", row.current, row.kind === "changed" && row.current ? "added" : row.current ? "same" : "empty", current.interpreter);
        diffTable.append(rowElement);
      });
    }
  };
  const openScriptRevisionDiff = (data) => {
    if (!(scriptDiffModal instanceof HTMLDialogElement)) return;
    const revisions = Array.isArray(data?.revisions) ? data.revisions : [];
    if (revisions.length < 2) return;
    const previousSelect = scriptDiffModal.querySelector("[data-automation-script-diff-previous]");
    const currentSelect = scriptDiffModal.querySelector("[data-automation-script-diff-current]");
    if (!(previousSelect instanceof HTMLSelectElement) || !(currentSelect instanceof HTMLSelectElement)) return;
    activeScriptDiffData = data;
    const options = revisions.map((revision) => {
      const option = document.createElement("option");
      option.value = String(revision.id);
      option.textContent = revisionOptionLabel(revision);
      return option;
    });
    previousSelect.replaceChildren(...options.map((option) => option.cloneNode(true)));
    currentSelect.replaceChildren(...options);
    previousSelect.value = String(revisions[revisions.length - 2].id);
    currentSelect.value = String(revisions[revisions.length - 1].id);
    renderScriptRevisionDiff();
    scriptDiffModal.showModal();
  };
  scriptDiffModal?.querySelector("[data-automation-script-diff-previous]")?.addEventListener("change", renderScriptRevisionDiff);
  scriptDiffModal?.querySelector("[data-automation-script-diff-current]")?.addEventListener("change", renderScriptRevisionDiff);
  scriptDiffModal?.querySelector("[data-automation-script-diff-close]")?.addEventListener("click", () => scriptDiffModal.close());

  const schedulesElement = document.getElementById("automation-schedules-table");
  if (schedulesElement instanceof HTMLElement && scheduleModal instanceof HTMLDialogElement && scheduleForm instanceof HTMLFormElement) {
    const scheduleRows = parseTableData("automation-schedules-data");
    scheduleRows.push({ is_new: true, name: "" });
    const wizardSteps = [
      { id: "identity", title: "Name the schedule", description: "Set the schedule identity and choose its allowlisted task type." },
      { id: "config", title: "Choose update streams", description: "Select the repository-backed update streams this task should check." },
      { id: "timing", title: "Choose when it runs", description: "Configure recurring or one-time execution in an explicit timezone." },
      { id: "state", title: "Choose the initial state", description: "Enable the schedule now or save it disabled for review before the worker can queue it." },
      { id: "review", title: "Review the schedule", description: "Confirm the workflow, timing, inputs, and initial state." },
    ];
    const wizardSubmit = scheduleForm.querySelector("[data-automation-wizard-submit]");
    const wizardModalTitle = scheduleForm.querySelector("[data-automation-wizard-modal-title]");
    const configStepLabel = scheduleForm.querySelector("[data-automation-config-step-label]");
    const configStepSubtitle = scheduleForm.querySelector("[data-automation-config-step-subtitle]");
    const taskType = scheduleForm.querySelector("[data-automation-task-type]");
    const scriptRevision = scheduleForm.querySelector("[data-automation-script-revision]");
    const scriptArguments = scheduleForm.querySelector("[data-automation-script-arguments]");
    const scriptArgumentsHint = scheduleForm.querySelector("[data-automation-script-arguments-hint]");
    const scheduleKind = scheduleForm.querySelector("[data-automation-schedule-kind]");
    const cronExpression = scheduleForm.querySelector("[data-automation-cron-expression]");
    const cronFrequency = scheduleForm.querySelector("[data-automation-cron-frequency]");
    const cronMinute = scheduleForm.querySelector("[data-automation-cron-minute]");
    const cronTime = scheduleForm.querySelector("[data-automation-cron-time]");
    const cronWeekday = scheduleForm.querySelector("[data-automation-cron-weekday]");
    const cronMonthday = scheduleForm.querySelector("[data-automation-cron-monthday]");
    const cronCustom = scheduleForm.querySelector("[data-automation-cron-custom]");
    const cronSummary = scheduleForm.querySelector("[data-automation-cron-summary]");
    const cronPreview = scheduleForm.querySelector("[data-automation-cron-preview]");
    let scheduleWizard;
    const selectedScriptInterpreter = () => scriptRevision instanceof HTMLSelectElement
      ? String(scriptRevision.selectedOptions[0]?.dataset.interpreter || "bash")
      : "bash";
    const quoteScriptArgument = (value, interpreter) => {
      const argument = String(value);
      if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(argument)) return argument;
      if (interpreter === "powershell") return `'${argument.replaceAll("'", "''")}'`;
      return `'${argument.replaceAll("'", `'"'"'`)}'`;
    };
    const formatScriptArguments = (argumentsList, interpreter) => {
      if (!Array.isArray(argumentsList) || !argumentsList.length) return "";
      const continuation = interpreter === "powershell" ? " `\n" : " \\\n";
      return argumentsList.map((argument) => quoteScriptArgument(argument, interpreter)).join(continuation);
    };
    const updateScriptArgumentsGuidance = () => {
      if (!(scriptArguments instanceof HTMLTextAreaElement)) return;
      const interpreter = selectedScriptInterpreter();
      const marker = interpreter === "powershell" ? "`" : "\\";
      const label = interpreter === "powershell" ? "PowerShell" : interpreter === "python" ? "Python" : "Bash";
      scriptArguments.placeholder = interpreter === "powershell"
        ? "-Server `\n'vcf.example.internal' `\n-Port 443"
        : "--server \\\n'vcf.example.internal' \\\n--port 443";
      if (scriptArgumentsHint instanceof HTMLElement) {
        scriptArgumentsHint.textContent = `${label}: enter one logical command line; end a visual continuation line with ${marker}. Quoted spaces stay in one literal argument.`;
      }
    };
    const updateConfigVisibility = () => {
      const value = taskType instanceof HTMLSelectElement ? taskType.value : "";
      const step = wizardSteps.find((item) => item.id === "config");
      const configCopy = value === "managed_script"
        ? { label: "Managed script", subtitle: "Choose enabled revision", title: "Choose a managed script", description: "Select the enabled immutable script revision this schedule should run." }
        : value === "vcf_depot_download"
          ? { label: "Depot profile", subtitle: "Choose download profile", title: "Choose a depot profile", description: "Select the enabled VCF Offline Depot download profile this schedule should run." }
          : value === "appliance_update_install"
            ? { label: "Update streams", subtitle: "Choose install streams", title: "Choose update streams", description: "Select the repository-backed update streams this task should install." }
            : { label: "Update streams", subtitle: "Choose check streams", title: "Choose update streams", description: "Select the repository-backed update streams this task should check." };
      if (step) {
        step.title = configCopy.title;
        step.description = configCopy.description;
      }
      if (configStepLabel instanceof HTMLElement) configStepLabel.textContent = configCopy.label;
      if (configStepSubtitle instanceof HTMLElement) configStepSubtitle.textContent = configCopy.subtitle;
      scheduleForm.querySelectorAll("[data-automation-config]").forEach((element) => {
        const group = element.getAttribute("data-automation-config");
        const visible = group === "appliance-update"
          ? value.startsWith("appliance_update_")
          : group === "vcf-depot"
            ? value === "vcf_depot_download"
            : value === "managed_script";
        element.classList.toggle("hidden", !visible);
      });
      if (scheduleWizard?.currentStepId === "config") scheduleWizard.showStep("config");
    };
    const cronWeekdayNames = { "0": "Sunday", "1": "Monday", "2": "Tuesday", "3": "Wednesday", "4": "Thursday", "5": "Friday", "6": "Saturday" };
    const cronPartsFromTime = () => {
      const [hour = "2", minute = "0"] = String(cronTime?.value || "02:00").split(":");
      return { hour: String(Number(hour)), minute: String(Number(minute)), label: `${hour.padStart(2, "0")}:${minute.padStart(2, "0")}` };
    };
    const updateCronBuilder = () => {
      if (!(cronExpression instanceof HTMLInputElement) || !(cronFrequency instanceof HTMLSelectElement)) return;
      const frequency = cronFrequency.value;
      scheduleForm.querySelectorAll("[data-automation-cron-control]").forEach((element) => {
        const control = element.getAttribute("data-automation-cron-control");
        const visible = control === frequency || (control === "time" && ["daily", "weekly", "monthly"].includes(frequency));
        element.classList.toggle("hidden", !visible);
        element.querySelectorAll("input, select").forEach((input) => { input.required = visible; });
      });
      const timezoneValue = String(scheduleForm.elements.timezone_name.value || "UTC");
      const time = cronPartsFromTime();
      let expression = "0 2 * * *";
      let summary = `Every day at ${time.label} ${timezoneValue}`;
      if (frequency === "hourly") {
        const minute = String(Number(cronMinute?.value || 0));
        expression = `${minute} * * * *`;
        summary = `Every hour at minute ${minute} · ${timezoneValue}`;
      } else if (frequency === "daily") {
        expression = `${time.minute} ${time.hour} * * *`;
      } else if (frequency === "weekly") {
        const weekday = String(cronWeekday?.value || "1");
        expression = `${time.minute} ${time.hour} * * ${weekday}`;
        summary = `Every ${cronWeekdayNames[weekday]} at ${time.label} ${timezoneValue}`;
      } else if (frequency === "monthly") {
        const monthday = String(Number(cronMonthday?.value || 1));
        expression = `${time.minute} ${time.hour} ${monthday} * *`;
        summary = `Every month on day ${monthday} at ${time.label} ${timezoneValue}`;
      } else {
        expression = String(cronCustom?.value || "").trim();
        summary = `Custom schedule in ${timezoneValue}`;
      }
      cronExpression.value = expression;
      if (cronSummary instanceof HTMLElement) cronSummary.textContent = summary;
      if (cronPreview instanceof HTMLElement) cronPreview.textContent = expression;
    };
    const loadCronBuilder = (rawExpression = "0 2 * * *") => {
      if (!(cronFrequency instanceof HTMLSelectElement)) return;
      const expression = String(rawExpression || "0 2 * * *").trim();
      const fields = expression.split(/\s+/);
      const numeric = (value, minimum, maximum) => /^\d+$/.test(value) && Number(value) >= minimum && Number(value) <= maximum;
      let frequency = "custom";
      if (fields.length === 5 && numeric(fields[0], 0, 59) && fields.slice(1).every((value) => value === "*")) {
        frequency = "hourly";
        if (cronMinute instanceof HTMLInputElement) cronMinute.value = fields[0];
      } else if (fields.length === 5 && numeric(fields[0], 0, 59) && numeric(fields[1], 0, 23) && fields[2] === "*" && fields[3] === "*" && fields[4] === "*") {
        frequency = "daily";
      } else if (fields.length === 5 && numeric(fields[0], 0, 59) && numeric(fields[1], 0, 23) && fields[2] === "*" && fields[3] === "*" && numeric(fields[4], 0, 6)) {
        frequency = "weekly";
        if (cronWeekday instanceof HTMLSelectElement) cronWeekday.value = fields[4];
      } else if (fields.length === 5 && numeric(fields[0], 0, 59) && numeric(fields[1], 0, 23) && numeric(fields[2], 1, 31) && fields[3] === "*" && fields[4] === "*") {
        frequency = "monthly";
        if (cronMonthday instanceof HTMLInputElement) cronMonthday.value = fields[2];
      }
      if (["daily", "weekly", "monthly"].includes(frequency) && cronTime instanceof HTMLInputElement) {
        cronTime.value = `${fields[1].padStart(2, "0")}:${fields[0].padStart(2, "0")}`;
      }
      if (cronCustom instanceof HTMLInputElement) cronCustom.value = expression;
      cronFrequency.value = frequency;
      updateCronBuilder();
    };
    const updateTimingVisibility = () => {
      const value = scheduleKind instanceof HTMLSelectElement ? scheduleKind.value : "cron";
      scheduleForm.querySelectorAll("[data-automation-schedule-timing]").forEach((element) => {
        const visible = element.getAttribute("data-automation-schedule-timing") === value;
        element.classList.toggle("hidden", !visible);
        element.querySelectorAll("[data-automation-timing-required]").forEach((input) => { input.required = visible; });
      });
      if (value === "cron") updateCronBuilder();
    };
    const validateScheduleStep = ({ step }) => {
      const taskValue = taskType instanceof HTMLSelectElement ? taskType.value : "";
      if (step.id === "config") {
        if (taskValue.startsWith("appliance_update_") && !scheduleForm.querySelector('input[name="selected_streams"]:checked')) {
          return { valid: false, message: "Select at least one update stream." };
        }
        const requiredConfig = taskValue === "managed_script" ? "revision_id" : taskValue === "vcf_depot_download" ? "vcf_profile_id" : "";
        if (requiredConfig && !String(scheduleForm.elements[requiredConfig]?.value || "")) {
          return {
            valid: false,
            message: taskValue === "managed_script"
              ? "Choose an enabled managed script revision."
              : "Choose an enabled VCF Offline Depot profile.",
            field: requiredConfig,
          };
        }
      }
      return true;
    };
    const reviewValue = (selector, value) => {
      const target = scheduleForm.querySelector(selector);
      if (target instanceof HTMLElement) target.textContent = value || "not configured";
    };
    const populateScheduleReview = () => {
      const taskValue = taskType instanceof HTMLSelectElement ? taskType.value : "";
      const kindValue = scheduleKind instanceof HTMLSelectElement ? scheduleKind.value : "cron";
      const timezoneValue = String(scheduleForm.elements.timezone_name.value || "UTC");
      const timingValue = kindValue === "once"
        ? `One time · ${scheduleForm.elements.run_once_at.value || "not set"}`
        : `Cron · ${scheduleForm.elements.cron_expression.value || "not set"}`;
      let configValue = "No additional inputs";
      if (taskValue.startsWith("appliance_update_")) {
        configValue = [...scheduleForm.querySelectorAll('input[name="selected_streams"]:checked')].map((input) => input.closest("label")?.innerText.trim() || input.value).join(", ");
      } else if (taskValue === "managed_script") {
        const scriptLabel = scheduleForm.elements.revision_id.selectedOptions[0]?.textContent?.trim() || "not selected";
        const hasArguments = Boolean(String(scheduleForm.elements.script_arguments.value || "").trim());
        configValue = `${scriptLabel} · ${hasArguments ? "parameters configured" : "no parameters"}`;
      } else if (taskValue === "vcf_depot_download") {
        configValue = scheduleForm.elements.vcf_profile_id.selectedOptions[0]?.textContent?.trim() || "not selected";
      }
      reviewValue("[data-automation-review-name]", String(scheduleForm.elements.name.value || ""));
      reviewValue("[data-automation-review-task]", taskValue.replaceAll("_", " "));
      reviewValue("[data-automation-review-timing]", timingValue);
      reviewValue("[data-automation-review-timezone]", timezoneValue);
      reviewValue("[data-automation-review-state]", scheduleForm.elements.enabled.checked ? "Enabled" : "Disabled");
      reviewValue("[data-automation-review-config]", configValue);
    };
    scheduleWizard = window.AtlasoUiPatterns.createWizard({
      form: scheduleForm,
      dialog: scheduleModal,
      steps: wizardSteps,
      validateStep: validateScheduleStep,
      prepareReview: populateScheduleReview,
      onOpen: ({ context: rowData }) => {
      scheduleForm.action = rowData ? `/automation/schedules/${rowData.id}/edit` : "/automation/schedules";
      if (wizardModalTitle instanceof HTMLElement) wizardModalTitle.textContent = rowData ? `Edit ${rowData.name}` : "Add schedule";
      if (wizardSubmit instanceof HTMLButtonElement) wizardSubmit.textContent = rowData ? "Update schedule" : "Create schedule";
      if (rowData) {
        scheduleForm.elements.name.value = rowData.name || "";
        scheduleForm.elements.task_type.value = rowData.task_type || "appliance_update_check";
        scheduleForm.elements.schedule_kind.value = rowData.schedule_kind || "cron";
        scheduleForm.elements.timezone_name.value = rowData.timezone || "UTC";
        scheduleForm.elements.cron_expression.value = rowData.cron_expression || "0 2 * * *";
        scheduleForm.elements.run_once_at.value = rowData.run_once_local || "";
        scheduleForm.elements.enabled.checked = Boolean(rowData.enabled);
        const selectedStreams = new Set(rowData.task_config?.selected_streams || []);
        scheduleForm.querySelectorAll('input[name="selected_streams"]').forEach((input) => { input.checked = selectedStreams.has(input.value); });
        scheduleForm.elements.vcf_profile_id.value = String(rowData.task_config?.profile_id || "");
        scheduleForm.elements.revision_id.value = String(rowData.task_config?.revision_id || "");
        scheduleForm.elements.vault_id.value = String(rowData.task_config?.vault_id || "");
        scheduleForm.elements.script_arguments.value = formatScriptArguments(rowData.task_config?.arguments, selectedScriptInterpreter());
      }
      updateScriptArgumentsGuidance();
      loadCronBuilder(rowData?.cron_expression || "0 2 * * *");
      updateConfigVisibility();
      updateTimingVisibility();
      },
    });
    const openScheduleWizard = (rowData = null, launcher = null) => {
      scheduleWizard.open({ context: rowData, launcher });
    };
    taskType?.addEventListener("change", updateConfigVisibility);
    scriptRevision?.addEventListener("change", updateScriptArgumentsGuidance);
    scheduleKind?.addEventListener("change", updateTimingVisibility);
    [cronFrequency, cronMinute, cronTime, cronWeekday, cronMonthday, cronCustom].forEach((control) => {
      control?.addEventListener("input", updateCronBuilder);
      control?.addEventListener("change", updateCronBuilder);
    });
    scheduleForm.elements.timezone_name?.addEventListener("input", updateCronBuilder);
    const atlasoGridOptions31 = {
      data: scheduleRows,
      layout: "fitColumns",
      placeholder: "No automation schedules have been created.",
      rowFormatter: (row) => markNewRecordRow(row, "name"),
      rowContextMenu: [
        {
          label: "Run now",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => submitForm("automation-schedule-run", row.getData().id),
        },
        {
          label: "Edit schedule",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => openScheduleWizard(row.getData(), row.getElement()),
        },
        {
          label: "Delete schedule",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => submitForm("automation-schedule-delete", row.getData().id),
        },
      ],
      columns: [
        {
          title: "Name",
          field: "name",
          minWidth: 150,
          formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button">+ Add schedule here</button>' : escapeHtml(cell.getValue()),
          cellClick: (event, cell) => {
            if (cell.getRow().getData().is_new) openScheduleWizard(null, event?.target);
          },
        },
        { title: "Task", field: "task_type", minWidth: 150, formatter: (cell) => cell.getRow().getData().is_new ? "" : String(cell.getValue() || "").replaceAll("_", " ") },
        { title: "Schedule", field: "schedule", minWidth: 150 },
        { title: "Timezone", field: "timezone", minWidth: 130 },
        { title: "Next run", field: "next_run_at", minWidth: 170 },
        { title: "Last task", field: "last_job_status", width: 110 },
        { title: "State", field: "enabled", width: 85, formatter: atlasoBooleanFormatter, editor: "tickCross", editable: (cell) => !cell.getRow().getData().is_new, hozAlign: "center", headerSort: false, cellEdited: (cell) => submitForm("automation-schedule-toggle", cell.getRow().getData().id) },
      ],
    };
    schedulesElement.atlasoTabulator = window.AtlasoUiPatterns.createGrid({
      element: schedulesElement,
      pattern: "wizard-backed",
      onReady: () => {
        schedulesElement.atlasoTabulatorReady = true;
      },
      options: atlasoGridOptions31,
    }).table;
  }

  const executionsElement = document.getElementById("automation-executions-table");
  if (executionsElement instanceof HTMLElement) {
    const executionRows = parseTableData("automation-executions-data");
    const openExecutionTask = (rowData) => {
      if (rowData?.task_url) window.location.assign(rowData.task_url);
    };
    const atlasoGridOptions32 = {
      data: executionRows,
      layout: "fitColumns",
      height: "100%",
      pagination: true,
      paginationMode: "local",
      paginationSize: 25,
      paginationCounter: "rows",
      placeholder: "No schedule executions have been recorded yet.",
      rowContextMenu: [
        {
          label: "Open associated task",
          action: (_event, row) => openExecutionTask(row.getData()),
        },
      ],
      columns: [
        { title: "Status", field: "status", width: 115, formatter: (cell) => taskStatusPillHtml(cell.getRow().getData()) },
        { title: "Schedule", field: "schedule_name", minWidth: 165, widthGrow: 2, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        { title: "Workflow", field: "task_label", minWidth: 165, widthGrow: 2, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        { title: "Trigger", field: "trigger_label", width: 110, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        { title: "Planned", field: "planned_for", minWidth: 180, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        { title: "Started", field: "started_at", minWidth: 180, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        { title: "Finished", field: "finished_at", minWidth: 180, formatter: (cell) => escapeHtml(cell.getValue() || "—") },
        {
          title: "Associated task",
          field: "id",
          minWidth: 250,
          formatter: (cell) => {
            const data = cell.getRow().getData();
            return `<a href="${escapeHtml(data.task_url || "/tasks")}"><code>${escapeHtml(data.id || "")}</code></a>`;
          },
        },
      ],
    };
    executionsElement.atlasoTabulator = window.AtlasoUiPatterns.createGrid({
      element: executionsElement,
      pattern: "read-only",
      onOpenRow: (rowData) => openExecutionTask(rowData),
      onReady: () => {
        executionsElement.atlasoTabulatorReady = true;
      },
      options: atlasoGridOptions32,
    }).table;
    executionsElement.atlasoTabulator?.on("rowDblClick", (_event, row) => openExecutionTask(row.getData()));
  }

  const scriptsElement = document.getElementById("automation-scripts-table");
  if (scriptsElement instanceof HTMLElement) {
    const scriptRows = parseTableData("automation-scripts-data");
    scriptRows.push({ is_new: true, name: "" });
    const showScriptGridStatus = (message, isError = false) => {
      const status = document.getElementById("automation-script-grid-status");
      if (!(status instanceof HTMLElement)) return;
      status.textContent = message;
      status.classList.toggle("hidden", !message);
      status.classList.toggle("error-text", isError);
    };
    const openScriptSource = (row) => {
      if (scriptModal instanceof HTMLDialogElement && typeof scriptModal.atlasoOpenSourceEditor === "function") {
        scriptModal.atlasoOpenSourceEditor(row);
      }
    };
    const saveExistingScriptMetadata = (cell) => {
      const row = cell.getRow();
      const data = row.getData();
      const name = String(data.name || "").trim();
      if (!name) {
        showScriptGridStatus("Script name is required.", true);
        if (typeof cell.restoreOldValue === "function") cell.restoreOldValue();
        return;
      }
      const form = document.getElementById(`automation-script-edit-${data.id}`);
      if (!(form instanceof HTMLFormElement)) return;
      form.elements.name.value = name;
      form.elements.description.value = String(data.description || "").trim();
      showScriptGridStatus("Saving managed-script metadata…");
      form.requestSubmit();
    };
    const createRevisionFromGridCell = (cell) => {
      const row = cell.getRow();
      const data = row.getData();
      const timeout = Number(data.timeout_seconds || 0);
      if (!Number.isInteger(timeout) || timeout < 1 || timeout > 86400) {
        showScriptGridStatus("Timeout must be between 1 and 86400 seconds.", true);
        if (typeof cell.restoreOldValue === "function") cell.restoreOldValue();
        return;
      }
      const form = document.getElementById(`automation-script-revision-${data.id}`);
      if (!(form instanceof HTMLFormElement)) return;
      form.elements.interpreter.value = data.interpreter || "bash";
      form.elements.timeout_seconds.value = String(timeout);
      form.elements.content.value = data.source_content || "";
      showScriptGridStatus("Creating a new disabled immutable revision…");
      form.requestSubmit();
    };
    const atlasoGridOptions33 = {
      data: scriptRows,
      layout: "fitColumns",
      placeholder: "No managed scripts have been created.",
      rowFormatter: (row) => markNewRecordRow(row, "name"),
      rowContextMenu: [
        {
          label: "Create new revision",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => openScriptSource(row),
        },
        {
          label: "Run latest revision",
          disabled: (component) => component.getData().is_new || !component.getData().latest_enabled,
          action: (_event, row) => openScriptRunModal(row.getData()),
        },
        {
          label: "Compare latest revisions",
          disabled: (component) => component.getData().is_new || !Array.isArray(component.getData().revisions) || component.getData().revisions.length < 2,
          action: (_event, row) => openScriptRevisionDiff(row.getData()),
        },
        {
          label: "Enable or disable latest revision",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => submitForm("automation-script-toggle", row.getData().id),
        },
        {
          label: "Delete managed script",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => submitForm("delete-automation-script", row.getData().id),
        },
      ],
      columns: lockNewRecordColumns([
        {
          title: "Name",
          field: "name",
          width: 250,
          minWidth: 230,
          editor: "input",
          editable: (cell) => !cell.getRow().getData().is_new,
          formatter: (cell) => cell.getRow().getData().is_new
            ? '<button class="add-row-button" type="button" data-automation-script-wizard-open>+ Add managed script here</button>'
            : escapeHtml(cell.getValue()),
          cellClick: (event, cell) => {
            if (cell.getRow().getData().is_new && typeof openScriptCreateWizard === "function") {
              openScriptCreateWizard(event?.target);
            }
          },
          cellEdited: (cell) => {
            saveExistingScriptMetadata(cell);
          },
        },
        { title: "Description", field: "description", minWidth: 190, editor: "input", editable: (cell) => !cell.getRow().getData().is_new, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || ""), cellEdited: saveExistingScriptMetadata },
        { title: "Interpreter", field: "interpreter", width: 115, editor: "list", editable: (cell) => !cell.getRow().getData().is_new, editorParams: { values: { bash: "bash", powershell: "powershell", python: "python" } }, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || ""), cellEdited: createRevisionFromGridCell },
        { title: "Timeout", field: "timeout_seconds", width: 95, editor: "number", editable: (cell) => !cell.getRow().getData().is_new, editorParams: { min: 1, max: 86400 }, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || ""), cellEdited: createRevisionFromGridCell },
        {
          title: "Source",
          field: "source_content",
          width: 78,
          headerSort: false,
          editable: false,
          hozAlign: "center",
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.is_new) return "";
            return '<button class="automation-source-button" type="button" aria-label="Open script source" title="Open Monaco source editor">…</button>';
          },
          cellClick: (_event, cell) => {
            const data = cell.getRow().getData();
            if (!data.is_new) openScriptSource(cell.getRow());
          },
        },
        {
          title: "Revision",
          field: "latest_revision",
          width: 85,
          formatter: (cell) => {
            const data = cell.getRow().getData();
            if (data.is_new) return "";
            const revisionLabel = `r${cell.getValue()}`;
            return Array.isArray(data.revisions) && data.revisions.length >= 2
              ? `<button class="automation-revision-button" type="button" aria-label="Compare ${escapeHtml(data.name)} revisions" title="Compare latest revisions">${revisionLabel}</button>`
              : revisionLabel;
          },
          cellClick: (_event, cell) => openScriptRevisionDiff(cell.getRow().getData()),
        },
        { title: "State", field: "latest_enabled", width: 85, formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell), editor: "tickCross", editable: (cell) => !cell.getRow().getData().is_new, hozAlign: "center", headerSort: false, cellEdited: (cell) => submitForm("automation-script-toggle", cell.getRow().getData().id) },
        { title: "Schedules", field: "schedule_count", width: 95, formatter: (cell) => cell.getRow().getData().is_new ? "" : cell.getValue() },
        { title: "Updated", field: "updated_at", minWidth: 165, formatter: (cell) => cell.getRow().getData().is_new ? "" : cell.getValue() },
      ], "name"),
    };
    scriptsElement.atlasoTabulator = window.AtlasoUiPatterns.createGrid({
      element: scriptsElement,
      pattern: "wizard-backed",
      onReady: () => {
        scriptsElement.atlasoTabulatorReady = true;
      },
      options: atlasoGridOptions33,
    }).table;
  }

}

function initializeManagedPackagePolicies() {
  document.querySelectorAll("[data-managed-package-form]").forEach((form) => {
    const policy = form.querySelector("[data-managed-package-policy]");
    const target = form.querySelector("[data-managed-package-target]");
    const targetLabel = form.querySelector("[data-managed-package-target-label]");
    if (!(policy instanceof HTMLSelectElement) || !(target instanceof HTMLInputElement)) return;
    const updateTargetState = () => {
      const usesLatest = policy.value === "latest";
      if (usesLatest) target.value = "";
      target.disabled = usesLatest;
      target.required = !usesLatest;
      target.placeholder = usesLatest ? "Resolved from repository" : "Required for pinned policy";
      target.setAttribute("aria-disabled", usesLatest ? "true" : "false");
      targetLabel?.classList.toggle("muted", usesLatest);
    };
    policy.addEventListener("change", updateTargetState);
    updateTargetState();
  });
}

function initializeApplianceUpdateSourceWizard() {
  const form = document.querySelector("[data-appliance-update-source-form]");
  const dialog = document.getElementById("appliance-update-source-dialog");
  const launchers = [...document.querySelectorAll("[data-update-source-wizard-open]")];
  if (
    !(form instanceof HTMLFormElement)
    || !(dialog instanceof HTMLDialogElement)
    || !launchers.length
    || !window.AtlasoUiPatterns
  ) {
    return;
  }

  const kindControl = form.elements.namedItem("kind");
  const urlControl = form.elements.namedItem("url");
  const managedControl = form.elements.namedItem("managed");
  const kindLabel = form.querySelector("[data-update-source-kind-label]");
  const urlLabel = form.querySelector("[data-update-source-url-label]");
  let selectedKind = "";

  const updateUrlRequirement = () => {
    if (!(urlControl instanceof HTMLInputElement)) return;
    const photonManaged = selectedKind === "photon"
      && managedControl instanceof HTMLInputElement
      && managedControl.checked;
    urlControl.required = selectedKind === "powershell" || photonManaged;
  };

  const selectKind = (kind) => {
    selectedKind = ["atlaso", "photon", "powershell"].includes(kind) ? kind : "";
    if (kindControl instanceof HTMLInputElement) kindControl.value = selectedKind;
    if (kindLabel instanceof HTMLElement) kindLabel.textContent = selectedKind ? selectedKind.toUpperCase() : "Not selected";
    if (urlLabel instanceof HTMLElement) {
      urlLabel.textContent = selectedKind === "atlaso" ? "Signed release base URL" : "Repository URL";
    }
    form.querySelectorAll("[data-update-source-kind-fields]").forEach((group) => {
      const active = group.getAttribute("data-update-source-kind-fields") === selectedKind;
      group.classList.toggle("hidden", !active);
      group.querySelectorAll("input, select, textarea").forEach((control) => {
        control.disabled = !active;
      });
    });
    updateUrlRequirement();
  };

  if (managedControl instanceof HTMLInputElement) {
    managedControl.addEventListener("change", updateUrlRequirement);
  }

  const wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "identity", title: "Name the repository", description: "Confirm its ecosystem, operator-visible name, and resolution priority." },
      { id: "endpoint", title: "Configure the endpoint", description: "Set the repository location and ecosystem-specific trust policy." },
      { id: "state", title: "Choose desired availability", description: "Decide whether the source participates in future update work." },
      { id: "review", title: "Review repository creation", description: "Confirm the desired state before saving it." },
    ],
    discardTitle: "Discard repository setup?",
    discardMessage: "The repository values entered in this wizard will be lost.",
    onOpen: ({ context }) => {
      form.reset();
      selectKind(context?.kind || "");
    },
    validateStep: (state) => validateAtlasoWizardStep(state),
    prepareReview: () => {
      const reviewItems = [
        { label: "Ecosystem", value: () => selectedKind.toUpperCase() },
        { label: "Repository", field: "name" },
        { label: "Priority", field: "priority" },
        { label: selectedKind === "atlaso" ? "Release base URL" : "Repository URL", field: "url" },
      ];
      if (selectedKind === "atlaso") reviewItems.push({ label: "Release channel", field: "channel" });
      if (selectedKind === "powershell") reviewItems.push({ label: "Trusted", field: "trusted" });
      if (selectedKind === "photon") {
        reviewItems.push(
          { label: "Atlaso managed", field: "managed" },
          { label: "RPM signatures", field: "gpgcheck" },
          { label: "TLS verification", field: "tls_verify" },
          { label: "GPG key URL", field: "gpgkey" },
        );
      }
      reviewItems.push({ label: "Desired state", field: "enabled" });
      renderAtlasoWizardReview(form, reviewItems);
    },
    onSubmit: async () => {
      const response = await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "X-Atlaso-Wizard": "1",
        },
      });
      const responseText = await response.text();
      let payload = {};
      try {
        payload = responseText ? JSON.parse(responseText) : {};
      } catch (_error) {
        payload = {};
      }
      if (!response.ok) {
        throw new Error(payload.detail || "The repository could not be created.");
      }
      if (!payload.source?.id) {
        throw new Error("The server did not return the created repository.");
      }
      try {
        window.localStorage.setItem("atlaso:appliance-update:workspace-tab", "appliance-update-sources");
        window.localStorage.setItem(
          `atlaso:appliance-update:${selectedKind}-repository-tab`,
          `update-source-${payload.source.id}`,
        );
      } catch {
        // Reloading the page still shows the saved repository when storage is unavailable.
      }
      window.location.assign("/appliance-update#update-sources");
      return { valid: true };
    },
  });

  launchers.forEach((button) => {
    button.addEventListener("click", () => {
      wizard.open({ launcher: button, context: { kind: button.dataset.updateSourceKind || "" } });
    });
  });
}

function initializeManagedPackageWizard() {
  const form = document.querySelector("[data-managed-package-create-form]");
  const dialog = document.getElementById("managed-package-dialog");
  const launcher = document.querySelector("[data-managed-package-wizard-open]");
  if (
    !(form instanceof HTMLFormElement)
    || !(dialog instanceof HTMLDialogElement)
    || !(launcher instanceof HTMLButtonElement)
    || !window.AtlasoUiPatterns
  ) {
    return;
  }
  const policy = form.querySelector("[data-managed-package-create-policy]");
  const target = form.querySelector("[data-managed-package-create-target]");
  const targetLabel = form.querySelector("[data-managed-package-create-target-label]");
  const updateTargetState = () => {
    if (!(policy instanceof HTMLSelectElement) || !(target instanceof HTMLInputElement)) return;
    const usesLatest = policy.value === "latest";
    if (usesLatest) target.value = "";
    target.disabled = usesLatest;
    target.required = !usesLatest;
    target.placeholder = usesLatest ? "Resolved from repository" : "Required for pinned policy";
    target.setAttribute("aria-disabled", usesLatest ? "true" : "false");
    targetLabel?.classList.toggle("muted", usesLatest);
  };
  policy?.addEventListener("change", updateTargetState);
  const wizard = window.AtlasoUiPatterns.createWizard({
    form,
    dialog,
    steps: [
      { id: "identity", title: "Choose the managed module", description: "Enter the exact module name and select its registered PowerShell repository." },
      { id: "policy", title: "Choose version resolution", description: "Pin an exact version or follow the latest version published by the repository." },
      { id: "enablement", title: "Choose desired availability", description: "Decide whether update checks and installation runs include this module." },
      { id: "review", title: "Review module creation", description: "Confirm the desired update state before saving it." },
    ],
    discardTitle: "Discard managed module?",
    discardMessage: "The module identity and version policy entered in this wizard will be lost.",
    onOpen: () => {
      form.reset();
      updateTargetState();
    },
    validateStep: (state) => validateAtlasoWizardStep(state),
    prepareReview: () => {
      renderAtlasoWizardReview(form, [
        { label: "Module", field: "name" },
        { label: "Repository", field: "source_id" },
        { label: "Version policy", field: "policy" },
        { label: "Target version", value: () => policy?.value === "latest" ? "Latest available" : target?.value || "Not set" },
        { label: "Desired state", field: "enabled" },
      ]);
    },
  });
  launcher.addEventListener("click", () => wizard.open({ launcher }));
}

function initializeEsxStorageTables() {
  const volumeElement = document.getElementById("esx-storage-volumes-table");
  const shareElement = document.getElementById("esx-storage-shares-table");
  if (!(volumeElement instanceof HTMLElement) && !(shareElement instanceof HTMLElement)) return;
  if (typeof Tabulator === "undefined") return;

  if (volumeElement instanceof HTMLElement) {
    const rows = JSON.parse(volumeElement.dataset.esxStorageVolumes || "[]");
    const canWrite = volumeElement.dataset.canWrite === "true";
    const tableRows = canWrite ? [...rows, { is_new: true, name: "" }] : rows;
    const volumeValue = (cell, formatter = (value) => value) => cell.getRow().getData().is_new ? "" : formatter(cell.getValue());
    const atlasoGridOptions34 = {
      data: tableRows,
      layout: "fitColumns",
      placeholder: "No storage volumes are configured.",
      rowFormatter: (row) => markNewRecordRow(row, "name"),
      columns: [
        { title: "Name", field: "name", minWidth: 130, formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-esx-storage-wizard-open="volume">+ Add storage volume here</button>' : escapeHtml(cell.getValue()) },
        { title: "Source", field: "source_type", formatter: (cell) => volumeValue(cell, (value) => value === "blank_disk" ? "blank disk" : "mounted ext4") },
        { title: "Stable identity / mount", field: "stable_device_id", minWidth: 260, formatter: (cell) => cell.getRow().getData().is_new ? "" : `<code>${escapeHtml(cell.getValue() || cell.getRow().getData().mount_path || "")}</code>` },
        { title: "Capacity", field: "capacity_bytes", formatter: (cell) => volumeValue(cell, (value) => Number(value || 0).toLocaleString()) },
        { title: "Filesystem", field: "filesystem_uuid", formatter: (cell) => volumeValue(cell, (value) => value || "pending ext4 format") },
        { title: "State", field: "state", formatter: (cell) => volumeValue(cell) },
      ],
    };
    window.AtlasoUiPatterns.createGrid({
      element: volumeElement,
      pattern: "wizard-backed",
      permission: {
        allowed: canWrite,
        message: "You have read-only access to storage volumes.",
      },
      options: atlasoGridOptions34,
    }).table;
  }

  if (shareElement instanceof HTMLElement) {
    const rows = JSON.parse(shareElement.dataset.esxStorageShares || "[]");
    const interfaces = JSON.parse(shareElement.dataset.interfaces || "[]");
    const canWrite = shareElement.dataset.canWrite === "true";
    const tableRows = canWrite ? [...rows, { is_new: true, datastore_name: "" }] : rows;
    const shareValue = (cell, formatter = (value) => value) => cell.getRow().getData().is_new ? "" : formatter(cell.getValue());
    const saveEnabledState = async (cell) => {
      const row = cell.getRow().getData();
      if (!canWrite || row.is_new) return;
      const body = new FormData();
      body.set("csrf", shareElement.dataset.csrf || "");
      body.set("datastore_name", row.datastore_name || "");
      body.set("volume_id", String(row.volume_id || ""));
      body.set("relative_path", row.relative_path || "");
      body.set("preferred_nfs_version", row.preferred_nfs_version || "4.1");
      body.set("interface_name", row.interface_name || "");
      for (const family of row.address_families || []) body.append("address_families", family);
      body.set("ipv4_clients", (row.ipv4_clients || []).join("\n"));
      body.set("ipv6_clients", (row.ipv6_clients || []).join("\n"));
      if (row.enabled) body.set("enabled", "on");
      try {
        const response = await fetch(`/esx-storage/shares/${row.id}`, {
          method: "POST",
          headers: { Accept: "application/json" },
          body,
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          throw new Error(payload.detail || "The datastore state could not be saved.");
        }
        window.history.replaceState(null, "", "/esx-storage#nfs-datastores");
        window.location.reload();
      } catch (error) {
        cell.restoreOldValue();
        showTransientGridStatus(error instanceof Error ? error.message : "The datastore state could not be saved.");
      }
    };
    const editRow = (row) => {
      const data = row?.getData?.() || row;
      if (!canWrite || !data || data.is_new) return;
      const form = document.querySelector('[data-esx-storage-wizard="share"]');
      form?.esxStorageOpenWizard?.(data);
    };
    const atlasoGridOptions35 = {
      data: tableRows,
      layout: "fitColumns",
      placeholder: "No NFS datastores are configured.",
      rowFormatter: (row) => markNewRecordRow(row, "datastore_name"),
      rowContextMenu: canWrite ? [
        {
          label: "Edit datastore",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => editRow(row),
        },
        {
          label: "Remove datastore",
          disabled: (component) => component.getData().is_new,
          action: (_event, row) => {
            const form = document.getElementById(`esx-storage-remove-share-${row.getData().id}`);
            if (form instanceof HTMLFormElement) form.requestSubmit();
          },
        },
        {
          label: "Remove newest inactive version",
          disabled: (_event, row) => !(row.getData().installed_versions || []).some((item) => item.version !== row.getData().active_version && item.version !== row.getData().desired_version),
          action: async (_event, row) => {
            const data = row.getData();
            const candidate = (data.installed_versions || []).find((item) => item.version !== data.active_version && item.version !== data.desired_version);
            if (!candidate) return;
            const confirmed = await requestConfirmation({
              title: `Remove ${data.label} ${candidate.version}?`,
              message: "This permanently removes the selected inactive immutable cache version. Active and desired versions cannot be removed.",
              label: "Remove media",
            });
            if (!confirmed) return;
            await networkBootRequest(`/api/v1/network-boot/environments/${data.key}/media/${encodeURIComponent(candidate.version)}`, { method: "DELETE" });
            window.location.reload();
          },
        },
      ] : [],
      rowDblClick: (_event, row) => editRow(row),
      columns: [
        { title: "Datastore", field: "datastore_name", formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-esx-storage-wizard-open="share">+ Add NFS datastore here</button>' : escapeHtml(cell.getValue()), minWidth: 205, widthGrow: 1.4 },
        { title: "Volume", field: "volume_name", minWidth: 120, formatter: (cell) => shareValue(cell) },
        { title: "Path", field: "relative_path", formatter: (cell) => shareValue(cell), minWidth: 150 },
        { title: "NFS", field: "preferred_nfs_version", formatter: (cell) => shareValue(cell) },
        { title: "Interface / VLAN", field: "interface_name", formatter: (cell) => shareValue(cell), minWidth: 130 },
        { title: "Families", field: "address_families", formatter: (cell) => shareValue(cell, (value) => (value || []).map((family) => family === "ipv4" ? "IPv4" : "IPv6").join(" + ")) },
        { title: "IPv4 VMkernel clients", field: "ipv4_clients", formatter: (cell) => shareValue(cell, (value) => (value || []).join(", ") || "any"), minWidth: 170 },
        { title: "IPv6 VMkernel clients", field: "ipv6_clients", formatter: (cell) => shareValue(cell, (value) => (value || []).join(", ") || "any"), minWidth: 180 },
        {
          title: "Enabled",
          field: "enabled",
          width: 82,
          hozAlign: "center",
          headerHozAlign: "center",
          formatter: (cell) => cell.getRow().getData().is_new ? "" : atlasoBooleanFormatter(cell),
          editor: "tickCross",
          editable: (cell) => canWrite && !cell.getRow().getData().is_new,
          cellEdited: saveEnabledState,
        },
      ],
    };
    window.AtlasoUiPatterns.createGrid({
      element: shareElement,
      pattern: "wizard-backed",
      permission: {
        allowed: canWrite,
        message: "You have read-only access to NFS datastores.",
      },
      onOpenRow: canWrite ? (rowData) => editRow(rowData) : null,
      options: atlasoGridOptions35,
    }).table;
  }
}

function initializeEsxStorageWizards() {
  const configurations = {
    volume: [
      { id: "identity", title: "Name the volume", description: "Choose a stable Atlaso name and how storage is supplied." },
      { id: "storage", title: "Select storage", description: "Choose the eligible whole disk or mounted ext4 filesystem backing this volume." },
      { id: "review", title: "Review the volume", description: "Confirm the desired state and the formatting safety boundary." },
    ],
    share: [
      { id: "identity", title: "Define the datastore", description: "Choose its ESX identity and contained directory." },
      { id: "endpoint", title: "Choose the endpoint", description: "Select one interface/VLAN, NFS version, and equal IPv4/IPv6 exposure." },
      { id: "clients", title: "Choose VMkernel access", description: "Restrict each enabled family to specific clients, or leave it empty to allow anyone." },
      { id: "state", title: "Choose datastore state", description: "Enable the datastore now or keep it disabled desired state without deleting backing data." },
      { id: "review", title: "Review the datastore", description: "Confirm the datastore, endpoint, and family-aware client allowlists." },
    ],
  };
  const forms = new Map();
  const setReviewValue = (form, key, value) => {
    const target = form.querySelector(`[data-esx-storage-review="${key}"]`);
    if (target instanceof HTMLElement) target.textContent = value || "not configured";
  };

  document.querySelectorAll("[data-esx-storage-wizard]").forEach((form) => {
    if (!(form instanceof HTMLFormElement)) return;
    const kind = form.dataset.esxStorageWizard;
    const steps = configurations[kind];
    const modal = form.closest("dialog");
    if (!steps || !(modal instanceof HTMLDialogElement)) return;
    const modalTitle = form.querySelector("[data-esx-storage-wizard-modal-title]");
    const submit = form.querySelector("[data-esx-storage-wizard-submit]");
    const populateReview = () => {
      if (kind === "volume") {
        const source = form.elements.source_type;
        const blankDisk = form.elements.stable_device_id;
        const mountedVolume = form.elements.mount_path;
        const target = source.value === "blank_disk" ? blankDisk : mountedVolume;
        setReviewValue(form, "volume-name", form.elements.name.value);
        setReviewValue(form, "volume-source", source.selectedOptions[0]?.textContent?.trim());
        setReviewValue(form, "volume-target", target.selectedOptions[0]?.textContent?.trim());
        return;
      }
      const families = [...form.querySelectorAll('input[name="address_families"]:checked')].map((input) => input.value === "ipv4" ? "IPv4" : "IPv6");
      const clients = [];
      if (families.includes("IPv4")) clients.push(`IPv4: ${String(form.elements.ipv4_clients.value || "").trim() || "any IPv4 client"}`);
      if (families.includes("IPv6")) clients.push(`IPv6: ${String(form.elements.ipv6_clients.value || "").trim() || "any IPv6 client"}`);
      setReviewValue(form, "share-name", form.elements.datastore_name.value);
      setReviewValue(form, "share-state", form.elements.enabled.checked ? "Enabled" : "Disabled");
      setReviewValue(form, "share-path", `${form.elements.volume_id.selectedOptions[0]?.textContent?.trim() || "volume"} / ${form.elements.relative_path.value}`);
      setReviewValue(form, "share-protocol", `NFS ${form.elements.preferred_nfs_version.value}`);
      setReviewValue(form, "share-endpoint", `${form.elements.interface_name.value} · ${families.join(" + ")}`);
      setReviewValue(form, "share-clients", clients.join(" · "));
    };
    const validateStep = ({ step }) => {
      if (kind === "share" && step.id === "endpoint" && !form.querySelector('input[name="address_families"]:checked')) {
        return {
          valid: false,
          message: "Enable IPv4, IPv6, or both for this datastore.",
        };
      }
      return true;
    };
    const defaultAction = form.action;
    let wizard;
    wizard = window.AtlasoUiPatterns.createWizard({
      form,
      dialog: modal,
      steps,
      validateStep,
      prepareReview: populateReview,
      onOpen: ({ context: row }) => {
      const editing = kind === "share" && row && row.id;
      form.action = editing ? `/esx-storage/shares/${row.id}` : defaultAction;
      if (modalTitle instanceof HTMLElement) modalTitle.textContent = editing ? "Edit NFS datastore" : kind === "share" ? "Add NFS datastore" : "Add storage volume";
      if (submit instanceof HTMLButtonElement) submit.textContent = editing ? "Update NFS datastore" : kind === "share" ? "Add NFS datastore" : "Add storage volume";
      if (editing) {
        form.elements.datastore_name.value = row.datastore_name || "";
        form.elements.volume_id.value = String(row.volume_id || "");
        form.elements.relative_path.value = row.relative_path || "";
        form.elements.preferred_nfs_version.value = row.preferred_nfs_version || "4.1";
        form.elements.interface_name.value = row.interface_name || "";
        form.querySelectorAll('input[name="address_families"]').forEach((checkbox) => {
          checkbox.checked = (row.address_families || []).includes(checkbox.value);
        });
        form.elements.ipv4_clients.value = (row.ipv4_clients || []).join("\n");
        form.elements.ipv6_clients.value = (row.ipv6_clients || []).join("\n");
        form.elements.enabled.checked = row.enabled !== false;
      }
      form.querySelector("[data-esx-storage-volume-source]")?.dispatchEvent(new Event("change"));
      if (!editing) form.querySelector("[data-esx-storage-interface]")?.dispatchEvent(new Event("change"));
      },
      onSubmit: async () => {
        try {
          const response = await fetch(form.action, {
            method: "POST",
            headers: { Accept: "application/json" },
            body: new FormData(form),
          });
          if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            return { ok: false, message: payload.detail || "The ESX Storage change could not be saved." };
          }
          const target = kind === "volume" ? "/esx-storage#storage-volumes" : "/esx-storage#nfs-datastores";
          wizard.markClean();
          window.history.replaceState(null, "", target);
          window.location.reload();
          return { ok: true, close: false };
        } catch (_error) {
          return {
            ok: false,
            message: "The ESX Storage change could not be saved. Check the connection and try again.",
          };
        }
      },
      closeOnSubmit: false,
    });
    const openWizard = (row = null, launcher = null) => wizard.open({ context: row, launcher });
    form.esxStorageOpenWizard = openWizard;
    forms.set(kind, { form, modal, wizard });
  });

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const trigger = event.target.closest("[data-esx-storage-wizard-open]");
    if (!(trigger instanceof HTMLElement)) return;
    const entry = forms.get(trigger.dataset.esxStorageWizardOpen);
    entry?.form.esxStorageOpenWizard?.(null, trigger);
  });
}

function initializeEsxStorageFamilyDefaults() {
  const form = document.querySelector("[data-esx-storage-share-form]");
  const select = form?.querySelector("[data-esx-storage-interface]");
  if (!(form instanceof HTMLFormElement) || !(select instanceof HTMLSelectElement)) return;
  const update = () => {
    const option = select.selectedOptions[0];
    for (const family of ["ipv4", "ipv6"]) {
      const checkbox = form.querySelector(`input[name="address_families"][value="${family}"]`);
      if (!(checkbox instanceof HTMLInputElement)) continue;
      checkbox.checked = Boolean(option?.dataset[family]);
    }
  };
  select.addEventListener("change", update);
  update();
}

function initializeEsxStorageVolumeSource() {
  const form = document.querySelector("[data-esx-storage-volume-form]");
  const source = form?.querySelector("[data-esx-storage-volume-source]");
  const blank = form?.querySelector("[data-esx-storage-blank-source]");
  const mounted = form?.querySelector("[data-esx-storage-mounted-source]");
  if (!(form instanceof HTMLFormElement) || !(source instanceof HTMLSelectElement)) return;
  const update = () => {
    const usesBlankDisk = source.value === "blank_disk";
    blank?.toggleAttribute("hidden", !usesBlankDisk);
    mounted?.toggleAttribute("hidden", usesBlankDisk);
    const stableIdentity = blank?.querySelector('select[name="stable_device_id"]');
    const mountPath = mounted?.querySelector('select[name="mount_path"]');
    if (stableIdentity instanceof HTMLSelectElement) stableIdentity.required = usesBlankDisk;
    if (mountPath instanceof HTMLSelectElement) mountPath.required = !usesBlankDisk;
  };
  source.addEventListener("change", update);
  update();
}

function initializeVaultsPage() {
  const workspace = document.querySelector("[data-vaults-workspace]");
  if (!(workspace instanceof HTMLElement) || !window.AtlasoUiPatterns) return;
  const createModal = document.getElementById("vault-create-modal");
  const createForm = document.querySelector("[data-vault-create-form]");
  if (createModal instanceof HTMLDialogElement && createForm instanceof HTMLFormElement) {
    const createWizard = window.AtlasoUiPatterns.createWizard({
      dialog: createModal,
      form: createForm,
      steps: [
        { id: "identity", title: "Name the vault", description: "Use a clear environment or workflow name." },
        { id: "review", title: "Review the vault", description: "Confirm the identity and restricted password scope." },
      ],
      validateStep: ({ step }) => step.id !== "identity" || createForm.reportValidity(),
      prepareReview: () => {
        const name = createForm.querySelector("[data-vault-create-review-name]");
        const description = createForm.querySelector("[data-vault-create-review-description]");
        if (name) name.textContent = String(createForm.elements.name.value || "").trim();
        if (description) description.textContent = String(createForm.elements.description.value || "").trim() || "No description";
      },
    });
    document.querySelectorAll("[data-vault-create-open]").forEach((button) => button.addEventListener("click", () => createWizard.open({ launcher: button })));
  }

  const entryModal = document.getElementById("vault-entry-modal");
  const entryForm = document.querySelector("[data-vault-entry-form]");
  if (!(entryModal instanceof HTMLDialogElement) || !(entryForm instanceof HTMLFormElement)) return;
  const uriList = entryForm.querySelector("[data-vault-uri-list]");
  const uriAddButton = entryForm.querySelector("[data-vault-uri-add]");
  const entrySubmit = entryForm.querySelector("[data-atlaso-wizard-submit]");
  const entryPassword = entryForm.querySelector("[data-vault-entry-password]");
  const entryPasswordEye = entryForm.querySelector("[data-vault-entry-password-eye]");
  const uriError = workspace.querySelector("[data-vault-uri-error]");
  let entryPasswordRevealTimer = 0;
  const uriValues = () => [...(uriList?.querySelectorAll("[data-vault-uri-input]") || [])]
    .map((input) => String(input.value || "").trim())
    .filter(Boolean);
  const rawUriValues = () => [...(uriList?.querySelectorAll("[data-vault-uri-input]") || [])]
    .map((input) => String(input.value || "").trim());
  const syncUriValue = () => {
    entryForm.elements.uris_json.value = JSON.stringify(uriValues());
    if (uriAddButton instanceof HTMLButtonElement) uriAddButton.disabled = rawUriValues().length >= 9;
  };
  const renderUriRows = (values = []) => {
    if (!(uriList instanceof HTMLElement)) return;
    uriList.replaceChildren();
    const rows = values.length ? values.slice(0, 9) : [""];
    rows.forEach((value, index) => {
      const row = document.createElement("div");
      row.className = "vault-uri-row";
      const label = document.createElement("label");
      const caption = document.createElement("span");
      caption.textContent = `URI ${index + 1}`;
      const input = document.createElement("input");
      input.type = "text";
      input.inputMode = "url";
      input.maxLength = 2048;
      input.placeholder = "https://vcf.example.internal";
      input.value = value;
      input.dataset.vaultUriInput = "true";
      input.setAttribute("aria-label", `URI ${index + 1}`);
      input.addEventListener("input", syncUriValue);
      label.append(caption, input);
      const remove = document.createElement("button");
      remove.className = "button secondary compact";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.setAttribute("aria-label", `Remove URI ${index + 1}`);
      remove.disabled = rows.length === 1;
      remove.addEventListener("click", () => {
        const nextValues = rawUriValues();
        nextValues.splice(index, 1);
        renderUriRows(nextValues);
      });
      row.append(label, remove);
      uriList.append(row);
    });
    syncUriValue();
  };
  uriAddButton?.addEventListener("click", () => {
    const values = rawUriValues();
    if (values.length < 9) renderUriRows([...values, ""]);
  });
  const validateUris = () => {
    const inputs = [...(uriList?.querySelectorAll("[data-vault-uri-input]") || [])];
    const seen = new Set();
    for (const input of inputs) {
      const value = String(input.value || "").trim();
      if (!value) continue;
      if (/\s/.test(value)) {
        return { ok: false, message: "URIs cannot contain whitespace.", field: input };
      }
      try {
        const parsed = new URL(value);
        if (!["http:", "https:", "ssh:", "sftp:"].includes(parsed.protocol) || !parsed.hostname) throw new Error();
        if (parsed.username || parsed.password) {
          return { ok: false, message: "Do not place credentials in a URI; use the entry Username and Password.", field: input };
        }
        if (seen.has(parsed.href)) {
          return { ok: false, message: "Each URI must be unique within the entry.", field: input };
        }
        seen.add(parsed.href);
      } catch (_error) {
        return { ok: false, message: "Enter an HTTP, HTTPS, SSH, or SFTP URI with a hostname.", field: input };
      }
    }
    syncUriValue();
    return true;
  };
  const openVaultUri = async (vaultId, row, index) => {
    const uri = row.uris?.[index];
    if (!uri) return;
    if (uriError instanceof HTMLElement) {
      uriError.textContent = "";
      uriError.classList.add("hidden");
    }
    const scheme = new URL(uri).protocol;
    if (scheme === "http:" || scheme === "https:") {
      window.open(uri, "_blank", "noopener");
      return;
    }
    let remoteWindow = null;
    const requestLaunch = async (confirmedFingerprint = "") => {
      const body = new FormData();
      body.set("csrf", String(entryForm.elements.csrf.value || ""));
      body.set("vault_id", String(vaultId));
      body.set("entry_id", String(row.id));
      body.set("uri_index", String(index + 1));
      if (confirmedFingerprint) body.set("confirmed_fingerprint", confirmedFingerprint);
      const response = await fetch("/terminal/remote-launches", {
        method: "POST",
        headers: { Accept: "application/json", "X-Requested-With": "Atlaso" },
        cache: "no-store",
        body,
      });
      const payload = await response.json().catch(() => ({}));
      if (response.status === 409 && payload.error_code === "SSH_HOST_KEY_CONFIRMATION_REQUIRED") {
        const confirmed = typeof window.requestConfirmation === "function" && await window.requestConfirmation({
          title: `Trust ${payload.target}?`,
          message: "Verify the SSH host key out of band before connecting.",
          detailLabel: "SHA-256 fingerprint",
          detail: payload.fingerprint,
          label: "Connect",
        });
        if (!confirmed) return null;
        remoteWindow = window.open(
          `/terminal/remote#target=${encodeURIComponent(String(payload.hostname || "Remote host"))}`,
          "_blank",
        );
        if (remoteWindow) remoteWindow.opener = null;
        return requestLaunch(payload.fingerprint);
      }
      if (!response.ok) throw new Error(payload.detail || "The remote terminal could not be prepared.");
      return payload;
    };
    try {
      const payload = await requestLaunch();
      if (!payload) {
        remoteWindow?.close();
        return;
      }
      if (remoteWindow && !remoteWindow.closed) {
        const launchUrl = new URL(payload.url, window.location.origin);
        launchUrl.hash += `&target=${encodeURIComponent(String(payload.target || "Remote host"))}`;
        remoteWindow.location.replace(launchUrl.toString());
        return;
      }
      const launchUrl = new URL(payload.url, window.location.origin);
      launchUrl.hash += `&target=${encodeURIComponent(String(payload.target || "Remote host"))}`;
      const opened = window.open(launchUrl.toString(), "_blank", "noopener");
      if (!opened) throw new Error("Allow pop-ups for Atlaso to open the approved remote terminal.");
    } catch (error) {
      remoteWindow?.close();
      const message = error instanceof Error ? error.message : "The remote terminal could not be prepared.";
      if (uriError instanceof HTMLElement) {
        uriError.textContent = `Could not open ${uri}. ${message}`;
        uriError.classList.remove("hidden");
        uriError.scrollIntoView({ block: "nearest" });
      }
      showTransientGridStatus("Remote target unavailable");
    }
  };
  const entryWizard = window.AtlasoUiPatterns.createWizard({
    dialog: entryModal,
    form: entryForm,
    steps: [
      { id: "identity", title: "Identify the password", description: "Choose a stable dotted key and optional details." },
      { id: "password", title: "Supply the password", description: "Atlaso encrypts this value before database storage." },
      { id: "uris", title: "Add connection URIs", description: "Add up to nine HTTP, HTTPS, SSH, or SFTP targets." },
      { id: "review", title: "Review the entry", description: "Confirm metadata without displaying the password." },
    ],
    validateStep: ({ step }) => {
      if (step.id === "password") {
        const password = entryForm.elements.value;
        if (password.required && !password.value) return { ok: false, message: "Enter a password.", field: password };
      }
      if (step.id === "uris") return validateUris();
      return true;
    },
    prepareReview: () => {
      entryForm.querySelector("[data-vault-entry-review-key]").textContent = String(entryForm.elements.key.value || "");
      entryForm.querySelector("[data-vault-entry-review-username]").textContent = String(entryForm.elements.username.value || "") || "Not specified";
      entryForm.querySelector("[data-vault-entry-review-password]").textContent = entryForm.elements.value.value ? "New encrypted value supplied" : "Existing encrypted value retained";
      entryForm.querySelector("[data-vault-entry-review-uris]").textContent = uriValues().length ? `${uriValues().length} configured` : "None";
    },
    onOpen: ({ context }) => {
      const row = context?.row || null;
      const copying = Boolean(context?.copy && row);
      const vaultId = context?.vaultId;
      window.clearTimeout(entryPasswordRevealTimer);
      entryPasswordRevealTimer = 0;
      entryForm.reset();
      if (entryPassword instanceof HTMLInputElement) entryPassword.type = "password";
      entryForm.action = row && !copying
        ? `/vaults/${vaultId}/entries/${row.id}/edit`
        : `/vaults/${vaultId}/entries`;
      entryForm.elements.copy_entry_id.value = copying ? String(row.id) : "";
      entryForm.dataset.vaultId = String(vaultId || "");
      entryForm.elements.key.value = copying ? String(context.copyKey || "") : row?.key || "";
      entryForm.elements.description.value = row?.description || "";
      entryForm.elements.username.value = row?.username || "";
      renderUriRows(row?.uris || []);
      entryForm.elements.value.required = !row;
      const title = entryForm.querySelector("[data-vault-entry-title]");
      if (title) title.textContent = copying ? "Copy entry" : row ? "Edit entry" : "Add password";
      const help = entryForm.querySelector("[data-vault-entry-password-help]");
      if (entryPassword instanceof HTMLInputElement) {
        entryPassword.placeholder = copying ? "••••••••" : "";
      }
      if (help) help.textContent = copying
        ? "The encrypted value will be copied. Use the eye to inspect it or enter a replacement."
        : row
          ? "Leave blank to retain the existing encrypted value."
          : "The value is encrypted before it is stored.";
      if (entrySubmit instanceof HTMLButtonElement) entrySubmit.textContent = copying ? "Copy entry" : row ? "Save entry" : "Save password";
      entryPasswordEye?.classList.toggle("hidden", !row);
      if (entryPasswordEye instanceof HTMLButtonElement) {
        entryPasswordEye.dataset.revealed = "false";
        entryPasswordEye.setAttribute("aria-label", "Reveal password");
        entryPasswordEye.title = "Reveal password";
      }
    },
  });
  entryPasswordEye?.addEventListener("click", async () => {
    if (!(entryPasswordEye instanceof HTMLButtonElement) || !(entryPassword instanceof HTMLInputElement)) return;
    if (entryPasswordEye.dataset.revealed === "true") {
      entryPassword.type = "password";
      entryPasswordEye.dataset.revealed = "false";
      entryPasswordEye.setAttribute("aria-label", "Reveal password");
      entryPasswordEye.title = "Reveal password";
      return;
    }
    const match = entryForm.action.match(/\/vaults\/(\d+)\/entries\/(\d+)\/edit$/);
    const vaultId = match?.[1] || entryForm.dataset.vaultId;
    const entryId = match?.[2] || String(entryForm.elements.copy_entry_id.value || "");
    if (!vaultId || !entryId) return;
    entryPasswordEye.disabled = true;
    const body = new FormData();
    body.set("csrf", String(entryForm.elements.csrf.value || ""));
    try {
      const response = await fetch(`/vaults/${vaultId}/entries/${entryId}/reveal`, {
        method: "POST",
        headers: { Accept: "application/json" },
        cache: "no-store",
        body,
      });
      if (!response.ok) throw new Error();
      const payload = await response.json();
      entryPassword.value = String(payload.value || "");
      entryPassword.type = "text";
      entryPasswordEye.dataset.revealed = "true";
      entryPasswordEye.setAttribute("aria-label", "Hide password");
      entryPasswordEye.title = "Hide password";
      entryPasswordRevealTimer = window.setTimeout(() => {
        if (!entryPassword.isConnected) return;
        entryPassword.type = "password";
        entryPasswordEye.dataset.revealed = "false";
        entryPasswordEye.setAttribute("aria-label", "Reveal password");
        entryPasswordEye.title = "Reveal password";
        entryPasswordRevealTimer = 0;
      }, 15000);
    } catch (_error) {
      showTransientGridStatus("Password reveal failed");
    } finally {
      entryPasswordEye.disabled = false;
    }
  });

  document.querySelectorAll("[data-vault-entries-table]").forEach((element) => {
    if (!(element instanceof HTMLElement)) return;
    const vaultId = Number(element.dataset.vaultId || 0);
    const source = document.getElementById(`vault-entries-data-${vaultId}`);
    const rows = JSON.parse(source?.textContent || "[]");
    rows.push({ is_new: true, key: "" });
    window.AtlasoUiPatterns.createGrid({
      element,
      pattern: "wizard-backed",
      options: {
        data: rows,
        layout: "fitColumns",
        height: "100%",
        placeholder: "No passwords are stored in this vault.",
        rowFormatter: (row) => markNewRecordRow(row, "key"),
        rowContextMenu: (_event, component) => {
          const row = component.getData();
          if (row.is_new) return [];
          const uriActions = (row.uris || []).map((uri, index) => {
            const parsed = new URL(uri);
            return {
              label: `URI ${index + 1} · ${parsed.protocol.slice(0, -1).toUpperCase()} · ${parsed.host}`,
              action: () => openVaultUri(vaultId, row, index),
            };
          });
          const existingKeys = new Set(rows.filter((candidate) => !candidate.is_new).map((candidate) => String(candidate.key || "")));
          const copyKeyWithSuffix = (suffix) => {
            const marker = suffix === 1 ? ".copy" : `.copy${suffix}`;
            return `${String(row.key || "").slice(0, 180 - marker.length).replace(/\.$/, "")}${marker}`;
          };
          let copySuffix = 1;
          let copyKey = copyKeyWithSuffix(copySuffix);
          while (existingKeys.has(copyKey)) copyKey = copyKeyWithSuffix(copySuffix += 1);
          return [
            {
              label: "Edit",
              action: (_menuEvent, rowComponent) => entryWizard.open({
                context: { vaultId, row: rowComponent.getData() },
                launcher: rowComponent.getElement(),
              }),
            },
            {
              label: "Copy",
              action: (_menuEvent, rowComponent) => entryWizard.open({
                context: { vaultId, row: rowComponent.getData(), copy: true, copyKey },
                launcher: rowComponent.getElement(),
              }),
            },
            { separator: true },
            {
              label: "Open",
              disabled: uriActions.length === 0,
              menu: uriActions,
            },
            { separator: true },
            {
              label: "Remove",
              action: (_menuEvent, rowComponent) => {
                const data = rowComponent.getData();
                document.getElementById(`vault-entry-delete-${data.id}`)?.requestSubmit();
              },
            },
          ];
        },
        columns: [
          {
            title: "Key",
            field: "key",
            minWidth: 230,
            formatter: (cell) => cell.getRow().getData().is_new
              ? '<button class="add-row-button" type="button">+ Add password here</button>'
              : `<code>${escapeHtml(cell.getValue())}</code>`,
            cellClick: (_event, cell) => entryWizard.open({ context: { vaultId, row: cell.getRow().getData().is_new ? null : cell.getRow().getData() }, launcher: cell.getElement() }),
          },
          { title: "Description", field: "description", minWidth: 220, formatter: (cell) => cell.getRow().getData().is_new ? "" : escapeHtml(cell.getValue() || "—") },
          { title: "Username", field: "username", minWidth: 180, formatter: (cell) => cell.getRow().getData().is_new ? "" : `<code>${escapeHtml(cell.getValue() || "—")}</code>` },
          {
            title: "URI(s)",
            field: "uris",
            minWidth: 280,
            variableHeight: true,
            formatter: (cell) => {
              if (cell.getRow().getData().is_new) return "";
              const uris = cell.getValue() || [];
              return uris.length
                ? `<div class="vault-uri-cell">${uris.map((uri) => `<code>${escapeHtml(uri)}</code>`).join("")}</div>`
                : "—";
            },
          },
          {
            title: "Password",
            field: "has_value",
            minWidth: 170,
            headerSort: false,
            formatter: (cell) => cell.getRow().getData().is_new ? "" : '<span class="vault-password-value" data-vault-password-value>••••••••</span> <button class="vault-password-eye" type="button" aria-label="Reveal password" title="Reveal password" data-vault-password-eye>&#128065;</button>',
            cellClick: async (event, cell) => {
              const eye = event.target.closest("[data-vault-password-eye]");
              if (!(eye instanceof HTMLButtonElement)) return;
              const value = cell.getElement().querySelector("[data-vault-password-value]");
              if (!(value instanceof HTMLElement)) return;
              if (eye.dataset.revealed === "true") {
                value.textContent = "••••••••";
                eye.dataset.revealed = "false";
                eye.setAttribute("aria-label", "Reveal password");
                eye.title = "Reveal password";
                return;
              }
              eye.disabled = true;
              const body = new FormData();
              body.set("csrf", String(entryForm.elements.csrf.value || ""));
              try {
                const row = cell.getRow().getData();
                const response = await fetch(`/vaults/${vaultId}/entries/${row.id}/reveal`, {
                  method: "POST",
                  headers: { Accept: "application/json" },
                  cache: "no-store",
                  body,
                });
                if (!response.ok) throw new Error("Password reveal failed.");
                const payload = await response.json();
                value.textContent = String(payload.value || "");
                eye.dataset.revealed = "true";
                eye.setAttribute("aria-label", "Hide password");
                eye.title = "Hide password";
                window.setTimeout(() => {
                  if (!value.isConnected) return;
                  value.textContent = "••••••••";
                  eye.dataset.revealed = "false";
                  eye.setAttribute("aria-label", "Reveal password");
                  eye.title = "Reveal password";
                }, 15000);
              } catch (_error) {
                value.textContent = "Reveal failed";
              } finally {
                eye.disabled = false;
              }
            },
          },
        ],
      },
    });
  });
}

function initializeVcfVaultImport() {
  const modal = document.getElementById("vcf-vault-import-modal");
  const form = document.querySelector("[data-vcf-vault-import-form]");
  if (!(modal instanceof HTMLDialogElement) || !(form instanceof HTMLFormElement) || !window.AtlasoUiPatterns) return;
  const candidatesElement = form.querySelector("[data-vcf-vault-candidates]");
  const fingerprintHelp = form.querySelector("[data-vcf-vault-fingerprint]");
  const fingerprintConfirm = form.querySelector("[data-vcf-vault-fingerprint-confirm]");
  let candidates = [];
  let observedFingerprint = "";
  const requestPayload = () => ({
    csrf: String(form.elements.csrf.value || ""),
    source_type: String(form.elements.source_type.value || ""),
    address: String(form.elements.address.value || ""),
    port: Number(form.elements.port.value || 443),
    confirmed_fingerprint: String(form.elements.confirmed_fingerprint.value || ""),
    username: String(form.elements.username.value || ""),
    password: String(form.elements.password.value || ""),
    credential_vault_id: String(form.elements.credential_vault_id.value || ""),
    credential_entry_id: String(form.elements.credential_entry_id.value || ""),
  });
  const renderCandidates = () => {
    candidatesElement.replaceChildren();
    candidates.forEach((candidate) => {
      const label = document.createElement("label");
      label.className = "info-band";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.name = "candidate_ids";
      checkbox.value = candidate.candidate_id;
      checkbox.checked = true;
      const copy = document.createElement("span");
      copy.className = "vcf-helper-action-copy";
      copy.innerHTML = `<strong><code>${escapeHtml(candidate.key)}</code></strong><span class="muted">${escapeHtml(candidate.description || candidate.resource_name || "")}</span>`;
      label.append(checkbox, copy);
      candidatesElement.append(label);
    });
  };
  const inspectSource = async (controller) => {
    const response = await fetch("/vcf-helper/vault-import/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      cache: "no-store",
      body: JSON.stringify(requestPayload()),
    });
    const payload = await response.json().catch(() => ({}));
    if (response.status === 409 && payload.fingerprint) {
      observedFingerprint = payload.fingerprint;
      form.elements.confirmed_fingerprint.value = "";
      if (fingerprintHelp) fingerprintHelp.textContent = observedFingerprint;
      if (fingerprintConfirm instanceof HTMLInputElement) fingerprintConfirm.checked = false;
      controller.setError("");
      return "tls";
    }
    if (!response.ok) {
      controller.setError(payload.detail || "VCF password discovery failed.");
      return "error";
    }
    candidates = Array.isArray(payload.candidates) ? payload.candidates : [];
    if (!candidates.length) {
      controller.setError("The source returned no supported passwords.");
      return "error";
    }
    renderCandidates();
    return "ready";
  };
  const wizard = window.AtlasoUiPatterns.createWizard({
    dialog: modal,
    form,
    steps: [
      { id: "credential", title: "Choose a credential source", description: "Use a saved vault key or continue with a one-time manual login." },
      { id: "source", title: "Choose the VCF source", description: "Identify the appliance without sending or resolving credentials." },
      { id: "tls", title: "Verify the TLS fingerprint", description: "Confirm the observed SHA-256 fingerprint before Atlaso uses credentials." },
      { id: "credentials", title: "Authenticate to the source", description: "Credentials are used only for this discovery and reviewed import." },
      { id: "selection", title: "Choose passwords", description: "Select supported VCF and ESX password metadata to import." },
      { id: "review", title: "Review the import", description: "Choose the destination vault and confirm the selected count." },
    ],
    onOpen: () => {
      form.reset();
      form.elements.port.value = "443";
      form.elements.confirmed_fingerprint.value = "";
      observedFingerprint = "";
      if (fingerprintHelp) fingerprintHelp.textContent = "Not inspected yet";
      if (fingerprintConfirm instanceof HTMLInputElement) fingerprintConfirm.checked = false;
      candidates = [];
      candidatesElement?.replaceChildren();
    },
    onNext: async ({ controller, step }) => {
      if (step.id === "source") {
        form.elements.confirmed_fingerprint.value = "";
        const state = await inspectSource(controller);
        return state === "tls" ? "tls" : false;
      }
      if (step.id === "tls") {
        if (hasSelectedVcfVaultCredential(form)) {
          const state = await inspectSource(controller);
          return state === "ready" ? "selection" : state === "tls" ? "tls" : false;
        }
        return "credentials";
      }
      if (step.id === "credentials") {
        const state = await inspectSource(controller);
        return state === "ready" ? true : state === "tls" ? "tls" : false;
      }
      return true;
    },
    validateStep: ({ step }) => {
      if (step.id === "selection" && !form.querySelector('input[name="candidate_ids"]:checked')) {
        return { ok: false, message: "Select at least one password." };
      }
      return true;
    },
    prepareReview: () => {
      const source = form.querySelector("[data-vcf-vault-review-source]");
      const count = form.querySelector("[data-vcf-vault-review-count]");
      if (source) source.textContent = `${form.elements.source_type.selectedOptions[0]?.textContent || ""} · ${form.elements.address.value}`;
      if (count) count.textContent = String(form.querySelectorAll('input[name="candidate_ids"]:checked').length);
    },
    onSubmit: async () => {
      const payload = {
        ...requestPayload(),
        vault_id: Number(form.elements.vault_id.value || 0),
        candidate_ids: [...form.querySelectorAll('input[name="candidate_ids"]:checked')].map((input) => input.value),
      };
      const response = await fetch("/vcf-helper/vault-import", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        cache: "no-store",
        body: JSON.stringify(payload),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) return { ok: false, message: result.detail || "The password import failed." };
      wizard.markClean();
      window.location.assign(`/vaults#vault-panel-${result.vault_id}`);
      return { ok: true, close: false };
    },
    closeOnSubmit: false,
  });
  fingerprintConfirm?.addEventListener("change", () => {
    if (!(fingerprintConfirm instanceof HTMLInputElement)) return;
    form.elements.confirmed_fingerprint.value = fingerprintConfirm.checked ? observedFingerprint : "";
  });
  document.querySelectorAll("[data-vcf-vault-import-open]").forEach((button) => button.addEventListener("click", () => wizard.open({ launcher: button })));
}

async function networkBootRequest(url, options = {}) {
  const csrf = document.querySelector("input[name='csrf']")?.value || "";
  const isFormData = options.body instanceof FormData;
  const response = await fetch(url, {
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...(options.body && !isFormData ? { "Content-Type": "application/json" } : {}),
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || "The Network Boot request failed.");
  return payload;
}

function initializeNetworkBootWorkspace() {
  const workspace = document.querySelector("[data-network-boot-page-workspace]");
  const networkSlot = workspace?.querySelector("[data-network-boot-section-slot]");
  const kickstartsSlot = workspace?.querySelector("[data-network-boot-kickstarts-slot]");
  const staticRail = workspace?.querySelector("[data-network-boot-static-rail]");
  const networkSection = document.querySelector("[data-network-boot-section]");
  const tasksPanel = document.querySelector("[data-network-boot-tasks-panel]");
  const kickstartsSection = document.querySelector("[data-esxi-kickstarts-panel]");
  const bootService = document.querySelector("[data-network-boot-service-panel]");
  const legacyWorkspace = document.querySelector(".esxi-pxe-workspace");
  const legacyRail = legacyWorkspace?.querySelector(":scope > aside.side-stack");
  if (
    !(workspace instanceof HTMLElement)
    || !(networkSlot instanceof HTMLElement)
    || !(kickstartsSlot instanceof HTMLElement)
    || !(staticRail instanceof HTMLElement)
    || !(networkSection instanceof HTMLElement)
    || !(tasksPanel instanceof HTMLElement)
    || !(kickstartsSection instanceof HTMLElement)
    || !(bootService instanceof HTMLElement)
    || !(legacyWorkspace instanceof HTMLElement)
  ) return;

  networkSection.classList.remove("panel", "wide-panel");
  networkSection.classList.add("network-boot-inner-section");
  tasksPanel.classList.add("network-boot-inner-section");
  kickstartsSection.classList.remove("panel", "wide-panel");
  kickstartsSection.classList.add("network-boot-inner-section");
  networkSlot.append(networkSection);
  networkSlot.append(tasksPanel);
  kickstartsSlot.append(kickstartsSection);
  staticRail.append(bootService);
  Array.from(legacyRail?.children || []).forEach((panel) => staticRail.append(panel));
  legacyWorkspace.remove();

  const hashTarget = window.location.hash
    ? document.getElementById(window.location.hash.slice(1))
    : null;
  if (hashTarget instanceof HTMLElement && kickstartsSection.contains(hashTarget)) {
    const networkButton = workspace.querySelector('[data-tab-target="network-boot-primary-panel"]');
    const kickstartsButton = workspace.querySelector('[data-tab-target="network-boot-kickstarts-panel"]');
    networkButton?.classList.remove("active");
    networkButton?.setAttribute("aria-selected", "false");
    kickstartsButton?.classList.add("active");
    kickstartsButton?.setAttribute("aria-selected", "true");
    networkSlot.classList.remove("active");
    networkSlot.setAttribute("hidden", "");
    kickstartsSlot.classList.add("active");
    kickstartsSlot.removeAttribute("hidden");
  }
}

function initializeNetworkBootPage() {
  const hostsElement = document.getElementById("network-boot-discovered-table");
  const environmentsElement = document.getElementById("network-boot-environments-table");
  if (!(hostsElement instanceof HTMLElement) || !(environmentsElement instanceof HTMLElement)) return;
  const canWrite = hostsElement.dataset.canWrite === "true";
  const hostDialog = document.getElementById("network-boot-host-dialog");
  const detailElement = hostDialog?.querySelector("[data-network-boot-host-detail]");
  const uploadDialog = document.getElementById("network-boot-upload-dialog");
  const uploadForm = uploadDialog?.querySelector("[data-network-boot-upload-form]");
  const uploadLabel = uploadDialog?.querySelector("[data-network-boot-upload-label]");
  const uploadProgress = uploadDialog?.querySelector("[data-network-boot-upload-progress]");
  const uploadStatus = uploadDialog?.querySelector("[data-network-boot-upload-status]");
  const uploadSubmit = uploadDialog?.querySelector("[data-network-boot-upload-submit]");
  let selectedHost = null;
  const openHost = async (row) => {
    try {
      selectedHost = await networkBootRequest(`/api/v1/network-boot/hosts/${row.id}`);
      const history = await networkBootRequest(`/api/v1/network-boot/hosts/${row.id}/history`);
      if (detailElement) detailElement.textContent = JSON.stringify({ host: selectedHost, history }, null, 2);
      hostDialog?.showModal();
    } catch (error) {
      showTransientGridStatus(error instanceof Error ? error.message : "The inventory report could not be loaded.");
    }
  };
  window.AtlasoUiPatterns.createGrid({
    element: hostsElement,
    fallback: `#${hostsElement.dataset.fallbackId}`,
    pattern: "read-only",
    onOpenRow: openHost,
    emptyMessage: "No inventory reports received.",
    options: {
      data: JSON.parse(hostsElement.dataset.rows || "[]"),
      index: "id",
      height: "360px",
      columns: [
        { title: "UUID", field: "dmi_uuid", minWidth: 220, formatter: (cell) => escapeHtml(cell.getValue() || "MAC fallback") },
        { title: "MACs", field: "macs", minWidth: 190, formatter: (cell) => escapeHtml((cell.getValue() || []).join(", ")) },
        { title: "CPU", field: "cpu_model", minWidth: 180 },
        { title: "Memory", field: "total_memory_bytes", width: 120, formatter: (cell) => formatMonitorBytes(cell.getValue()) },
        { title: "Disks", field: "disk_count", width: 80, hozAlign: "right" },
        { title: "NICs", field: "interface_count", width: 75, hozAlign: "right" },
        { title: "Last seen", field: "last_seen_at", minWidth: 170 },
        { title: "Session", field: "session_state", width: 100 },
      ],
    },
  });
  hostDialog?.querySelector("[data-network-boot-host-close]")?.addEventListener("click", () => hostDialog.close());
  hostDialog?.querySelector("[data-network-boot-reboot]")?.addEventListener("click", async () => {
    if (!selectedHost) return;
    const confirmed = await requestConfirmation({
      title: "Reboot inventory session?",
      message: "Atlaso will deliver one audited reboot command to this host's live Inventory Linux session.",
      label: "Queue reboot",
    });
    if (!confirmed) return;
    await networkBootRequest(`/api/v1/network-boot/hosts/${selectedHost.id}/reboot`, { method: "POST" });
    hostDialog.close();
  });
  const persistEnvironmentState = async (row, enabled) => {
    const data = row.getData();
    const updated = await networkBootRequest(`/api/v1/network-boot/environments/${data.key}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled, desired_version: data.desired_version || "" }),
    });
    await row.update(updated);
    return updated;
  };
  const updateEnvironment = async (cell) => {
    const row = cell.getRow();
    const data = row.getData();
    try {
      await persistEnvironmentState(row, Boolean(data.enabled));
    } catch (error) {
      cell.restoreOldValue();
      showTransientGridStatus(error instanceof Error ? error.message : "Network Boot desired state could not be saved.");
    }
  };
  const toggleEnvironmentFromMenu = async (row) => {
    const data = row.getData();
    const enabled = !data.enabled;
    try {
      await persistEnvironmentState(row, enabled);
      showTransientGridStatus(`${data.label} ${enabled ? "enabled" : "disabled"} in pending desired state.`);
    } catch (error) {
      showTransientGridStatus(error instanceof Error ? error.message : "Network Boot desired state could not be saved.");
    }
  };
  const queueEnvironmentDownload = async (data) => {
    const confirmed = await requestConfirmation({
      title: `Download latest ${data.label}?`,
      message: "Atlaso will resolve, verify, and install one immutable upstream release. The active boot menu will not change.",
      label: "Queue download",
    });
    if (!confirmed) return;
    const queued = await networkBootRequest(`/api/v1/network-boot/environments/${data.key}/sync`, { method: "POST" });
    showTransientGridStatus(`Queued verified download task ${queued.job_id}.`);
  };
  const openEnvironmentUpload = (data) => {
    if (!(uploadDialog instanceof HTMLDialogElement) || !(uploadForm instanceof HTMLFormElement)) return;
    uploadForm.reset();
    uploadForm.elements.environment_key.value = data.key;
    if (uploadLabel) uploadLabel.textContent = data.label;
    if (uploadProgress instanceof HTMLProgressElement) {
      uploadProgress.hidden = true;
      uploadProgress.value = 0;
    }
    if (uploadStatus instanceof HTMLElement) {
      uploadStatus.dataset.state = "idle";
      uploadStatus.textContent = "Choose the matching upstream release asset.";
    }
    uploadDialog.showModal();
  };
  window.AtlasoUiPatterns.createGrid({
    element: environmentsElement,
    fallback: `#${environmentsElement.dataset.fallbackId}`,
    pattern: "direct-edit",
    emptyMessage: "The fixed Network Boot catalog is unavailable.",
    options: {
      data: JSON.parse(environmentsElement.dataset.rows || "[]"),
      index: "key",
      height: "360px",
      rowContextMenu: canWrite ? [
        {
          label: (component) => (component.getData().enabled ? "Disable" : "Enable"),
          disabled: (component) => {
            const data = component.getData();
            return !data.enabled && !(data.installed_versions || []).length;
          },
          action: async (_event, row) => {
            await toggleEnvironmentFromMenu(row);
          },
        },
        {
          label: "Download latest stable",
          action: async (_event, row) => {
            await queueEnvironmentDownload(row.getData());
          },
        },
        {
          label: "Upload release asset",
          action: (_event, row) => {
            openEnvironmentUpload(row.getData());
          },
        },
      ] : [],
      columns: [
        { title: "Environment", field: "label", minWidth: 180, frozen: true },
        { title: "Enabled", field: "enabled", width: 95, formatter: "tickCross", editor: canWrite ? "tickCross" : false, cellEdited: updateEnvironment },
        {
          title: "Desired version",
          field: "desired_version",
          minWidth: 150,
          editor: canWrite ? "list" : false,
          editorParams: (cell) => ({ values: Object.fromEntries((cell.getRow().getData().installed_versions || []).map((item) => [item.version, item.version])), clearable: true }),
          cellEdited: updateEnvironment,
        },
        {
          title: "Newest installed",
          field: "installed_versions",
          minWidth: 150,
          formatter: (cell) => escapeHtml(cell.getValue()?.[0]?.version || "Not installed"),
        },
        { title: "Active version", field: "active_version", minWidth: 140 },
        { title: "Ready", field: "ready", width: 85, formatter: "tickCross" },
        {
          title: "Source",
          field: "source_label",
          minWidth: 210,
          formatter: (cell) => {
            const data = cell.getRow().getData();
            const label = data.source_label || "Authoritative release page";
            try {
              const source = new URL(data.release_page);
              if (source.protocol !== "https:") return escapeHtml(label);
              const url = source.toString();
              return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(url)}">${escapeHtml(label)}</a>`;
            } catch {
              return escapeHtml(label);
            }
          },
        },
        { title: "Verification", field: "verification_method", minWidth: 220 },
        { title: "Risk", field: "risk", minWidth: 240 },
      ],
    },
  });
  uploadDialog?.querySelector("[data-network-boot-upload-close]")?.addEventListener("click", () => uploadDialog.close());
  uploadForm?.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!(uploadForm instanceof HTMLFormElement) || !(uploadDialog instanceof HTMLDialogElement)) return;
    const fileInput = uploadForm.elements.artifact;
    const environmentKey = uploadForm.elements.environment_key.value;
    if (!(fileInput instanceof HTMLInputElement) || !fileInput.files?.length || !environmentKey) {
      if (uploadStatus instanceof HTMLElement) {
        uploadStatus.dataset.state = "error";
        uploadStatus.textContent = "Choose a boot media file before uploading.";
      }
      return;
    }
    const file = fileInput.files[0];
    const body = new FormData(uploadForm);
    const request = new XMLHttpRequest();
    request.open("POST", `/api/v1/network-boot/environments/${environmentKey}/upload`);
    request.setRequestHeader("Accept", "application/json");
    const csrf = document.querySelector("input[name='csrf']")?.value || "";
    if (csrf) request.setRequestHeader("X-CSRF-Token", csrf);
    request.upload.addEventListener("loadstart", () => {
      if (uploadProgress instanceof HTMLProgressElement) {
        uploadProgress.hidden = false;
        uploadProgress.value = 0;
      }
      if (uploadSubmit instanceof HTMLButtonElement) uploadSubmit.disabled = true;
      if (uploadStatus instanceof HTMLElement) {
        uploadStatus.dataset.state = "saving";
        uploadStatus.textContent = `Uploading ${file.name}...`;
      }
    });
    request.upload.addEventListener("progress", (progressEvent) => {
      if (!(uploadProgress instanceof HTMLProgressElement) || !progressEvent.lengthComputable) return;
      const percent = Math.max(0, Math.min(100, Math.round((progressEvent.loaded / progressEvent.total) * 100)));
      uploadProgress.value = percent;
      if (uploadStatus instanceof HTMLElement) uploadStatus.textContent = `Uploading ${file.name}: ${percent}%`;
    });
    request.addEventListener("load", () => {
      let payload = {};
      try {
        payload = JSON.parse(request.responseText || "{}");
      } catch (_error) {
        payload = {};
      }
      if (request.status >= 200 && request.status < 300) {
        if (uploadStatus instanceof HTMLElement) {
          uploadStatus.dataset.state = "saved";
          uploadStatus.textContent = `Queued verification task ${payload.job_id}. You can close this dialog and follow it on Tasks.`;
        }
        return;
      }
      if (uploadStatus instanceof HTMLElement) {
        uploadStatus.dataset.state = "error";
        uploadStatus.textContent = payload.detail || `Upload failed with HTTP ${request.status}.`;
      }
    });
    request.addEventListener("error", () => {
      if (uploadStatus instanceof HTMLElement) {
        uploadStatus.dataset.state = "error";
        uploadStatus.textContent = "Upload failed before Atlaso received the file.";
      }
    });
    request.addEventListener("loadend", () => {
      if (uploadSubmit instanceof HTMLButtonElement) uploadSubmit.disabled = false;
    });
    request.send(body);
  });
  const promoteDialog = document.getElementById("network-boot-promote-dialog");
  const promoteForm = promoteDialog?.querySelector("[data-network-boot-promote-form]");
  if (!(promoteDialog instanceof HTMLDialogElement) || !(promoteForm instanceof HTMLFormElement)) return;
  const promoteWizard = window.AtlasoUiPatterns.createWizard({
    form: promoteForm,
    dialog: promoteDialog,
    steps: [
      { id: "identity", title: "Review host identity", description: "Choose the explicit ESXi hostname, discovered MAC, and address." },
      { id: "installer", title: "Choose installer inputs", description: "Select the Kickstart, installer ISO, and reviewed variables." },
      { id: "enablement", title: "Choose desired-state enablement", description: "Enabled is reviewed last before the summary." },
      { id: "review", title: "Review ESXi promotion", description: "Promotion creates desired state only and does not run appliance apply." },
    ],
    validateStep: validateAtlasoWizardStep,
    onOpen: ({ context }) => {
      if (!context) return;
      promoteForm.elements.host_id.value = context.id;
      promoteForm.elements.hostname.value = context.product_name
        ? context.product_name.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-|-$/g, "")
        : "";
      promoteForm.elements.mac_address.replaceChildren(...context.macs.map((mac) => new Option(mac, mac)));
      const assignedAddress = context.latest_report?.assigned_addresses?.[0] || "";
      promoteForm.elements.ip_address.value = assignedAddress.split("/")[0];
    },
    prepareReview: () => renderAtlasoWizardReview(promoteForm, [
      { label: "Hostname", field: "hostname" }, { label: "MAC", field: "mac_address" },
      { label: "Address", field: "ip_address" }, { label: "Kickstart", field: "kickstart_id" },
      { label: "Installer ISO", field: "installer_iso_path" }, { label: "Enabled", field: "enabled" },
    ]),
    onSubmit: async () => {
      let variables;
      try { variables = JSON.parse(promoteForm.elements.variables.value || "{}"); } catch { return { ok: false, message: "Variables must be a JSON object." }; }
      await networkBootRequest(`/api/v1/network-boot/hosts/${promoteForm.elements.host_id.value}/promote`, {
        method: "POST",
        body: JSON.stringify({
          hostname: promoteForm.elements.hostname.value,
          mac_address: promoteForm.elements.mac_address.value,
          ip_address: promoteForm.elements.ip_address.value,
          kickstart_id: promoteForm.elements.kickstart_id.value,
          installer_iso_path: promoteForm.elements.installer_iso_path.value,
          variables,
          enabled: promoteForm.elements.enabled.checked,
        }),
      });
      window.location.reload();
      return { ok: true };
    },
  });
  hostDialog?.querySelector("[data-network-boot-promote-open]")?.addEventListener("click", (event) => {
    if (!selectedHost) return;
    hostDialog.close();
    promoteWizard.open({ launcher: event.currentTarget, context: selectedHost });
  });
}

document.addEventListener("DOMContentLoaded", initializeDashboard);
document.addEventListener("DOMContentLoaded", initializeNetworkBootWorkspace);
document.addEventListener("DOMContentLoaded", initializeNetworkBootPage);
document.addEventListener("DOMContentLoaded", initializeVaultsPage);
document.addEventListener("DOMContentLoaded", initializeVcfVaultCredentialPickers);
document.addEventListener("DOMContentLoaded", initializeVcfVaultImport);
document.addEventListener("DOMContentLoaded", initializeEsxStorageTables);
document.addEventListener("DOMContentLoaded", initializeEsxStorageWizards);
document.addEventListener("DOMContentLoaded", initializeEsxStorageFamilyDefaults);
document.addEventListener("DOMContentLoaded", initializeEsxStorageVolumeSource);
document.addEventListener("DOMContentLoaded", initializeDnsRecordsTable);
document.addEventListener("DOMContentLoaded", initializeDnsDomainWizard);
document.addEventListener("DOMContentLoaded", initializeDhcpScopesTable);
document.addEventListener("DOMContentLoaded", initializeDhcpOptionsTable);
document.addEventListener("DOMContentLoaded", initializeDhcpReservationsTable);
document.addEventListener("DOMContentLoaded", initializeDhcpLeasesTable);
document.addEventListener("DOMContentLoaded", initializeDhcpLeaseReservationActions);
document.addEventListener("DOMContentLoaded", initializeEsxiPxeHostsTable);
document.addEventListener("DOMContentLoaded", initializeEsxiInstallerIsosTable);
document.addEventListener("DOMContentLoaded", initializeEsxiPxePreviewTable);
document.addEventListener("DOMContentLoaded", initializeEsxiCustomVariablesTable);
document.addEventListener("DOMContentLoaded", initializeCaProfilesTable);
document.addEventListener("DOMContentLoaded", initializeCaCertificatesTable);
document.addEventListener("DOMContentLoaded", () => initializeCaSettings());
document.addEventListener("DOMContentLoaded", initializeCaCsrWizard);
document.addEventListener("DOMContentLoaded", initializeKmsClientsTable);
document.addEventListener("DOMContentLoaded", initializeKmsKeysTable);
document.addEventListener("DOMContentLoaded", () => initializeKmsSettings());
document.addEventListener("DOMContentLoaded", initializeLdapOrganizationWizard);
document.addEventListener("DOMContentLoaded", initializeLdapPageState);
document.addEventListener("DOMContentLoaded", initializeLdapDirectoryTables);
document.addEventListener("DOMContentLoaded", initializeLdapPasswordModal);
document.addEventListener("DOMContentLoaded", initializeLdapBindSecretModal);
document.addEventListener("DOMContentLoaded", initializeAutomationTables);
document.addEventListener("DOMContentLoaded", initializeManagedPackagePolicies);
document.addEventListener("DOMContentLoaded", initializeApplianceUpdateSourceWizard);
document.addEventListener("DOMContentLoaded", initializeManagedPackageWizard);
document.addEventListener("DOMContentLoaded", () => initializeNtpSettings());
document.addEventListener("DOMContentLoaded", initializeNTPsecUpstreamsTable);
document.addEventListener("DOMContentLoaded", initializeNTPsecSourceHealthModal);
document.addEventListener("DOMContentLoaded", initializeVcfRegistryBundlesTable);
document.addEventListener("DOMContentLoaded", initializeVcfDepotProfilesTable);
document.addEventListener("DOMContentLoaded", initializeVcfDepotTasksTable);
document.addEventListener("DOMContentLoaded", initializeVcfDepotTaskLogModal);
document.addEventListener("DOMContentLoaded", initializeTasksPage);
document.addEventListener("DOMContentLoaded", initializeApplianceUpdateSubmission);
document.addEventListener("DOMContentLoaded", initializeServerTime);
document.addEventListener("DOMContentLoaded", initializeFirewallRulesTable);
document.addEventListener("DOMContentLoaded", initializeManagedFirewallRulesTable);
document.addEventListener("DOMContentLoaded", initializeFirewallSourceGroupManager);
document.addEventListener("DOMContentLoaded", initializeServicesTable);
document.addEventListener("DOMContentLoaded", initializeUsersTable);
document.addEventListener("DOMContentLoaded", initializeUserPasswordForm);
document.addEventListener("DOMContentLoaded", initializeRoutesWanRoutesTable);
document.addEventListener("DOMContentLoaded", initializeRoutesWanRoutingTable);
document.addEventListener("DOMContentLoaded", initializeRoutesWanNatTable);
document.addEventListener("DOMContentLoaded", initializeRoutesWanPoliciesTable);
document.addEventListener("DOMContentLoaded", initializePhysicalInterfacesTable);
document.addEventListener("DOMContentLoaded", initializeApiTokensTable);
document.addEventListener("DOMContentLoaded", () => initializeOidcProviderSettings());
document.addEventListener("DOMContentLoaded", initializeOidcClientsTable);
document.addEventListener("DOMContentLoaded", initializeOidcKeysTable);
document.addEventListener("DOMContentLoaded", initializeOidcGroupMappingsTable);
document.addEventListener("DOMContentLoaded", initializeOidcSubjectsTable);
document.addEventListener("DOMContentLoaded", initializeVlanInterfacesTable);
document.addEventListener("DOMContentLoaded", initializeMonacoEditors);
document.addEventListener("DOMContentLoaded", initializeKickstartCollection);
document.addEventListener("DOMContentLoaded", initializeHostsFileEditor);
document.addEventListener("DOMContentLoaded", initializeZoneEditors);
document.addEventListener("DOMContentLoaded", initializeAccountMenu);
document.addEventListener("DOMContentLoaded", initializeConfirmationModals);
document.addEventListener("DOMContentLoaded", initializePreviewModalControls);
document.addEventListener("DOMContentLoaded", () => initializeCopyValueButtons());
document.addEventListener("DOMContentLoaded", () => initializeDownloadValueButtons());
document.addEventListener("DOMContentLoaded", initializeNonTabbableHelperControls);
document.addEventListener("DOMContentLoaded", initializeSecretToggles);
document.addEventListener("DOMContentLoaded", () => initializeSwitchFields());
document.addEventListener("DOMContentLoaded", () => initializeAutosaveForms());
document.addEventListener("DOMContentLoaded", initializeApplianceSettings);
document.addEventListener("DOMContentLoaded", () => initializeFirewallSettings());
document.addEventListener("DOMContentLoaded", () => initializeDnsSettings());
document.addEventListener("DOMContentLoaded", initializeVcfFqdnGenerator);
document.addEventListener("DOMContentLoaded", initializeVcfTrustForm);
document.addEventListener("DOMContentLoaded", initializeVcfSddcDeployment);
document.addEventListener("DOMContentLoaded", initializeVcfTargetDepotHelper);
document.addEventListener("DOMContentLoaded", initializeVcfLdapHelper);
document.addEventListener("DOMContentLoaded", () => initializeVcfBackupSettings());
document.addEventListener("DOMContentLoaded", () => initializeVcfRegistrySettings());
document.addEventListener("DOMContentLoaded", () => initializeVcfDepotSettings());
document.addEventListener("DOMContentLoaded", initializeVcfDepotSoftwareDepotIdGenerator);
document.addEventListener("DOMContentLoaded", initializeVcfDepotToolResetModal);
document.addEventListener("DOMContentLoaded", initializeVcfDepotTokenPaste);
document.addEventListener("DOMContentLoaded", initializeVcfDepotActivationPaste);
document.addEventListener("DOMContentLoaded", initializeVcfDepotCredentialsPaste);
document.addEventListener("DOMContentLoaded", initializeVcfDepotPropertiesEditor);
document.addEventListener("DOMContentLoaded", initializeFileUploadControls);
document.addEventListener("DOMContentLoaded", initializeEsxiIsoUploadForms);
document.addEventListener("DOMContentLoaded", () => initializeTagEditors());
document.addEventListener("DOMContentLoaded", () => initializeServiceBindEditors());
document.addEventListener("DOMContentLoaded", initializeTabs);
document.addEventListener("DOMContentLoaded", initializeLogsPage);
document.addEventListener("DOMContentLoaded", initializeAuditEventsTable);
document.addEventListener("DOMContentLoaded", initializeApplianceApplyProgress);
document.addEventListener("DOMContentLoaded", initializeMonitorPage);
document.addEventListener("DOMContentLoaded", initializeHistoryBackButtons);
document.addEventListener("DOMContentLoaded", initializePublicAddressModeToggle);
document.addEventListener("DOMContentLoaded", () => {
  registerAtlasoPrismLanguages();
  highlightConfigPreviews();
});

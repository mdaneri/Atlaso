import * as monaco from "monaco-editor/esm/vs/editor/editor.api";
import "monaco-editor/esm/vs/editor/editor.all.js";
import "monaco-editor/esm/vs/basic-languages/python/python.contribution";
import "monaco-editor/esm/vs/basic-languages/shell/shell.contribution";
import "monaco-editor/esm/vs/basic-languages/powershell/powershell.contribution";
import "monaco-editor/esm/vs/basic-languages/ini/ini.contribution";

const KICKSTART_VARIABLES = [
  ["host.hostname", "Assigned ESXi host name"],
  ["host.mac", "Assigned ESXi host MAC address"],
  ["host.ip_address", "Assigned ESXi host IP address"],
  ["dhcp.gateway", "DHCP gateway"],
  ["dhcp.netmask", "DHCP IPv4 netmask"],
  ["dhcp.prefix", "DHCP prefix length"],
  ["dhcp.dns_servers", "DHCP DNS server list"],
  ["dhcp.ntp_servers", "DHCP NTP server list"],
  ["dhcp.domain", "DHCP domain"],
  ["pxe.http_base_url", "ESXi PXE HTTP base URL"],
];

const languageDefinitions = {
  "atlaso-hosts": {
    tokenizer: {
      root: [
        [/^\s*#.*$/, "comment"],
        [/(?:\d{1,3}\.){3}\d{1,3}\b/, "number"],
        [/(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*\b/, "number"],
        [/[A-Za-z0-9_.:-]+/, "variable"],
      ],
    },
  },
  "atlaso-zone": {
    ignoreCase: true,
    tokenizer: {
      root: [
        [/;.*/, "comment"],
        [/\$(?:ORIGIN|TTL|INCLUDE|GENERATE)\b/, "keyword"],
        [/\bIN\b/, "keyword"],
        [/\b(?:A|AAAA|CNAME|MX|NS|PTR|SOA|SRV|TXT|CAA)\b/, "type"],
        [/(?:\d{1,3}\.){3}\d{1,3}\b/, "number"],
        [/(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*\b/, "number"],
        [/\d+/, "number"],
        [/"(?:\\.|[^"\\])*"/, "string"],
        [/[A-Za-z0-9_.:-]+/, "variable"],
      ],
    },
  },
  "atlaso-kickstart": {
    tokenizer: {
      root: [
        [/^\s*#.*$/, "comment"],
        [/\{\{[^}]*\}\}/, "variable.predefined"],
        [/^%(?:pre|post|firstboot|packages|include|end)\b.*/, "keyword"],
        [/^(?:acceptance|accepteula|autopart|bootloader|clearpart|dryrun|install|keyboard|network|paranoid|part|reboot|rootpw|serialnum|upgrade|vmaccepteula)\b/, "keyword"],
        [/--[A-Za-z0-9-]+(?==|\s|$)/, "attribute.name"],
        [/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/, "string"],
        [/\b\d+(?:\.\d+)?\b/, "number"],
      ],
    },
  },
};

for (const [id, monarch] of Object.entries(languageDefinitions)) {
  monaco.languages.register({ id });
  monaco.languages.setMonarchTokensProvider(id, monarch);
}

const modelCompletions = new Map();
monaco.languages.registerCompletionItemProvider("atlaso-kickstart", {
  triggerCharacters: ["{"],
  provideCompletionItems(model, position) {
    const linePrefix = model.getLineContent(position.lineNumber).slice(0, position.column - 1);
    const markerStart = linePrefix.lastIndexOf("{{");
    if (markerStart < 0 || linePrefix.slice(markerStart + 2).includes("}}")) return { suggestions: [] };
    const range = {
      startLineNumber: position.lineNumber,
      endLineNumber: position.lineNumber,
      startColumn: markerStart + 3,
      endColumn: position.column,
    };
    return {
      suggestions: [...KICKSTART_VARIABLES, ...(modelCompletions.get(model.uri.toString()) || [])].map(([label, detail]) => ({
        label,
        detail,
        documentation: detail,
        kind: monaco.languages.CompletionItemKind.Variable,
        insertText: `${label}}}`,
        range,
        sortText: label.startsWith("vault.") ? `2-${label}` : `1-${label}`,
      })),
    };
  },
});

function updateTextarea(textarea, value) {
  textarea.value = value;
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
}

function editorLanguage(textarea, options = {}) {
  return options.language || textarea.dataset.monacoLanguage || "plaintext";
}

function enhanceTextarea(textarea, options = {}) {
  if (!(textarea instanceof HTMLTextAreaElement) || textarea.atlasoMonacoEditor) {
    return textarea?.atlasoMonacoEditor || null;
  }
  const minimumHeight = Math.max((textarea.rows || 8) * 18 + 22, 140);
  const shell = document.createElement("div");
  shell.className = "atlaso-monaco-shell";
  const toolbar = document.createElement("div");
  toolbar.className = "atlaso-monaco-toolbar";
  const expandButton = document.createElement("button");
  expandButton.className = "atlaso-monaco-expand-button";
  expandButton.type = "button";
  expandButton.textContent = "⛶";
  expandButton.setAttribute("aria-label", "Expand editor");
  expandButton.title = "Expand editor";
  expandButton.setAttribute("aria-pressed", "false");
  toolbar.append(expandButton);
  const container = document.createElement("div");
  container.className = "atlaso-monaco-editor";
  container.style.minHeight = `${minimumHeight}px`;
  container.style.height = `${minimumHeight}px`;
  shell.append(toolbar, container);
  textarea.classList.add("monaco-source-textarea");
  textarea.hidden = true;
  textarea.insertAdjacentElement("afterend", shell);

  const editor = monaco.editor.create(container, {
    value: textarea.value,
    language: editorLanguage(textarea, options),
    theme: "vs",
    automaticLayout: true,
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, 'Liberation Mono', monospace",
    fontSize: 12,
    lineHeight: 18,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    renderWhitespace: "selection",
    folding: true,
    glyphMargin: false,
    lineNumbersMinChars: 3,
    padding: { top: 7, bottom: 7 },
    accessibilitySupport: "auto",
    tabSize: 2,
  });
  const hostDialog = shell.closest("dialog");
  const setExpanded = (expanded, { restoreFocus = false } = {}) => {
    document.querySelectorAll(".atlaso-monaco-shell.is-expanded").forEach((other) => {
      if (other !== shell) other.atlasoMonacoRestore?.();
    });
    shell.classList.toggle("is-expanded", expanded);
    hostDialog?.classList.toggle("has-expanded-monaco", expanded);
    document.body.classList.toggle("atlaso-monaco-expanded-open", expanded);
    expandButton.textContent = expanded ? "⤢" : "⛶";
    expandButton.setAttribute("aria-label", expanded ? "Restore editor" : "Expand editor");
    expandButton.title = expandButton.getAttribute("aria-label");
    expandButton.setAttribute("aria-pressed", String(expanded));
    requestAnimationFrame(() => editor.layout());
    if (restoreFocus) expandButton.focus();
  };
  shell.atlasoMonacoRestore = () => setExpanded(false, { restoreFocus: true });
  expandButton.addEventListener("click", () => {
    setExpanded(!shell.classList.contains("is-expanded"));
  });
  document.addEventListener("keydown", (event) => {
    if (
      event.key === "Escape"
      && shell.classList.contains("is-expanded")
      && !document.querySelector(".suggest-widget.visible")
    ) {
      event.preventDefault();
      setExpanded(false, { restoreFocus: true });
    }
  });
  if (editorLanguage(textarea, options) === "atlaso-kickstart") {
    let completions = options.completions;
    if (!Array.isArray(completions) && textarea.dataset.monacoCompletions) {
      try { completions = JSON.parse(textarea.dataset.monacoCompletions); } catch (_error) { completions = []; }
    }
    modelCompletions.set(editor.getModel().uri.toString(), Array.isArray(completions) ? completions : []);
  }
  editor.onDidChangeModelContent(() => updateTextarea(textarea, editor.getValue()));
  textarea.atlasoMonacoEditor = editor;
  textarea.atlasoMonacoContainer = container;
  textarea.atlasoMonacoShell = shell;
  return editor;
}

function setValue(textarea, value) {
  if (!(textarea instanceof HTMLTextAreaElement)) return;
  const editor = textarea.atlasoMonacoEditor;
  if (editor) editor.setValue(value);
  else updateTextarea(textarea, value);
}

function getValue(textarea) {
  if (!(textarea instanceof HTMLTextAreaElement)) return "";
  return textarea.atlasoMonacoEditor?.getValue() ?? textarea.value;
}

function setLanguage(textarea, language) {
  if (!(textarea instanceof HTMLTextAreaElement)) return;
  textarea.dataset.monacoLanguage = language;
  const model = textarea.atlasoMonacoEditor?.getModel();
  if (model) monaco.editor.setModelLanguage(model, language);
}

function focus(textarea) {
  const editor = textarea?.atlasoMonacoEditor;
  if (editor) editor.focus();
  else if (textarea instanceof HTMLTextAreaElement) textarea.focus();
}

window.MonacoEnvironment = {
  getWorker() {
    return new Worker("/static/vendor/monaco/editor.worker.js?v=atlaso-monaco-20260729-3");
  },
};
window.AtlasoMonaco = { enhanceTextarea, focus, getValue, setLanguage, setValue };

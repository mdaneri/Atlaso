import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import {
  HighlightStyle,
  StreamLanguage,
  bracketMatching,
  foldGutter,
  indentOnInput,
  syntaxHighlighting,
} from "@codemirror/language";
import { powerShell } from "@codemirror/legacy-modes/mode/powershell";
import { python } from "@codemirror/legacy-modes/mode/python";
import { shell } from "@codemirror/legacy-modes/mode/shell";
import { Compartment, EditorState } from "@codemirror/state";
import {
  EditorView,
  crosshairCursor,
  drawSelection,
  dropCursor,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
  rectangularSelection,
} from "@codemirror/view";
import { tags } from "@lezer/highlight";

const hostToken = /^[A-Za-z0-9_.:-]+/;
const ipv4Token = /^(?:\d{1,3}\.){3}\d{1,3}\b/;
const ipv6Token = /^(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*\b/;

const atlasoHosts = StreamLanguage.define({
  name: "atlaso-hosts",
  token(stream) {
    if (stream.sol() && stream.match(/\s*#.*/)) return "comment";
    if (stream.eatSpace()) return null;
    if (stream.match(ipv4Token) || stream.match(ipv6Token)) return "number";
    if (stream.match(hostToken)) return "variableName";
    stream.next();
    return null;
  },
});

const atlasoZone = StreamLanguage.define({
  name: "atlaso-zone",
  token(stream) {
    if (stream.match(/;.*/)) return "comment";
    if (stream.eatSpace()) return null;
    if (stream.match(/^\$(?:ORIGIN|TTL|INCLUDE|GENERATE)\b/i) || stream.match(/^IN\b/i)) return "keyword";
    if (stream.match(/^(?:A|AAAA|CNAME|MX|NS|PTR|SOA|SRV|TXT|CAA)\b/i)) return "atom";
    if (stream.match(ipv4Token) || stream.match(ipv6Token) || stream.match(/^\d+\b/)) return "number";
    if (stream.match(/^"(?:\\.|[^"\\])*"/)) return "string";
    if (stream.match(hostToken)) return "variableName";
    stream.next();
    return null;
  },
});

const languageModes = {
  "atlaso-hosts": atlasoHosts,
  "atlaso-zone": atlasoZone,
  shell: StreamLanguage.define(shell),
  powershell: StreamLanguage.define(powerShell),
  python: StreamLanguage.define(python),
};

const highlightStyle = HighlightStyle.define([
  { tag: tags.comment, color: "#64748b", fontStyle: "italic" },
  { tag: [tags.keyword, tags.modifier], color: "#7c3aed", fontWeight: "700" },
  { tag: [tags.atom, tags.bool, tags.null], color: "#0f766e", fontWeight: "700" },
  { tag: tags.number, color: "#b45309" },
  { tag: [tags.string, tags.regexp], color: "#15803d" },
  { tag: [tags.variableName, tags.propertyName], color: "#1d4ed8" },
  { tag: [tags.function(tags.variableName), tags.definition(tags.variableName)], color: "#0369a1" },
  { tag: [tags.typeName, tags.className], color: "#be123c" },
  { tag: [tags.operator, tags.punctuation], color: "#475569" },
]);

const editorTheme = EditorView.theme({
  "&": {
    minHeight: "160px",
    border: "1px solid #cbd5e1",
    borderRadius: "6px",
    backgroundColor: "#f8fafc",
    color: "#111827",
    fontSize: "12px",
  },
  "&.cm-focused": {
    outline: "none",
    borderColor: "#2563eb",
    boxShadow: "0 0 0 3px rgba(37, 99, 235, 0.16)",
  },
  ".cm-scroller": {
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, 'Liberation Mono', monospace",
    lineHeight: "1.45",
  },
  ".cm-content": { padding: "7px 10px", minHeight: "inherit" },
  ".cm-line": { padding: "0 4px" },
  ".cm-gutters": { backgroundColor: "#eef2f7", color: "#64748b", borderRight: "1px solid #dbe3ef" },
  ".cm-activeLine": { backgroundColor: "rgba(37, 99, 235, 0.08)" },
  ".cm-activeLineGutter": { backgroundColor: "rgba(37, 99, 235, 0.12)", color: "#1d4ed8" },
  ".cm-selectionBackground, &.cm-focused .cm-selectionBackground": {
    backgroundColor: "rgba(37, 99, 235, 0.22)",
  },
});

function languageExtension(name) {
  return languageModes[name] || atlasoHosts;
}

function updateTextarea(textarea, value) {
  textarea.value = value;
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
}

function enhanceTextarea(textarea, options = {}) {
  if (!(textarea instanceof HTMLTextAreaElement) || textarea.atlasoCodeMirrorView) {
    return textarea?.atlasoCodeMirrorView || null;
  }
  const language = options.language || textarea.dataset.codemirrorLanguage || "atlaso-hosts";
  const minimumHeight = textarea.rows ? `${Math.max(textarea.rows * 18 + 22, 120)}px` : "160px";
  const languageCompartment = new Compartment();
  const updateListener = EditorView.updateListener.of((update) => {
    if (update.docChanged) updateTextarea(textarea, update.state.doc.toString());
  });
  const view = new EditorView({
    state: EditorState.create({
      doc: textarea.value,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightSpecialChars(),
        history(),
        foldGutter(),
        drawSelection(),
        dropCursor(),
        EditorState.allowMultipleSelections.of(true),
        indentOnInput(),
        bracketMatching(),
        rectangularSelection(),
        crosshairCursor(),
        highlightActiveLine(),
        languageCompartment.of(languageExtension(language)),
        syntaxHighlighting(highlightStyle),
        keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
        editorTheme,
        EditorView.theme({
          "&": { minHeight: minimumHeight },
          ".cm-content": { minHeight: minimumHeight },
        }),
        updateListener,
      ],
    }),
  });
  textarea.classList.add("codemirror-source-textarea");
  textarea.hidden = true;
  textarea.insertAdjacentElement("afterend", view.dom);
  textarea.atlasoCodeMirrorView = view;
  textarea.atlasoCodeMirrorLanguageCompartment = languageCompartment;
  return view;
}

function setValue(textarea, value) {
  if (!(textarea instanceof HTMLTextAreaElement)) return;
  const view = textarea.atlasoCodeMirrorView;
  if (!view) {
    updateTextarea(textarea, value);
    return;
  }
  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: value } });
}

function setLanguage(textarea, language) {
  if (!(textarea instanceof HTMLTextAreaElement)) return;
  textarea.dataset.codemirrorLanguage = language;
  const view = textarea.atlasoCodeMirrorView;
  const compartment = textarea.atlasoCodeMirrorLanguageCompartment;
  if (view && compartment) {
    view.dispatch({ effects: compartment.reconfigure(languageExtension(language)) });
  }
}

function focus(textarea) {
  const view = textarea?.atlasoCodeMirrorView;
  if (view) view.focus();
  else if (textarea instanceof HTMLTextAreaElement) textarea.focus();
}

window.AtlasoCodeMirror = { enhanceTextarea, focus, setLanguage, setValue };

/* One owned request and timer per visible log viewer. */
(() => {
  "use strict";

  function create({ output, status, controls, fetchPage, active = () => true, onPage = () => {},
    pageText = (page) => String(page.text || ""), renderPage = null, holdPage = () => false, initialCursor = "" }) {
    let closed = false;
    let request = null;
    let timer = null;
    let cursor = initialCursor;
    let nextCursor = "";
    let previousCursor = "";
    let hasMore = false;
    let following = true;
    let failures = 0;
    let terminalReads = 0;
    let previous = [];
    let generation = 0;
    let rendered = null;
    let rendering = null;
    const scroll = ["auto", "scroll"].includes(window.getComputedStyle?.(output)?.overflowY) ? output : output.parentElement;
    const buttons = {};
    const button = (name, label, action) => {
      const element = document.createElement("button");
      element.type = "button";
      element.className = "button ghost";
      element.textContent = label;
      element.addEventListener("click", action);
      controls?.append(element);
      buttons[name] = element;
    };
    const schedule = (delay) => {
      window.clearTimeout(timer);
      if (!closed) timer = window.setTimeout(refresh, delay);
    };
    const selected = () => {
      const selection = window.getSelection();
      return Boolean(selection && !selection.isCollapsed &&
        (output.contains(selection.anchorNode) || output.contains(selection.focusNode)));
    };
    const atBottom = () => !scroll || scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 32;
    const message = (text) => { if (status) status.textContent = text; };
    const updateButtons = () => {
      if (buttons.previous) buttons.previous.disabled = previous.length === 0 && !previousCursor;
      if (buttons.next) buttons.next.disabled = !hasMore;
      if (buttons.follow) buttons.follow.setAttribute("aria-pressed", String(following));
    };
    const navigate = (position, reset = false) => {
      generation += 1;
      request?.abort();
      request = null;
      cursor = position;
      if (reset) previous = [];
      rendered = null;
      terminalReads = 0;
      schedule(0);
    };
    button("first", "From beginning", () => { following = false; navigate("", true); });
    button("previous", "Previous page", () => {
      if (previous.length || previousCursor) { following = false; navigate(previous.pop() || previousCursor); }
    });
    button("next", "Next page", () => {
      if (hasMore) { following = false; previous.push(cursor); navigate(nextCursor); }
    });
    button("follow", "Follow live", () => {
      following = true;
      terminalReads = 0;
      if (following && initialCursor) navigate(initialCursor, true);
      if (following && scroll) scroll.scrollTop = scroll.scrollHeight;
      updateButtons();
      schedule(0);
    });

    async function refresh() {
      if (closed || request) return;
      if (document.hidden || !active()) { schedule(5000); return; }
      const controller = new AbortController();
      const sequence = generation;
      request = controller;
      const deadline = window.setTimeout(() => controller.abort(), 20000);
      try {
        const page = await fetchPage(cursor, controller.signal);
        if (rendering) await rendering.catch(() => {});
        if (closed || generation !== sequence || !active()) return;
        failures = 0;
        hasMore = Boolean(page.has_more);
        nextCursor = page.next_cursor || "";
        previousCursor = page.previous_cursor || "";
        cursor = page.cursor || cursor;
        const text = pageText(page);
        const bottom = atBottom();
        const held = rendered !== null && (selected() || !bottom || holdPage());
        if (text !== rendered && !held) {
          const navigated = rendered === null;
          const offset = navigated ? 0 : scroll?.scrollTop || 0;
          if (renderPage) {
            const pendingRender = Promise.resolve(renderPage(page, { following, navigated: rendered === null,
              isCurrent: () => !closed && generation === sequence && active() }));
            rendering = pendingRender;
            try { await pendingRender; }
            finally { if (rendering === pendingRender) rendering = null; }
            if (closed || generation !== sequence || !active()) return;
          } else if (rendered && text.startsWith(rendered)) {
            output.append(document.createTextNode(text.slice(rendered.length)));
          } else {
            output.textContent = text || "No log entries yet.";
          }
          rendered = text;
          if (!renderPage && typeof window.highlightConfigPreviewElement === "function") {
            window.highlightConfigPreviewElement(output);
          }
          if (scroll) scroll.scrollTop = following && (bottom || navigated) ? scroll.scrollHeight : offset;
        }
        onPage(page);
        if (closed || generation !== sequence || !active()) return;
        message(held && text !== rendered ? "New output available · reading position preserved" :
          `${page.job_id ? `${page.job_id} · ` : ""}${page.status || "Updated"} · ${new Date().toLocaleTimeString()}${page.notice ? ` · ${page.notice}` : ""}`);
        updateButtons();
        const terminal = ["succeeded", "failed", "cancelled", "skipped"].includes(page.status);
        terminalReads = terminal && !hasMore ? terminalReads + 1 : 0;
        if (page.reset) previous = [];
        if (following && hasMore && !held && nextCursor !== cursor) {
          previous.push(cursor);
          cursor = nextCursor;
          rendered = null;
          schedule(250);
        } else if (terminalReads < 2 || hasMore) {
          schedule(5000);
        }
      } catch (error) {
        if (closed || generation !== sequence) return;
        const revoked = error?.status === 401 || error?.status === 403;
        message(revoked ? "Access expired · reopen after signing in" : "Connection interrupted · retrying; displayed log may be stale");
        if (!revoked) schedule(Math.min(30000, 5000 * (2 ** failures++)));
      } finally {
        window.clearTimeout(deadline);
        if (request === controller) request = null;
      }
    }
    const visibility = () => {
      if (document.hidden) { generation += 1; request?.abort(); request = null; }
      else schedule(0);
    };
    const close = () => {
      closed = true;
      generation += 1;
      window.clearTimeout(timer);
      request?.abort();
      document.removeEventListener("visibilitychange", visibility);
      window.removeEventListener("pagehide", close);
      controls?.replaceChildren();
    };
    document.addEventListener("visibilitychange", visibility);
    window.addEventListener("pagehide", close, { once: true });
    updateButtons();
    const ready = refresh();
    return { close, ready };
  }

  async function fetchJson(url, signal) {
    const response = await fetch(url, { signal, credentials: "same-origin",
      headers: { Accept: "application/json", "X-Atlaso-Task-Log": "1" } });
    const loginRedirect = response.redirected && new URL(response.url, window.location.href).pathname.endsWith("/login");
    if (!response.ok || loginRedirect) {
      const error = new Error(`Log request failed (${response.status})`);
      error.status = loginRedirect ? 401 : response.status;
      throw error;
    }
    return response.json();
  }
  window.AtlasoLogViewer = { create, fetchJson };
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-live-log-url]").forEach((root) => {
      create({
        output: root.querySelector("[data-live-log-output]"),
        initialCursor: "tail",
        status: root.querySelector("[data-live-log-status]"),
        controls: root.querySelector("[data-live-log-controls]"),
        fetchPage: (cursor, signal) => {
          const url = new URL(root.dataset.liveLogUrl, window.location.href);
          if (cursor === "tail") url.searchParams.set("tail", "1");
          else if (cursor) url.searchParams.set("cursor", cursor);
          return fetchJson(url, signal);
        },
      });
    });
  });
})();

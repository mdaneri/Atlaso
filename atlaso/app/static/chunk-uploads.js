/* Shared browser file transport; existing form handlers own validation and results. */
(() => {
  "use strict";
  const nativeFetch = window.fetch.bind(window);
  const endpoint = "/ui/management/uploads/chunks";

  async function checked(url, options) {
    const response = await nativeFetch(url, options);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      const error = new Error(payload.detail || `Upload failed with HTTP ${response.status}.`);
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  async function uploadFetch(url, options = {}, progress = () => {}, received = () => {}) {
    const target = new URL(url, location.href);
    const body = options.body;
    const entries = body instanceof FormData ? [...body.entries()] : body instanceof File ? [["ova_file", body]] : [];
    const files = entries.filter(([, value]) => value instanceof File && value.name);
    if (!files.length) return nativeFetch(url, options);
    if (target.origin !== location.origin) throw new Error("File uploads must target this appliance.");
    const headers = new Headers(options.headers);
    const csrf = headers.get("X-CSRF-Token") || entries.find(([name]) => name === "csrf")?.[1]
      || document.querySelector('input[name="csrf"]')?.value || "";
    const common = { credentials: "same-origin", signal: options.signal, headers: { "X-CSRF-Token": csrf } };
    const total = files.reduce((sum, [, file]) => sum + file.size, 0);
    const ids = [];
    let completed = 0;
    progress(0, total);
    try {
      for (const [field, file] of files) {
        if (!file.size) throw new Error("Choose a nonempty file.");
        const session = await checked(endpoint, {
          ...common, method: "POST", headers: { ...common.headers, "Content-Type": "application/json" },
          body: JSON.stringify({ target: target.pathname, field, filename: file.name, size: file.size }),
        });
        ids.push(session.id);
        const chunkBytes = Math.min(8 * 1024 ** 2, session.chunk_bytes);
        if (!Number.isSafeInteger(chunkBytes) || chunkBytes <= 0) throw new Error("Invalid upload chunk size.");
        for (let offset = 0; offset < file.size;) {
          const chunk = file.slice(offset, offset + chunkBytes);
          const digest = await crypto.subtle.digest("SHA-256", await chunk.arrayBuffer());
          const checksum = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
          let result;
          for (let attempt = 0; ; attempt += 1) {
            try {
              result = await checked(`${endpoint}/data`, {
                ...common, method: "PUT", body: chunk,
                headers: { ...common.headers, "Content-Type": "application/octet-stream",
                  "X-Atlaso-Upload-Id": session.id, "X-Atlaso-Upload-Offset": String(offset),
                  "X-Atlaso-Chunk-SHA256": checksum },
              });
              break;
            } catch (error) {
              if (options.signal?.aborted || attempt >= 3 || (error.status && error.status < 500 && error.status !== 429)) throw error;
              await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** attempt));
            }
          }
          if (result.offset !== offset + chunk.size) throw new Error("Atlaso returned an unexpected upload offset.");
          offset = result.offset;
          progress(completed + offset, total);
        }
        completed += file.size;
      }
      received();
      headers.set("X-CSRF-Token", csrf);
      headers.set("X-Atlaso-Chunked", "1");
      headers.set("Content-Type", "application/json");
      // Finalization may mutate state: never retry this request automatically.
      return await nativeFetch(url, {
        ...options, headers,
        body: JSON.stringify({ files: ids, fields: entries.filter(([, value]) => typeof value === "string") }),
      });
    } finally {
      await Promise.allSettled(ids.map((id) => nativeFetch(`${endpoint}/data`, {
        method: "DELETE", credentials: "same-origin",
        headers: { "X-CSRF-Token": csrf, "X-Atlaso-Upload-Id": id },
      })));
    }
  }

  class ChunkedRequest extends EventTarget {
    constructor() {
      super();
      this.upload = new EventTarget();
      this.headers = new Headers();
      this.controller = new AbortController();
      this.status = 0;
      this.responseText = "";
    }
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader(name, value) { this.headers.set(name, value); }
    abort() { this.controller.abort(); }
    async send(body) {
      this.upload.dispatchEvent(new Event("loadstart"));
      try {
        const response = await uploadFetch(this.url, {
          method: this.method, headers: this.headers, body, signal: this.controller.signal,
        }, (loaded, total) => this.upload.dispatchEvent(new ProgressEvent("progress", {
          lengthComputable: true, loaded, total,
        })), () => this.upload.dispatchEvent(new Event("load")));
        this.status = response.status;
        this.responseText = await response.text();
        this.dispatchEvent(new Event("load"));
      } catch (error) {
        if (this.controller.signal.aborted) this.dispatchEvent(new Event("abort"));
        else {
          this.status = error.status || 503;
          this.responseText = JSON.stringify({ detail: error.message });
          this.dispatchEvent(new Event("load"));
        }
      }
    }
  }

  // Native multipart forms share the same transport after page-specific handlers
  // have had the opportunity to consume the submit event.
  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (event.defaultPrevented || !(form instanceof HTMLFormElement) || form.method.toLowerCase() !== "post") return;
    const body = new FormData(form, event.submitter);
    if (![...body.values()].some((value) => value instanceof File && value.name)) return;
    event.preventDefault();
    if (form.hasAttribute("aria-busy")) return;
    form.setAttribute("aria-busy", "true");
    const status = document.createElement("p");
    status.setAttribute("role", "status");
    form.append(status);
    try {
      const response = await uploadFetch(form.action, { method: "POST", body }, (loaded, total) => {
        status.textContent = `Uploading: ${Math.round(loaded / total * 100)}%`;
      }, () => { status.textContent = "Upload received. Validating..."; });
      if (response.redirected) location.assign(response.url);
      else if (response.headers.get("Content-Type")?.includes("text/html")) {
        const html = await response.text();
        document.open(); document.write(html); document.close();
      } else {
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.detail || "Upload failed.");
        location.reload();
      }
    } catch (error) {
      status.textContent = error.message || "Upload failed. Select the file and try again.";
      status.setAttribute("role", "alert");
    } finally {
      form.removeAttribute("aria-busy");
    }
  });
  window.AtlasoUploads = { fetch: uploadFetch, Request: ChunkedRequest };
})();

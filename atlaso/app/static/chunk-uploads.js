/* Shared browser file transport; existing form handlers own validation and results. */
(() => {
  "use strict";
  // Staging traffic does not change desired state or need an Apply status refresh.
  const nativeFetch = window.fetch.bind(window);
  const endpoint = "/ui/management/uploads/chunks";

  async function checksumBytes(buffer) {
    if (globalThis.crypto?.subtle) {
      const digest = await crypto.subtle.digest("SHA-256", buffer);
      return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    // HTTP management pages have no SubtleCrypto. Hash only the bounded chunk;
    // these standard SHA-256 rounds keep the same wire-integrity contract.
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    const state = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const input = new Uint8Array(buffer);
    const padded = new Uint8Array(Math.ceil((input.length + 9) / 64) * 64);
    padded.set(input); padded[input.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(input.length / 0x20000000));
    view.setUint32(padded.length - 4, input.length * 8);
    const words = new Uint32Array(64);
    const rotate = (word, bits) => (word >>> bits) | (word << (32 - bits));
    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i += 1) words[i] = view.getUint32(offset + i * 4);
      for (let i = 16; i < 64; i += 1) {
        const x = words[i - 15], y = words[i - 2];
        words[i] = words[i - 16] + (rotate(x, 7) ^ rotate(x, 18) ^ (x >>> 3))
          + words[i - 7] + (rotate(y, 17) ^ rotate(y, 19) ^ (y >>> 10));
      }
      let [a, b, c, d, e, f, g, h] = state;
      for (let i = 0; i < 64; i += 1) {
        const first = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25))
          + ((e & f) ^ (~e & g)) + constants[i] + words[i]) | 0;
        const second = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22))
          + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + first) | 0;
        d = c; c = b; b = a; a = (first + second) | 0;
      }
      [a, b, c, d, e, f, g, h].forEach((value, index) => { state[index] += value; });
    }
    return Array.from(state, (word) => word.toString(16).padStart(8, "0")).join("");
  }

  async function checked(url, options) {
    const response = await nativeFetch(url, options);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      const error = new Error(payload.detail || `Upload failed with HTTP ${response.status}.`);
      error.status = response.status;
      error.code = payload.code;
      error.overwriteToken = payload.overwrite_token;
      throw error;
    }
    return response.json();
  }

  async function uploadFetch(url, options = {}, progress = () => {}, received = () => {}) {
    const target = new URL(url, location.href);
    const body = options.body;
    const entries = body instanceof FormData ? [...body.entries()] : body instanceof File ? [["ova_file", body]] : [];
    const files = entries.filter(([, value]) => value instanceof File && value.name);
    if (!files.length) return window.fetch(url, options);
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
        const reservation = { target: target.pathname, field, filename: file.name, size: file.size };
        const reserve = () => checked(endpoint, {
          ...common, method: "POST", headers: { ...common.headers, "Content-Type": "application/json" },
          body: JSON.stringify(reservation),
        });
        let session;
        try {
          session = await reserve();
        } catch (error) {
          if (error.status !== 409 || error.code !== "overwrite_required") throw error;
          const confirmed = typeof requestConfirmation === "function" && await requestConfirmation({
            title: "Overwrite existing file?",
            message: `A file named “${file.name}” already exists. Overwrite it with the selected file? The current file will be replaced only after validation succeeds.`,
            label: "Overwrite",
          });
          if (!confirmed) throw new Error("Upload canceled. The existing file was kept.");
          if (options.signal?.aborted) throw new Error("Upload canceled.");
          reservation.overwrite_token = error.overwriteToken;
          // A changed destination requires a new user attempt, not automatic consent.
          session = await reserve();
        }
        ids.push(session.id);
        const chunkBytes = Math.min(8 * 1024 ** 2, session.chunk_bytes);
        if (!Number.isSafeInteger(chunkBytes) || chunkBytes <= 0) throw new Error("Invalid upload chunk size.");
        for (let offset = 0; offset < file.size;) {
          const chunk = file.slice(offset, offset + chunkBytes);
          const checksum = await checksumBytes(await chunk.arrayBuffer());
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
      return await window.fetch(url, {
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
      } finally {
        this.dispatchEvent(new Event("loadend"));
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

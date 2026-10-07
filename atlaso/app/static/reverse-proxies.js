(function initializeReverseProxyModule(global) {
  "use strict";

  const MAX_ITEMS = 512;
  const DEFAULTS = Object.freeze({
    connect_timeout: 5,
    read_timeout: 60,
    send_timeout: 60,
    body_limit: 16777216,
  });
  const steps = [
    { id: "identity", title: "Name the proxy", description: "Set its unique hostname and operator description." },
    { id: "listener", title: "Choose exact listeners", description: "Select eligible addresses, the public scheme and port, and any exact redirect listener." },
    { id: "routes", title: "Define application paths", description: "Add one or more non-overlapping path routes and choose upstream trust." },
    { id: "publication", title: "Choose publication", description: "Control the Public Services directory and authoritative DNS independently." },
    { id: "state", title: "Choose desired state", description: "Enable the proxy only after reviewing its listeners and paths." },
    { id: "review", title: "Review the reverse proxy", description: "Confirm the complete desired state before global Appliance Apply." },
  ];

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[character]);
  }

  function pathsOverlap(left, right) {
    const first = String(left || "");
    const second = String(right || "");
    return Boolean(first && second && (first.startsWith(second) || second.startsWith(first)));
  }

  function routeHealthRow(item = {}) {
    return {
      proxy_id: Number(item.proxy_id || 0),
      route_id: Number(item.route_id || 0),
      proxy_name: String(item.proxy_name || ""),
      path_prefix: String(item.path_prefix || ""),
      status: String(item.status || "unknown"),
      last_success: String(item.last_success || ""),
      failure_class: String(item.failure_class || ""),
      http_status: item.http_status == null ? "" : String(item.http_status),
      tls_status: String(item.tls_status || ""),
      applied: Boolean(item.applied),
      pending: Boolean(item.pending),
      warning: String(item.warning || ""),
    };
  }

  function healthDisplayRow(item = {}) {
    const row = routeHealthRow(item);
    const statuses = {
      healthy: "Healthy",
      degraded: "Degraded",
      unavailable: "Unavailable",
      pending: "Pending",
      disabled: "Disabled",
    };
    const failures = {
      desired_state_exceeds_limit: "Desired state exceeds limit",
      desired_state_pending: "Desired state pending",
      health_unavailable: "Health observation missing",
      insecure_verification: "Insecure verification",
      invalid_http: "Invalid HTTP response",
      runtime_observer_unavailable: "Runtime observation unavailable",
      tls_verification: "TLS verification failed",
      unavailable: "Unavailable",
      upstream_http: "Upstream HTTP error",
    };
    const tlsStatuses = {
      failed: "Failed",
      fingerprint: "Fingerprint",
      insecure: "Insecure",
      not_applicable: "Not applicable",
      not_probed: "Not probed",
      trusted_ca: "Trusted CA",
    };
    const tls = tlsStatuses[row.tls_status] || (row.tls_status ? "Other" : "");
    return {
      ...row,
      status: statuses[row.status] || "Unknown",
      failure_class: failures[row.failure_class] || (row.failure_class ? "Other" : "—"),
      http_tls: [row.http_status ? `HTTP ${row.http_status}` : "", tls ? `TLS ${tls}` : ""].filter(Boolean).join(" · ") || "—",
      apply_state: row.pending
        ? row.applied ? "Applied with pending changes" : "Pending apply"
        : row.applied ? "Applied" : "Not applied",
    };
  }

  function visibleProxyRow(item = {}) {
    const record = serializeProxy(item);
    const routes = Array.isArray(record.routes) ? record.routes : [];
    const insecure = routes.some((route) => route.trust_mode === "insecure");
    return {
      ...record,
      routes,
      path_count: routes.length,
      insecure_upstream: insecure,
    };
  }

  function serializeProxy(item = {}, enabled = item.enabled) {
    const payload = {
      name: String(item.name || ""),
      description: String(item.description || ""),
      hostname: String(item.hostname || ""),
      scheme: item.scheme === "https" ? "https" : "http",
      port: Number(item.port || 0),
      redirect_http: Boolean(item.redirect_http),
      redirect_port: Number(item.redirect_port || 0),
      enabled: Boolean(enabled),
      public_listing: item.public_listing !== false,
      managed_dns: Boolean(item.managed_dns),
      listeners: (Array.isArray(item.listeners) ? item.listeners : []).map((listener) => ({
        interface: String(listener.interface || ""),
        address: String(listener.address || ""),
      })),
      routes: (Array.isArray(item.routes) ? item.routes : []).map((route) => ({
        ...(Number.isInteger(Number(route.id)) && Number(route.id) > 0 ? { id: Number(route.id) } : {}),
        path_prefix: String(route.path_prefix || ""),
        upstream_scheme: route.upstream_scheme === "https" ? "https" : "http",
        upstream_host: String(route.upstream_host || ""),
        upstream_port: Number(route.upstream_port || 0),
        path_behavior: route.path_behavior === "strip" ? "strip" : "preserve",
        trust_mode: ["trusted_ca", "fingerprint", "insecure"].includes(route.trust_mode) ? route.trust_mode : "trusted_ca",
        ...(route.trust_mode === "fingerprint" ? { fingerprint: String(route.fingerprint || "") } : {}),
        insecure_acknowledged: route.trust_mode === "insecure" && Boolean(route.insecure_acknowledged),
      })),
      connect_timeout: Number(item.connect_timeout ?? DEFAULTS.connect_timeout),
      read_timeout: Number(item.read_timeout ?? DEFAULTS.read_timeout),
      send_timeout: Number(item.send_timeout ?? DEFAULTS.send_timeout),
      body_limit: Number(item.body_limit ?? DEFAULTS.body_limit),
    };
    if (Number.isInteger(Number(item.id)) && Number(item.id) > 0) payload.id = Number(item.id);
    return payload;
  }

  function endpointMessage(response, fallback) {
    return response.json().then((payload) => {
      const detail = payload && typeof payload.detail === "string" ? payload.detail : "";
      return detail || fallback;
    }).catch(() => fallback);
  }

  function initializeHealth(element, reportError) {
    const fallback = document.getElementById(element.dataset.fallbackId || "");
    const message = document.querySelector("[data-reverse-proxy-health-message]");
    const refreshButton = document.querySelector("[data-reverse-proxy-health-refresh]");
    let table = null;
    let requestSequence = 0;
    if (typeof global.AtlasoUiPatterns?.createGrid !== "function") return null;

    const escapeCell = (cell) => escapeHtml(cell.getValue());
    const grid = global.AtlasoUiPatterns.createGrid({
      element,
      fallback,
      pattern: "read-only",
      emptyMessage: "No route health observations are available.",
      errorMessage: "Health observations are unavailable. Showing the fallback view.",
      options: {
        data: [],
        layout: "fitColumns",
        placeholder: "No route health observations are available.",
        columns: [
          { title: "Proxy", field: "proxy_name", minWidth: 140, formatter: escapeCell },
          { title: "Path", field: "path_prefix", minWidth: 140, formatter: (cell) => `<code>${escapeHtml(cell.getValue())}</code>` },
          { title: "Status", field: "status", minWidth: 115, formatter: escapeCell },
          { title: "Last success", field: "last_success", minWidth: 150, formatter: escapeCell },
          { title: "Failure class", field: "failure_class", minWidth: 130, formatter: escapeCell },
          { title: "HTTP / TLS", field: "http_tls", minWidth: 120, formatter: escapeCell },
          { title: "Apply state", field: "apply_state", minWidth: 110, formatter: escapeCell },
          { title: "Warning", field: "warning", minWidth: 220, formatter: escapeCell },
        ],
      },
    });
    table = grid?.table || null;

    const refresh = async () => {
      const sequence = ++requestSequence;
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 15000);
      try {
        const response = await fetch(element.dataset.healthUrl, {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(await endpointMessage(response, "Health observations are unavailable."));
        const payload = await response.json();
        if (!Array.isArray(payload.items) || payload.items.length > MAX_ITEMS) {
          throw new Error("The bounded health response is invalid.");
        }
        if (sequence !== requestSequence) return;
        const rows = payload.items.map(healthDisplayRow);
        await table?.replaceData?.(rows);
        element.classList.remove("hidden");
        fallback?.classList.add("hidden");
        element.dataset.atlasoGridState = rows.length ? "ready" : "empty";
        if (message) message.textContent = rows.length
          ? `${rows.length} bounded route observation${rows.length === 1 ? "" : "s"} refreshed.`
          : "No route health observations are available.";
      } catch (error) {
        if (sequence !== requestSequence) return;
        element.classList.add("hidden");
        fallback?.classList.remove("hidden");
        element.dataset.atlasoGridState = "error";
        if (message) message.textContent = "Health observations are unavailable. Showing the fallback view.";
        reportError(error instanceof Error ? error.message : "Health observations are unavailable.");
      } finally {
        window.clearTimeout(timeout);
      }
    };

    refreshButton?.addEventListener("click", () => { void refresh(); });
    return { refresh, table };
  }

  function initialize() {
    const element = document.getElementById("reverse-proxies-table");
    if (!(element instanceof HTMLElement)) return null;
    if (typeof global.AtlasoUiPatterns?.createGrid !== "function") return null;

    const canWrite = element.dataset.canWrite === "true";
    const errorElement = document.querySelector("[data-reverse-proxy-error]");
    const form = document.querySelector("[data-reverse-proxy-wizard]");
    const dialog = form?.closest("dialog");
    const routesContainer = form?.querySelector("[data-reverse-proxy-routes]");
    const routeTemplate = form?.querySelector("template[data-reverse-proxy-route-template]");
    const listenerSelect = form?.querySelector("[data-reverse-proxy-listeners]");
    const dataUrl = element.dataset.dataUrl;
    const saveUrl = element.dataset.saveUrl;
    const csrf = element.dataset.csrf || "";
    let items = [];
    let listenerOptions = [];
    let table = null;
    let wizard = null;
    let loadSequence = 0;
    let originalRecord = null;
    const health = initializeHealth(document.getElementById("reverse-proxy-health-table"), showError);

    function showError(message = "") {
      if (!(errorElement instanceof HTMLElement)) return;
      errorElement.textContent = message;
      errorElement.classList.toggle("hidden", !message);
    }

    function setCollectionRows(nextItems = items) {
      items = Array.isArray(nextItems) ? nextItems.slice(0, MAX_ITEMS) : [];
      const tableRows = canWrite ? [...items.map(visibleProxyRow), { is_new: true, name: "" }] : items.map(visibleProxyRow);
      void table?.setData?.(tableRows);
      const fallback = document.getElementById(element.dataset.fallbackId || "");
      if (fallback instanceof HTMLElement && !items.length) {
        const body = fallback.tBodies[0];
        if (body) {
          const row = document.createElement("tr");
          const cell = document.createElement("td");
          cell.colSpan = 8;
          cell.className = "muted";
          cell.textContent = "No reverse proxies are configured.";
          row.append(cell);
          body.replaceChildren(row);
        }
      }
    }

    function setValidation(payload) {
      const errors = Array.isArray(payload.validation_errors) ? payload.validation_errors : [];
      const warnings = Array.isArray(payload.validation_warnings) ? payload.validation_warnings : [];
      const status = document.querySelector("[data-reverse-proxy-validation-status]");
      const errorList = document.querySelector("[data-reverse-proxy-validation-errors]");
      const warningList = document.querySelector("[data-reverse-proxy-validation-warnings]");
      const message = document.querySelector("[data-reverse-proxy-validation-message]");
      const preview = document.querySelector("[data-reverse-proxy-config-preview]");
      const previewPath = document.querySelector("[data-reverse-proxy-config-path]");
      const replaceList = (target, values) => {
        if (!(target instanceof HTMLElement)) return;
        target.replaceChildren(...values.map((value) => {
          const row = document.createElement("div");
          row.textContent = String(value);
          return row;
        }));
        target.classList.toggle("hidden", !values.length);
      };
      replaceList(errorList, errors);
      replaceList(warningList, warnings);
      if (status instanceof HTMLElement) {
        status.textContent = errors.length ? "needs attention" : warnings.length ? "review warnings" : "valid";
        status.classList.toggle("good", !errors.length && !warnings.length);
        status.classList.toggle("warn", Boolean(errors.length || warnings.length));
      }
      if (message instanceof HTMLElement) message.textContent = errors.length
        ? "Resolve the listed errors before applying these reverse-proxy changes."
        : warnings.length ? "Review the warnings before global Appliance Apply."
          : "Reverse-proxy desired state passes Atlaso validation. Global Appliance Apply validates and publishes the configuration.";
      if (preview instanceof HTMLElement && typeof payload.config_preview === "string") preview.textContent = payload.config_preview;
      if (previewPath instanceof HTMLElement && typeof payload.config_path === "string") previewPath.textContent = payload.config_path;
    }

    function updateListenerOptions(options, selected = []) {
      if (!(listenerSelect instanceof HTMLSelectElement)) return;
      const chosen = new Set(selected.map((entry) => `${entry.interface}|${entry.address}`));
      const valid = Array.isArray(options) ? options : [];
      listenerOptions = valid;
      listenerSelect.replaceChildren(...valid.map((option) => {
        const item = new Option(String(option.label || `${option.interface} · ${option.address}`), `${option.interface}|${option.address}`);
        item.selected = chosen.has(item.value);
        return item;
      }));
    }

    async function refreshData() {
      const sequence = ++loadSequence;
      try {
        const response = await fetch(dataUrl, { credentials: "same-origin", headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error(await endpointMessage(response, "Reverse-proxy data could not be loaded."));
        const payload = await response.json();
        if (!Array.isArray(payload.items) || payload.items.length > MAX_ITEMS || !Array.isArray(payload.listener_options)) {
          throw new Error("The reverse-proxy data response is invalid.");
        }
        if (sequence !== loadSequence) return;
        setCollectionRows(payload.items);
        updateListenerOptions(payload.listener_options);
        setValidation(payload);
        showError("");
      } catch (error) {
        if (sequence !== loadSequence) return;
        showError(error instanceof Error ? error.message : "Reverse-proxy data could not be loaded.");
      }
    }

    function routeField(route, name) {
      return route.querySelector(`[name="${name}"]`);
    }

    function updateTrustControls(route) {
      const scheme = routeField(route, "upstream_scheme");
      const trustField = route.querySelector("[data-reverse-proxy-trust-field]");
      const fingerprintField = route.querySelector("[data-reverse-proxy-fingerprint-field]");
      const warning = route.querySelector("[data-reverse-proxy-insecure-warning]");
      const trustMode = route.querySelector("[data-reverse-proxy-trust-mode]");
      const fingerprint = route.querySelector("[data-reverse-proxy-fingerprint]");
      const https = scheme?.value === "https";
      const needsFingerprint = https && trustMode?.value === "fingerprint";
      const insecure = https && trustMode?.value === "insecure";
      for (const [target, visible] of [[trustField, https], [fingerprintField, needsFingerprint], [warning, insecure]]) {
        target?.classList.toggle("hidden", !visible);
        target?.toggleAttribute("hidden", !visible);
      }
      if (fingerprint instanceof HTMLInputElement) fingerprint.required = needsFingerprint;
      if (trustMode instanceof HTMLSelectElement) trustMode.disabled = !https;
    }

    function syncListenerControls() {
      if (!(form instanceof HTMLFormElement)) return;
      const scheme = form.querySelector("[data-reverse-proxy-scheme]");
      const redirect = form.querySelector("[data-reverse-proxy-redirect]");
      const redirectField = form.querySelector("[data-reverse-proxy-redirect-port-field]");
      const certNote = form.querySelector("[data-reverse-proxy-certificate-note]");
      const https = scheme?.value === "https";
      const redirectVisible = https && Boolean(redirect?.checked);
      redirect?.toggleAttribute("disabled", !https);
      if (redirect instanceof HTMLInputElement && !https) redirect.checked = false;
      for (const [target, visible] of [[redirectField, redirectVisible], [certNote, https]]) {
        target?.classList.toggle("hidden", !visible);
        target?.toggleAttribute("hidden", !visible);
      }
      const port = form.querySelector("[data-reverse-proxy-redirect-port]");
      if (port instanceof HTMLInputElement) port.required = redirectVisible;
    }

    function routeNodes() {
      return [...(routesContainer?.querySelectorAll("[data-reverse-proxy-route]") || [])];
    }

    function syncRouteRemoveButtons() {
      const routes = routeNodes();
      routes.forEach((route) => {
        const remove = route.querySelector("[data-reverse-proxy-route-remove]");
        if (remove instanceof HTMLButtonElement) remove.disabled = routes.length <= 1;
      });
    }

    function appendRoute(data = {}) {
      if (!(routesContainer instanceof HTMLElement) || !(routeTemplate instanceof HTMLTemplateElement)) return null;
      const fragment = routeTemplate.content.cloneNode(true);
      const route = fragment.querySelector("[data-reverse-proxy-route]");
      if (!(route instanceof HTMLElement)) return null;
      routesContainer.insertBefore(fragment, routesContainer.querySelector("[data-reverse-proxy-route-add]"));
      for (const key of ["route_id", "path_prefix", "upstream_scheme", "upstream_host", "upstream_port", "path_behavior", "trust_mode", "fingerprint"]) {
        const field = routeField(route, key);
        if (field) field.value = data[key === "route_id" ? "id" : key] ?? (key === "upstream_scheme" ? "http" : key === "path_behavior" ? "preserve" : key === "trust_mode" ? "trusted_ca" : "");
      }
      updateTrustControls(route);
      syncRouteRemoveButtons();
      return route;
    }

    function populateForm(row = null) {
      if (!(form instanceof HTMLFormElement)) return;
      form.reset();
      const initialRoutes = routeNodes();
      initialRoutes.slice(1).forEach((route) => route.remove());
      const route = initialRoutes[0];
      const record = row || {};
      originalRecord = row ? serializeProxy(row) : null;
      const acknowledgement = form.querySelector("[data-reverse-proxy-insecure-ack]");
      if (acknowledgement instanceof HTMLInputElement) {
        acknowledgement.checked = false;
        delete acknowledgement.dataset.initialized;
      }
      form.querySelector("[data-reverse-proxy-id]").value = record.id || "";
      for (const key of ["name", "description", "hostname", "scheme", "port", "redirect_port", "connect_timeout", "read_timeout", "send_timeout", "body_limit"]) {
        const field = form.querySelector(`[name="${key}"]`);
        if (field && record[key] != null) field.value = record[key];
      }
      for (const key of ["redirect_http", "enabled", "public_listing", "managed_dns"]) {
        const field = form.querySelector(`[name="${key}"]`);
        if (field instanceof HTMLInputElement) field.checked = record[key] === undefined ? key === "public_listing" : Boolean(record[key]);
      }
      updateListenerOptions(listenerOptions, Array.isArray(record.listeners) ? record.listeners : []);
      const recordRoutes = Array.isArray(record.routes) && record.routes.length ? record.routes : [{}];
      if (route) {
        const first = recordRoutes[0];
        for (const key of ["route_id", "path_prefix", "upstream_scheme", "upstream_host", "upstream_port", "path_behavior", "trust_mode", "fingerprint"]) {
          const field = routeField(route, key);
          if (field) field.value = first[key === "route_id" ? "id" : key] ?? (key === "upstream_scheme" ? "http" : key === "path_behavior" ? "preserve" : key === "trust_mode" ? "trusted_ca" : "");
        }
        updateTrustControls(route);
        recordRoutes.slice(1).forEach((entry) => appendRoute(entry));
      }
      syncListenerControls();
      syncRouteRemoveButtons();
      form.action = saveUrl;
    }

    function collectPayload() {
      const selectedListeners = listenerSelect instanceof HTMLSelectElement
        ? [...listenerSelect.selectedOptions].map((option) => {
          const [interfaceName, address] = option.value.split("|", 2);
          return { interface: interfaceName, address };
        }) : [];
      const routes = routeNodes().map((route) => {
        const upstreamScheme = routeField(route, "upstream_scheme")?.value || "http";
        const trustMode = upstreamScheme === "https" ? routeField(route, "trust_mode")?.value || "trusted_ca" : "trusted_ca";
        const routeId = Number(routeField(route, "route_id")?.value || 0);
        const reviewed = Boolean(form.querySelector("[data-reverse-proxy-insecure-ack]")?.checked);
        return {
          ...(Number.isInteger(routeId) && routeId > 0 ? { id: routeId } : {}),
          path_prefix: String(routeField(route, "path_prefix")?.value || "").trim(),
          upstream_scheme: upstreamScheme,
          upstream_host: String(routeField(route, "upstream_host")?.value || "").trim(),
          upstream_port: Number(routeField(route, "upstream_port")?.value || 0),
          path_behavior: routeField(route, "path_behavior")?.value || "preserve",
          trust_mode: trustMode,
          fingerprint: upstreamScheme === "https" && trustMode === "fingerprint"
            ? String(routeField(route, "fingerprint")?.value || "").trim() : "",
          insecure_acknowledged: trustMode === "insecure" && reviewed,
        };
      });
      const value = (name) => form.querySelector(`[name="${name}"]`);
      const boolean = (name) => Boolean(value(name)?.checked);
      const payload = {
        name: String(value("name")?.value || "").trim(),
        description: String(value("description")?.value || "").trim(),
        hostname: String(value("hostname")?.value || "").trim(),
        scheme: value("scheme")?.value || "http",
        port: Number(value("port")?.value || 0),
        redirect_http: boolean("redirect_http"),
        redirect_port: Number(value("redirect_port")?.value || 0),
        enabled: boolean("enabled"),
        public_listing: boolean("public_listing"),
        managed_dns: boolean("managed_dns"),
        listeners: selectedListeners,
        routes,
        connect_timeout: Number(value("connect_timeout")?.value || DEFAULTS.connect_timeout),
        read_timeout: Number(value("read_timeout")?.value || DEFAULTS.read_timeout),
        send_timeout: Number(value("send_timeout")?.value || DEFAULTS.send_timeout),
        body_limit: Number(value("body_limit")?.value || DEFAULTS.body_limit),
      };
      const id = Number(value("id")?.value || 0);
      if (Number.isInteger(id) && id > 0) payload.id = id;
      return payload;
    }

    function validateStep({ step }) {
      if (step.id === "listener") {
        if (!listenerSelect || !listenerSelect.selectedOptions.length) return { valid: false, message: "Select at least one eligible listener address.", field: "listeners" };
        if (form.querySelector("[data-reverse-proxy-redirect]")?.checked && form.querySelector("[data-reverse-proxy-scheme]")?.value !== "https") {
          return { valid: false, message: "HTTP-to-HTTPS redirect requires an HTTPS listener.", field: "scheme" };
        }
      }
      if (step.id === "routes") {
        const routes = routeNodes();
        if (!routes.length) return { valid: false, message: "Add at least one path route." };
        for (const route of routes) {
          const path = String(routeField(route, "path_prefix")?.value || "").trim();
          if (!path.startsWith("/") || path.length > 1024 || path.includes("?") || path.includes("#")) {
            return { valid: false, message: "Each route needs an absolute path prefix no longer than 1024 characters.", field: routeField(route, "path_prefix") };
          }
          const host = String(routeField(route, "upstream_host")?.value || "").trim();
          if (host.includes("@") || /[/?#]/.test(host)) {
            return { valid: false, message: "Enter an upstream host or IP without a URL scheme, path, or user information.", field: routeField(route, "upstream_host") };
          }
          if (routeField(route, "upstream_scheme")?.value === "https" && routeField(route, "trust_mode")?.value === "fingerprint") {
            const fingerprint = String(routeField(route, "fingerprint")?.value || "").replace(/[:\s-]/g, "");
            if (!/^[a-f\d]{64}$/i.test(fingerprint)) return { valid: false, message: "Enter the exact 64-character SHA-256 certificate fingerprint.", field: routeField(route, "fingerprint") };
          }
        }
        const prefixes = routes.map((route) => String(routeField(route, "path_prefix")?.value || "").trim());
        for (let left = 0; left < prefixes.length; left += 1) {
          for (let right = left + 1; right < prefixes.length; right += 1) {
            if (pathsOverlap(prefixes[left], prefixes[right])) return { valid: false, message: "Path prefixes must not overlap. Adjust the affected path route.", field: routeField(routes[right], "path_prefix") };
          }
        }
      }
      if (step.id === "review") {
        const hasInsecureRoute = routeNodes().some((route) => routeField(route, "upstream_scheme")?.value === "https" && routeField(route, "trust_mode")?.value === "insecure");
        if (hasInsecureRoute && !form.querySelector("[data-reverse-proxy-insecure-ack]")?.checked) {
          return { valid: false, message: "Explicitly acknowledge insecure upstream certificate verification before saving.", field: form.querySelector("[data-reverse-proxy-insecure-ack]") };
        }
      }
      return true;
    }

    function populateReview() {
      const payload = collectPayload();
      const routes = payload.routes;
      const insecure = routes.some((route) => route.upstream_scheme === "https" && route.trust_mode === "insecure");
      const set = (name, value) => {
        const target = form.querySelector(`[data-reverse-proxy-review="${name}"]`);
        if (target) target.textContent = value || "Not configured";
      };
      set("identity", `${payload.name} · ${payload.hostname}`);
      set("listener", `${payload.scheme.toUpperCase()} ${payload.port} · ${payload.listeners.map((listener) => `${listener.interface} ${listener.address}`).join(", ")}${payload.redirect_http ? ` · HTTP redirect ${payload.redirect_port}` : ""}`);
      set("routes", routes.map((route) => `${route.path_prefix} → ${route.upstream_scheme}://${route.upstream_host}:${route.upstream_port} (${route.path_behavior}, ${route.trust_mode})`).join("; "));
      set("publication", `${payload.public_listing ? "Public Services listed" : "Hidden from Public Services"} · ${payload.managed_dns ? "Atlaso DNS" : "External DNS"}`);
      set("state", payload.enabled ? "Enabled desired state" : "Disabled desired state");
      const warning = form.querySelector("[data-reverse-proxy-review-insecure-warning]");
      warning?.classList.toggle("hidden", !insecure);
      warning?.toggleAttribute("hidden", !insecure);
      const acknowledgement = form.querySelector("[data-reverse-proxy-insecure-ack-panel]");
      acknowledgement?.classList.toggle("hidden", !insecure);
      acknowledgement?.toggleAttribute("hidden", !insecure);
      const ack = form.querySelector("[data-reverse-proxy-insecure-ack]");
      if (ack instanceof HTMLInputElement && !ack.dataset.initialized) {
        const currentInsecure = routes.filter((route) => route.trust_mode === "insecure");
        const previouslyAcknowledged = currentInsecure.length > 0 && currentInsecure.every((route) => {
          const original = originalRecord?.routes?.find((candidate) => candidate.id === route.id);
          return Boolean(original && original.trust_mode === "insecure" && original.insecure_acknowledged);
        });
        ack.checked = previouslyAcknowledged;
        ack.dataset.initialized = "true";
      }
      return true;
    }

    async function submitPayload(payload) {
      const response = await fetch(saveUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error(await endpointMessage(response, "The reverse-proxy change could not be saved."));
      await refreshData();
      return response.json().catch(() => ({}));
    }

    function openWizard(row, launcher) {
      if (!wizard || !canWrite) return;
      void wizard.open({ context: row || null, launcher });
    }

    if (canWrite && form instanceof HTMLFormElement && dialog instanceof HTMLDialogElement) {
      wizard = global.AtlasoUiPatterns.createWizard({
        form,
        dialog,
        steps,
        validateStep,
        prepareReview: populateReview,
        onOpen: ({ context }) => populateForm(context),
        onSubmit: async () => {
          try {
            const payload = collectPayload();
            await submitPayload(payload);
            showError("");
            return { valid: true };
          } catch (error) {
            return { valid: false, message: error instanceof Error ? error.message : "The reverse-proxy change could not be saved. Check the connection and try again." };
          }
        },
        discardTitle: "Discard reverse-proxy changes?",
        discardMessage: "The values entered for this proxy will be lost.",
        discardConfirmLabel: "Discard changes",
      });

      routesContainer?.addEventListener("click", (event) => {
        if (!(event.target instanceof Element)) return;
        if (event.target.closest("[data-reverse-proxy-route-add]")) {
          appendRoute();
          return;
        }
        const remove = event.target.closest("[data-reverse-proxy-route-remove]");
        if (remove && routeNodes().length > 1) {
          remove.closest("[data-reverse-proxy-route]")?.remove();
          syncRouteRemoveButtons();
        }
      });
      form.addEventListener("change", (event) => {
        if (!(event.target instanceof Element)) return;
        const route = event.target.closest("[data-reverse-proxy-route]");
        if (route && event.target.matches("[data-reverse-proxy-upstream-scheme], [data-reverse-proxy-trust-mode]")) updateTrustControls(route);
        if (route && event.target.matches("[data-reverse-proxy-upstream-scheme], [data-reverse-proxy-trust-mode]")) {
          const acknowledgement = form.querySelector("[data-reverse-proxy-insecure-ack]");
          if (acknowledgement instanceof HTMLInputElement) {
            acknowledgement.checked = false;
            acknowledgement.dataset.initialized = "true";
          }
        }
        if (event.target.matches("[data-reverse-proxy-scheme], [data-reverse-proxy-redirect]")) syncListenerControls();
        if (event.target.matches('[name="managed_dns"]')) {
          const hint = form.querySelector("[data-reverse-proxy-dns-guidance]");
          if (hint) hint.textContent = event.target.checked
            ? "Atlaso will reconcile exact A and AAAA records to the selected listener addresses when its authoritative DNS can serve this hostname."
            : "Configure the exact A and AAAA records for the selected listener addresses in your external DNS service.";
        }
      });
    }

    const fallback = document.getElementById(element.dataset.fallbackId || "");
    const edit = (rowData, launcher) => {
      const row = items.find((item) => String(item.id) === String(rowData?.id));
      openWizard(row || rowData, launcher);
    };
    const saveEnabled = async (cell) => {
      const row = cell.getRow().getData();
      if (!canWrite || row.is_new) return;
      const current = items.find((item) => String(item.id) === String(row.id));
      if (!current) {
        cell.restoreOldValue();
        return;
      }
      try {
        await submitPayload(serializeProxy(current, Boolean(cell.getValue())));
        const saved = items.find((item) => String(item.id) === String(row.id));
        if (saved) await cell.getRow().update(visibleProxyRow(saved));
      } catch (error) {
        cell.restoreOldValue();
        showError(error instanceof Error ? error.message : "The enabled state could not be saved.");
      }
    };
    const text = (cell) => escapeHtml(cell.getValue());
    const proxyValue = (cell, formatter = (value) => value) => cell.getRow().getData().is_new ? "" : formatter(cell.getValue());
    table = global.AtlasoUiPatterns.createGrid({
      element,
      fallback,
      pattern: "wizard-backed",
      permission: { allowed: canWrite, message: "You have read-only access to reverse proxies." },
      onOpenRow: canWrite ? (rowData, _row, event) => edit(rowData, event?.target) : null,
      options: {
        data: canWrite ? [...JSON.parse(element.dataset.reverseProxies || "[]"), { is_new: true, name: "" }] : JSON.parse(element.dataset.reverseProxies || "[]"),
        layout: "fitColumns",
        placeholder: "No reverse proxies are configured.",
        rowFormatter: (row) => row.getElement()?.classList.toggle("is-new-record", Boolean(row.getData().is_new)),
        rowContextMenu: canWrite ? [
          { label: "Edit reverse proxy", disabled: (row) => Boolean(row.getData().is_new), action: (_event, row) => edit(row.getData(), row.getElement()) },
          { label: "Delete reverse proxy", disabled: (row) => Boolean(row.getData().is_new), action: async (_event, row) => {
            const data = row.getData();
            if (typeof global.requestConfirmation !== "function" || !await global.requestConfirmation({
              title: `Delete reverse proxy ${data.name}?`,
              message: "This removes the proxy from desired state. Global Appliance Apply retires its listener, DNS, firewall, certificate reference, and directory entry.",
              label: "Delete reverse proxy",
              tone: "danger",
            })) return;
            try {
              const response = await fetch(`${saveUrl.replace(/\/save$/, "")}/${encodeURIComponent(data.id)}/delete`, {
                method: "POST", credentials: "same-origin",
                headers: { Accept: "application/json", "X-CSRF-Token": csrf },
              });
              if (!response.ok) throw new Error(await endpointMessage(response, "The reverse proxy could not be deleted."));
              await refreshData();
              showError("");
            } catch (error) {
              showError(error instanceof Error ? error.message : "The reverse proxy could not be deleted.");
            }
          } },
        ] : [],
        columns: [
          { title: "Name", field: "name", minWidth: 150, formatter: (cell) => cell.getRow().getData().is_new ? '<button class="add-row-button" type="button" data-reverse-proxy-add>+ Add reverse proxy here</button>' : text(cell) },
          { title: "Hostname", field: "hostname", minWidth: 170, formatter: (cell) => cell.getRow().getData().is_new ? "" : `<code>${text(cell)}</code>` },
          { title: "Listener", field: "port", minWidth: 180, formatter: (cell) => proxyValue(cell, (port) => `${escapeHtml(String(cell.getRow().getData().scheme).toUpperCase())} ${escapeHtml(port)} · ${(cell.getRow().getData().listeners || []).map((listener) => `${escapeHtml(listener.interface)} ${escapeHtml(listener.address)}`).join(", ")}`) },
          { title: "Paths", field: "path_count", width: 76, hozAlign: "center", formatter: (cell) => proxyValue(cell, (value) => String(value)) },
          { title: "Upstream trust", field: "insecure_upstream", minWidth: 140, formatter: (cell) => proxyValue(cell, (value) => value ? '<span class="status-pill warn">Insecure verification</span>' : "Trusted CA / fingerprint") },
          { title: "Publication", field: "public_listing", minWidth: 150, formatter: (cell) => proxyValue(cell, (value) => `${value ? "Public Services" : "Hidden"} · ${cell.getRow().getData().managed_dns ? "Atlaso DNS" : "External DNS"}`) },
          { title: "Enabled", field: "enabled", width: 84, hozAlign: "center", formatter: (cell) => cell.getRow().getData().is_new ? "" : (typeof global.atlasoBooleanFormatter === "function" ? global.atlasoBooleanFormatter(cell) : cell.getValue() ? "✓" : "×"), editor: "tickCross", editable: (cell) => canWrite && !cell.getRow().getData().is_new, cellEdited: saveEnabled },
        ],
      },
    }).table;

    element.addEventListener("click", (event) => {
      if (!(event.target instanceof Element)) return;
      const add = event.target.closest("[data-reverse-proxy-add]");
      if (add) {
        openWizard(null, add);
        return;
      }
      const editButton = event.target.closest("[data-reverse-proxy-edit]");
      if (editButton) edit(items.find((item) => String(item.id) === editButton.dataset.reverseProxyEdit), editButton);
    });
    fallback?.addEventListener("click", (event) => {
      if (!(event.target instanceof Element)) return;
      const button = event.target.closest("[data-reverse-proxy-edit]");
      if (button) edit(items.find((item) => String(item.id) === button.dataset.reverseProxyEdit), button);
    });

    try {
      const bootItems = JSON.parse(element.dataset.reverseProxies || "[]");
      const bootOptions = JSON.parse(element.dataset.listenerOptions || "[]");
      if (!Array.isArray(bootItems) || bootItems.length > MAX_ITEMS || !Array.isArray(bootOptions)) throw new Error("Initial reverse-proxy data is invalid.");
      items = bootItems;
      listenerOptions = bootOptions;
      if (table) void table.setData?.(canWrite ? [...items.map(visibleProxyRow), { is_new: true, name: "" }] : items.map(visibleProxyRow));
      if (health) void health.refresh();
      void refreshData();
    } catch (error) {
      showError(error instanceof Error ? error.message : "Initial reverse-proxy data is invalid.");
    }

    return { refreshData, table, wizard, health };
  }

  const api = Object.freeze({ escapeHtml, pathsOverlap, routeHealthRow, healthDisplayRow, serializeProxy, visibleProxyRow, initialize });
  global.AtlasoReverseProxies = api;
  if (global.document?.readyState === "loading") global.document.addEventListener("DOMContentLoaded", initialize, { once: true });
  else if (global.document) initialize();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : window);

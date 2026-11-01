(() => {
  "use strict";

  const settingsFormIds = new Set([
    "appliance-settings-form",
    "authentication-lifetimes-settings-form",
    "vmware-ceip-settings-form",
  ]);

  function forwardExternalAutosaveInput(event) {
    const control = event.target;
    if (!(control instanceof HTMLElement)) return;
    let form = control.form;
    if (event.type === "tag-editor:change") {
      const editor = control.closest("[data-tag-editor]");
      const name = editor?.dataset.tagName || "";
      const owner = editor?.querySelector(`[data-tag-list]`);
      if (name && owner && editor.dataset.formId) {
        owner.querySelectorAll(`input[type="hidden"][name="${CSS.escape(name)}"]`).forEach((input) => {
          input.setAttribute("form", editor.dataset.formId);
        });
        form = document.getElementById(editor.dataset.formId);
      }
    }
    if (!(form instanceof HTMLFormElement) || !settingsFormIds.has(form.id) || form.contains(control)) return;
    if (event.type === "tag-editor:change") {
      form.dispatchEvent(new Event("tag-editor:change"));
    } else {
      form.dispatchEvent(new Event("change"));
    }
  }

  function safeText(root, selector, value, fallback = "Unknown") {
    const element = root.querySelector(selector);
    if (element) element.textContent = value === null || value === undefined || value === "" ? fallback : String(value);
  }

  function readableBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes <= 0) return "Unknown";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let size = bytes;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
  }

  function gridValue(value) {
    return value === null || value === undefined || value === "" ? "—" : String(value);
  }

  function initializeHardwareGrid(element, rows, columns, identity, emptyMessage) {
    if (!window.AtlasoUiPatterns || !window.Tabulator) return null;
    if (element.dataset.hardwareGridInitialized === "1") return element.atlasoHardwareController || null;
    element.dataset.hardwareGridInitialized = "1";
    let controller = null;
    try {
      controller = window.AtlasoUiPatterns.createGrid({
        element,
        fallback: `#${element.dataset.fallbackId}`,
        pattern: "read-only",
        emptyMessage,
        options: {
          data: Array.isArray(rows) ? rows : [],
          index: identity,
          layout: "fitColumns",
          height: "280px",
          placeholder: emptyMessage,
          columns,
        },
        onReady: () => {
          const message = element.dataset.hardwareObservationError;
          if (message) {
            controller?.setError(message);
            element.classList.add("hidden");
            document.querySelector(`#${element.dataset.fallbackId}`)?.classList.remove("hidden");
          }
        },
      });
      element.atlasoHardwareController = controller;
      element.atlasoHardwareTable = controller.table;
      controller.table?.on?.("dataLoaded", () => {
        const message = element.dataset.hardwareObservationError;
        if (message) controller.setError(message);
      });
      return controller;
    } catch {
      element.dataset.atlasoGridState = "error";
      return null;
    }
  }

  function setInventoryState(root, selector, state, count) {
    const element = root.querySelector(selector);
    if (!element) return;
    const countKnown = Number.isFinite(Number(count));
    const healthy = state === "available" || state === "healthy" || state === "ok";
    element.className = `status-pill ${healthy ? "good" : state === "failed" || state === "unknown" ? "warn" : "muted"}`;
    const labels = { failed: "Check failed", unknown: "Unknown", unsupported: "Unsupported", not_supported: "Unsupported", unavailable: "Unavailable", not_checked: "Not checked" };
    element.textContent = labels[state] || `${countKnown ? count : ""} ${selector.includes("disk") ? "disks" : "adapters"}`.trim();
  }

  function updateSummary(root, hardware, tools) {
    const manufacturer = hardware.manufacturer || hardware.sys_vendor || "";
    const model = hardware.model || hardware.product_name || "";
    safeText(root, "[data-hardware-model]", [manufacturer, model].filter(Boolean).join(" / "));
    safeText(root, "[data-hardware-architecture]", hardware.architecture);
    const cpuCount = Number(hardware.cpu_count);
    const cpu = [hardware.cpu, Number.isFinite(cpuCount) && cpuCount > 0 ? `${cpuCount} logical CPUs` : ""].filter(Boolean).join(" · ");
    safeText(root, "[data-hardware-cpu]", cpu);
    safeText(root, "[data-hardware-memory]", readableBytes(hardware.memory_bytes));
    safeText(root, "[data-hardware-kernel]", hardware.kernel);
    const provider = String(hardware.platform || hardware.detected || tools?.provider || "unknown").toLowerCase();
    const platform = root.querySelector("[data-hardware-platform]");
    if (platform) {
      platform.textContent = ({ vmware: "VMware", hyperv: "Microsoft Hyper-V", microsoft: "Microsoft Hyper-V", kvm: "KVM / QEMU", qemu: "KVM / QEMU", baremetal: "Physical appliance", none: "Physical appliance" })[provider] || "Unknown platform";
      platform.className = `status-pill ${["vmware", "hyperv", "microsoft", "kvm", "qemu", "baremetal", "none"].includes(provider) ? "good" : "warn"}`;
    }
  }

  function updateFallbackTable(root, fallbackId, rows, type, state, reason = "") {
    const table = root.querySelector(`#${fallbackId}`);
    const body = table?.tBodies?.[0];
    if (!body) return;
    body.replaceChildren();
    if (["failed", "unknown", "unsupported", "unavailable", "not_supported"].includes(state)) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = type === "disks" ? 7 : 6;
      cell.className = "muted";
      cell.textContent = reason || (state === "failed" ? "Hardware inventory check failed." : state === "unsupported" || state === "not_supported" ? "Hardware inventory is not supported on this appliance." : "Hardware inventory is unavailable.");
      return;
    }
    if (!Array.isArray(rows) || rows.length === 0) {
      const row = body.insertRow();
      const cell = row.insertCell();
      cell.colSpan = type === "disks" ? 7 : 6;
      cell.className = "muted";
      cell.textContent = type === "disks" ? "No disks were reported by the host inventory." : "No network adapters were reported by the host inventory.";
      return;
    }
    rows.forEach((item) => {
      const row = body.insertRow();
      const values = type === "disks"
        ? [item.device_path, item.model, item.serial, readableBytes(item.size_bytes), item.transport, item.filesystem_type, item.mount_path]
        : [item.name, item.mac, item.driver, item.link_state, item.speed_mbps ? `${item.speed_mbps} Mbps` : "", Array.isArray(item.addresses) ? item.addresses.join(", ") : item.addresses];
      values.forEach((value) => { row.insertCell().textContent = gridValue(value); });
    });
  }

  function setInventoryGridError(root, gridId, fallbackId, message) {
    const grid = root.querySelector(`#${gridId}`);
    if (!grid) return;
    grid.dataset.hardwareObservationError = message;
    grid.atlasoHardwareController?.setError(message);
    grid.classList.add("hidden");
    root.querySelector(`#${fallbackId}`)?.classList.remove("hidden");
  }

  function setInventoryGridData(element, rows, columns, identity, emptyMessage) {
    if (!element) return;
    delete element.dataset.hardwareObservationError;
    const alreadyInitialized = element.dataset.hardwareGridInitialized === "1";
    const controller = initializeHardwareGrid(element, rows, columns, identity, emptyMessage);
    if (!controller?.table) return;
    if (alreadyInitialized) {
      controller.setState("loading", "Updating hardware inventory…");
      controller.table.setData(rows);
    }
  }

  function updateInventory(root, hardware) {
    const inventory = hardware.inventory && typeof hardware.inventory === "object" ? hardware.inventory : {};
    const disks = Array.isArray(hardware.disks) ? hardware.disks : Array.isArray(inventory.disks) ? inventory.disks : [];
    const interfaces = Array.isArray(hardware.interfaces) ? hardware.interfaces : Array.isArray(inventory.interfaces) ? inventory.interfaces : [];
    const fallbackState = hardware.inventory_state || (hardware.status === "unsupported" ? "unsupported" : "unknown");
    const diskState = String(hardware.disk_inventory_state || hardware.disks_state || inventory.disk_state || fallbackState);
    const networkState = String(hardware.network_inventory_state || hardware.interfaces_state || inventory.network_state || fallbackState);
    setInventoryState(root, "[data-disk-inventory-state]", diskState, disks.length);
    setInventoryState(root, "[data-network-inventory-state]", networkState, interfaces.length);
    updateFallbackTable(root, "settings-disks-fallback", disks, "disks", diskState, hardware.disks_reason);
    updateFallbackTable(root, "settings-network-fallback", interfaces, "interfaces", networkState, hardware.interfaces_reason);
    const diskColumns = [
      { title: "Device", field: "device_path", minWidth: 150 },
      { title: "Model", field: "model", minWidth: 150 },
      { title: "Serial", field: "serial", minWidth: 130 },
      { title: "Capacity", field: "size_bytes", minWidth: 110, formatter: (cell) => readableBytes(cell.getValue()) },
      { title: "Transport", field: "transport", minWidth: 110 },
      { title: "Filesystem", field: "filesystem_type", minWidth: 110 },
      { title: "Mount", field: "mount_path", minWidth: 150 },
    ];
    const networkColumns = [
      { title: "Name", field: "name", minWidth: 100 },
      { title: "MAC", field: "mac", minWidth: 150 },
      { title: "Driver", field: "driver", minWidth: 110 },
      { title: "Link", field: "link_state", minWidth: 90 },
      { title: "Speed", field: "speed_mbps", minWidth: 100, formatter: (cell) => cell.getValue() ? `${cell.getValue()} Mbps` : "—" },
      { title: "Addresses", field: "addresses", minWidth: 190, formatter: (cell) => Array.isArray(cell.getValue()) ? cell.getValue().join(", ") : gridValue(cell.getValue()) },
    ];
    const inventories = [
      { grid: "settings-disks-grid", fallback: "settings-disks-fallback", rows: disks, columns: diskColumns, key: "device_path", state: diskState, type: "disks", empty: "No disks were reported by the host inventory." },
      { grid: "settings-network-grid", fallback: "settings-network-fallback", rows: interfaces, columns: networkColumns, key: "name", state: networkState, type: "interfaces", empty: "No network adapters were reported by the host inventory." },
    ];
    inventories.forEach((inventoryState) => {
      const grid = root.querySelector(`#${inventoryState.grid}`);
      if (["available", "healthy", "ok"].includes(inventoryState.state)) {
        setInventoryGridData(grid, inventoryState.rows, inventoryState.columns, inventoryState.key, inventoryState.empty);
        return;
      }
      const defaultMessage = ["failed", "unknown", "unsupported", "unavailable", "not_supported"].includes(inventoryState.state)
        ? inventoryState.state === "failed" ? "Hardware inventory check failed." : inventoryState.state === "unsupported" || inventoryState.state === "not_supported" ? "Hardware inventory is not supported on this appliance." : "Hardware inventory is unavailable."
        : "Hardware inventory has not been checked.";
      const message = (inventoryState.type === "disks" ? hardware.disks_reason : hardware.interfaces_reason) || defaultMessage;
      setInventoryGridError(root, inventoryState.grid, inventoryState.fallback, message);
    });
  }

  function describeTargetPackages(packages, plan) {
    if (!plan || typeof plan.package_change !== "boolean") return "Package plan unavailable. Check status before installation.";
    if (plan.package_change === false) return "No package transaction planned.";
    if (!Array.isArray(packages) || packages.length === 0) {
      const version = plan.target_version ? ` Target agent version: ${plan.target_version}.` : "";
      return `The verified target package list is unavailable; check status again before review.${version}`;
    }
    return packages.map((item) => {
      if (typeof item === "string") return item;
      const name = item?.name || "Unknown package";
      const version = item?.version || "version unavailable";
      const architecture = item?.architecture || "architecture unavailable";
      return `${name} ${version} (${architecture})`;
    }).join("; ");
  }

  function describeServiceChanges(provider, plan) {
    if (!plan || !Array.isArray(plan.actions)) return "Service plan unavailable. Check status before installation.";
    const actions = Array.isArray(plan?.actions) ? plan.actions : [];
    if (!actions.length) return "No service changes required.";
    const descriptions = {
      vmware: "Enable and start vmtoolsd.service.",
      qemu: "Enable and start qemu-guest-agent.service.",
      kvm: "Enable and start qemu-guest-agent.service.",
      hyperv: "Disable and stop hv_fcopy_daemon.service; enable and start hv_kvp_daemon.service and hv_vss_daemon.service.",
    };
    return descriptions[provider] || "Required service changes are unavailable for the detected provider.";
  }

  function describeClockSafety(clockSafety, legacyClockSource) {
    if (!clockSafety || typeof clockSafety !== "object" || Array.isArray(clockSafety)) {
      return legacyClockSource ? String(legacyClockSource) : "Clock guard status is unavailable.";
    }
    const authorities = { ntp_client: "NTP client", ntp_server: "NTP server", vmware_tools: "VMware Tools" };
    const status = String(clockSafety.status || "unknown");
    const authority = authorities[clockSafety.authority] || clockSafety.authority || "unknown";
    const protection = clockSafety.protected === true ? "protected" : clockSafety.protected === false ? "not yet protected" : "protection unknown";
    const guard = `Authority: ${authority}. Guard: ${status}; ${protection}.`;
    const reason = clockSafety.reason ? ` ${clockSafety.reason}` : "";
    return `${guard}${reason}`;
  }

  function updateGuestTools(root, tools) {
    const provider = String(tools.provider || "");
    const state = String(tools.state || "unknown");
    const requiredUnits = {
      vmware: ["vmtoolsd.service"], qemu: ["qemu-guest-agent.service"],
      hyperv: ["hv_kvp_daemon.service", "hv_vss_daemon.service", "hv_fcopy_daemon.service"],
    }[provider] || [];
    const currentServices = (Array.isArray(tools.services) ? tools.services : [])
      .filter((service) => requiredUnits.includes(service.unit) || service.active === true || service.enabled === true)
      .map((service) => {
        if (service.load_state === "not-found") return `${service.unit}: not installed`;
        const active = service.active_state || (service.active === true ? "active" : service.active === false ? "stopped" : "unknown");
        const enabled = service.enabled_state || (service.enabled === true ? "enabled" : service.enabled === false ? "disabled" : "unknown");
        return `${service.unit}: ${active} / ${enabled}`;
      });
    safeText(root, "[data-guest-tools-effective-services]", currentServices.join("; "));
    const knownProvider = ["vmware", "hyperv", "qemu", "kvm"].includes(provider);
    const providerLabel = ({ vmware: "VMware open-vm-tools", hyperv: "Microsoft Hyper-V Linux integration", qemu: "KVM / QEMU guest agent", kvm: "KVM / QEMU guest agent" })[provider] || (provider === "baremetal" ? "Physical appliance — guest tools optional" : provider || "Unknown");
    const stateLabel = ({ missing: "Not installed", stopped: "Installed, stopped", healthy: "Running and healthy", unsupported: "Unsupported", unknown: "Status unknown", failed: "Check failed", not_checked: "Not checked" })[state] || state;
    const stateElement = root.querySelector("[data-guest-tools-state]");
    if (stateElement) {
      stateElement.textContent = stateLabel;
      stateElement.className = `status-pill ${state === "healthy" ? "good" : ["missing", "stopped"].includes(state) ? "warn" : "muted"}`;
    }
    safeText(root, "[data-guest-tools-provider]", providerLabel);
    safeText(root, "[data-guest-tools-version]", tools.version, state === "missing" ? "Not installed" : "Unavailable");
    const plan = tools.plan && typeof tools.plan === "object" ? tools.plan : null;
    const packageChange = plan?.package_change === true;
    const targetPackageList = tools.target_packages || plan?.target_packages;
    const targetPackageListKnown = Array.isArray(targetPackageList) && targetPackageList.length > 0;
    const packageSource = packageChange
      ? tools.available === true ? "Verified offline package closure" : "Verified package closure unavailable"
      : plan?.package_change === false ? "No package transaction required" : "Package plan unavailable";
    safeText(root, "[data-guest-tools-source]", packageSource);
    const targetPackages = describeTargetPackages(targetPackageList, plan);
    safeText(root, "[data-guest-tools-packages]", targetPackages);
    const serviceChanges = describeServiceChanges(provider, plan);
    safeText(root, "[data-guest-tools-services]", serviceChanges);
    const rebootImpact = tools.reboot_impact || (tools.reboot_required === true ? "A system reboot is required." : tools.reboot_required === false ? "No system reboot is expected." : "System reboot impact is unknown.");
    safeText(root, "[data-guest-tools-reboot]", `${actionsRequireServiceWork(plan) ? "The listed service actions may start or stop services. " : ""}${rebootImpact}`);
    const clockSafety = describeClockSafety(tools.clock_safety, tools.clock_source);
    safeText(root, "[data-guest-tools-clock]", clockSafety);
    safeText(root, "[data-guest-tools-summary]", tools.reason || tools.summary || (state === "healthy" ? "The compatible guest integration is running." : "Guest tools remain optional; explicitly review maintenance before installation."));
    const actionsMessage = root.querySelector("[data-guest-tools-action-message]");
    if (actionsMessage && tools.reason) {
      actionsMessage.textContent = String(tools.reason);
      actionsMessage.classList.remove("hidden");
    } else if (actionsMessage) {
      actionsMessage.textContent = "";
      actionsMessage.classList.add("hidden");
    }
    root.querySelectorAll("[data-guest-tools-provider-input]").forEach((input) => { input.value = knownProvider ? provider : ""; });
    const digest = String(tools.review_digest || "");
    const digestInput = root.querySelector("[data-guest-tools-review-digest]");
    if (digestInput) digestInput.value = digest;
    const checkButton = root.querySelector("[data-guest-tools-check-button]");
    if (checkButton) checkButton.disabled = !knownProvider || root.dataset?.maintenanceActive === "true";
    const installButton = root.querySelector("[data-guest-tools-install-button]");
    if (installButton) installButton.disabled = !knownProvider || tools.available !== true || !/^[0-9a-f]{64}$/i.test(digest) || (state === "healthy" && !packageChange) || !plan || typeof plan.package_change !== "boolean" || !Array.isArray(plan.actions) || (packageChange && !targetPackageListKnown);
    if (installButton && root.dataset?.maintenanceActive === "true") installButton.disabled = true;
    const installForm = root.querySelector("[data-guest-tools-install]");
    if (installForm) {
      installForm.dataset.confirmMessage = [
        `Detected provider: ${providerLabel}.`,
        `Package transaction: ${targetPackages}`,
        `Service changes: ${serviceChanges}`,
        `Restart and reboot impact: ${actionsRequireServiceWork(plan) ? "The listed service actions may start or stop services. " : ""}${rebootImpact}`,
        `Clock authority and guard: ${clockSafety}`,
        `Package source: ${packageSource}.`,
        "A bounded audited task will record this maintenance in Tasks.",
      ].join("\n\n");
    }
  }

  function actionsRequireServiceWork(plan) {
    return Array.isArray(plan?.actions) && plan.actions.includes("enable-required-services");
  }

  async function refreshHardware(root, { reportFailure = true } = {}) {
    const state = root.querySelector("[data-hardware-load-state]");
    const refresh = root.querySelector("[data-hardware-refresh]");
    if (refresh) refresh.disabled = true;
    if (state) {
      state.textContent = "Checking hardware and guest-tools status…";
      state.className = "alert muted";
    }
    try {
      const response = await fetch(root.dataset.statusUrl, { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`Hardware status request failed (${response.status}).`);
      const payload = await response.json();
      if (!payload || typeof payload !== "object" || !payload.hardware || !payload.guest_tools) throw new Error("Hardware status response was incomplete.");
      const task = payload.maintenance_task;
      const active = task && typeof task.job_id === "string" && ["pending", "running"].includes(task.status);
      root.dataset.maintenanceActive = active ? "true" : "false";
      updateSummary(root, payload.hardware, payload.guest_tools);
      updateInventory(root, payload.hardware);
      updateGuestTools(root, payload.guest_tools);
      if (active) {
        const message = root.querySelector("[data-guest-tools-action-message]");
        if (message) {
          message.textContent = `Maintenance task ${task.job_id} is ${task.status} (${task.progress_percent || 0}%). Follow it in Tasks, then refresh Hardware after completion.`;
          message.className = "alert muted";
        }
        const link = root.querySelector("[data-guest-tools-task-link]");
        if (link) link.href = `${link.href.split("?")[0]}?job_id=${encodeURIComponent(task.job_id)}`;
      }
      if (state) {
        state.textContent = "Hardware status was checked. Inventory and guest-tool actions are read-only until an explicit task is submitted.";
        state.className = "alert success";
      }
    } catch (error) {
      if (state) {
        state.textContent = reportFailure ? (error instanceof Error ? error.message : "Hardware status check failed.") : "Hardware status is unavailable.";
        state.className = "alert warning";
      }
      updateGuestTools(root, { state: "unknown", reason: "Guest-tools status could not be verified. Retry the check before requesting maintenance." });
      ["settings-disks-fallback", "settings-network-fallback"].forEach((id) => updateFallbackTable(root, id, [], id.includes("disks") ? "disks" : "interfaces", "failed"));
      setInventoryState(root, "[data-disk-inventory-state]", "failed");
      setInventoryState(root, "[data-network-inventory-state]", "failed");
      setInventoryGridError(root, "settings-disks-grid", "settings-disks-fallback", "Hardware inventory check failed.");
      setInventoryGridError(root, "settings-network-grid", "settings-network-fallback", "Hardware inventory check failed.");
    } finally {
      if (refresh) refresh.disabled = false;
    }
  }

  async function submitGuestToolsCheck(root, form) {
    const button = form.querySelector("button[type='submit']");
    if (button) button.disabled = true;
    const message = root.querySelector("[data-guest-tools-action-message]");
    if (message) {
      message.textContent = "Submitting the audited guest-tools check task…";
      message.className = "alert muted";
    }
    try {
      const response = await fetch(form.action, { method: "POST", credentials: "same-origin", headers: { Accept: "application/json" }, body: new FormData(form) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || payload.message || "Guest-tools check could not be queued.");
      const jobId = String(payload.job_id || payload.task_id || "");
      root.dataset.maintenanceActive = "true";
      if (message) {
        message.textContent = jobId ? `Guest-tools check task ${jobId} was queued. Follow its progress in Tasks.` : "Guest-tools check was queued. Follow progress in Tasks.";
        message.className = "alert success";
      }
      await refreshHardware(root);
    } catch (error) {
      if (message) {
        message.textContent = error instanceof Error ? error.message : "Guest-tools check could not be queued.";
        message.className = "alert error";
      }
    } finally {
      if (button) button.disabled = root.dataset.maintenanceActive === "true";
    }
  }

  function initializeSettingsHardware() {
    document.addEventListener("input", forwardExternalAutosaveInput, true);
    document.addEventListener("change", forwardExternalAutosaveInput, true);
    document.addEventListener("tag-editor:change", forwardExternalAutosaveInput, true);
    const root = document.querySelector("[data-settings-hardware]");
    if (!(root instanceof HTMLElement)) return;
    root.querySelectorAll("[data-hardware-grid]").forEach((grid) => grid.classList.add("hidden"));
    const panel = document.getElementById("settings-hardware");
    const tab = document.querySelector('[data-tab-target="settings-hardware"]');
    let checked = false;
    const checkAndLoad = () => {
      if (!checked) {
        checked = true;
        refreshHardware(root, { reportFailure: false });
      }
    };
    tab?.addEventListener("click", checkAndLoad);
    if (panel && !panel.hasAttribute("hidden")) checkAndLoad();
    root.querySelector("[data-hardware-refresh]")?.addEventListener("click", () => refreshHardware(root));
    const webTerminalEditor = root.closest("[data-settings-workspace]")?.querySelector('[data-tag-editor][data-tag-name="web_terminal_interfaces"]');
    if (webTerminalEditor instanceof HTMLElement) webTerminalEditor.dataset.formId = "appliance-settings-form";
    root.querySelector("[data-guest-tools-check]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      submitGuestToolsCheck(root, event.currentTarget);
    });
    root.querySelector("[data-guest-tools-install]")?.addEventListener("submit", (event) => {
      const form = event.currentTarget;
      if (!(form instanceof HTMLFormElement)) return;
      const button = form.querySelector("[data-guest-tools-install-button]");
      const digest = form.querySelector("[data-guest-tools-review-digest]");
      if (!(button instanceof HTMLButtonElement) || button.disabled || !(digest instanceof HTMLInputElement) || !/^[0-9a-f]{64}$/i.test(digest.value)) {
        event.preventDefault();
        const message = root.querySelector("[data-guest-tools-action-message]");
        if (message) {
          message.textContent = "Refresh status and review compatible package availability before requesting guest-tools maintenance.";
          message.className = "alert warning";
        }
      }
    });
  }

  document.addEventListener("DOMContentLoaded", initializeSettingsHardware);
})();

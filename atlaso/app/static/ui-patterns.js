(function initializeAtlasoUiPatterns(global) {
  "use strict";

  const GRID_PATTERNS = new Set(["direct-edit", "wizard-backed", "read-only"]);
  const FOCUSABLE_SELECTOR = [
    "a[href]",
    "button:not([disabled]):not([tabindex='-1'])",
    "input:not([disabled]):not([tabindex='-1'])",
    "select:not([disabled]):not([tabindex='-1'])",
    "textarea:not([disabled]):not([tabindex='-1'])",
    "[tabindex]:not([tabindex='-1'])",
  ].join(",");

  function resolveElement(value, root) {
    if (!value) return null;
    if (typeof value === "string") return (root || global.document)?.querySelector(value) || null;
    return value;
  }

  function isHidden(element) {
    return Boolean(element?.closest?.("[hidden], .hidden"));
  }

  function firstFocusable(root) {
    return [...(root?.querySelectorAll?.(FOCUSABLE_SELECTOR) || [])].find((element) => !isHidden(element)) || null;
  }

  function normalizeValidationResult(result) {
    if (result === false) return { valid: false };
    if (typeof result === "string") return { valid: false, message: result };
    if (result && typeof result === "object" && (result.valid === false || result.ok === false)) {
      return {
        valid: false,
        message: result.message || result.error || "",
        field: result.field || null,
        step: result.step,
      };
    }
    return { valid: true };
  }

  function compareGridValues(left, right) {
    if (left === right) return 0;
    if (left === null || left === undefined || left === "") return -1;
    if (right === null || right === undefined || right === "") return 1;
    if (typeof left === "number" && typeof right === "number") return left - right;
    if (typeof left === "boolean" && typeof right === "boolean") return Number(left) - Number(right);
    return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" });
  }

  function withPinnedLastSorters(columns, predicate) {
    return (columns || []).map((column) => {
      if (Array.isArray(column.columns)) {
        return { ...column, columns: withPinnedLastSorters(column.columns, predicate) };
      }
      if (column.headerSort === false) return column;
      const originalSorter = column.sorter;
      return {
        ...column,
        sorter: (left, right, leftRow, rightRow, columnComponent, direction, sorterParams) => {
          const leftPinned = Boolean(predicate(leftRow?.getData?.(), leftRow));
          const rightPinned = Boolean(predicate(rightRow?.getData?.(), rightRow));
          if (leftPinned !== rightPinned) {
            const pinnedOrder = leftPinned ? 1 : -1;
            return direction === "desc" ? -pinnedOrder : pinnedOrder;
          }
          if (typeof originalSorter === "function") {
            return originalSorter(left, right, leftRow, rightRow, columnComponent, direction, sorterParams);
          }
          return compareGridValues(left, right);
        },
      };
    });
  }

  function createGrid(config = {}) {
    const element = resolveElement(config.element, global.document);
    const pattern = config.pattern || "read-only";
    const fallback = resolveElement(
      config.fallback || (element?.dataset?.fallbackId ? `#${element.dataset.fallbackId}` : null),
      global.document,
    );
    const status = resolveElement(config.status, global.document);
    const permission = config.permission || { allowed: true };
    let table = null;
    let currentState = "loading";
    let tableBuilt = false;
    let loadFailed = false;

    if (!element) throw new Error("Atlaso grid foundation requires an element.");
    if (!GRID_PATTERNS.has(pattern)) throw new Error(`Unsupported Atlaso grid pattern: ${pattern}`);

    element.dataset.atlasoGridPattern = pattern;

    const setState = (state, message = "") => {
      currentState = state;
      element.dataset.atlasoGridState = state;
      element.setAttribute("aria-busy", state === "loading" ? "true" : "false");
      if (status) {
        status.textContent = message;
        status.dataset.state = state;
        status.classList?.toggle?.("hidden", !message);
      }
      if (state === "error") {
        fallback?.classList?.remove?.("hidden");
        element.classList?.add?.("hidden");
      }
    };

    const setError = (message) => setState("error", message || "The grid could not be loaded.");
    const showLoadedState = (rowCount) => {
      fallback?.classList?.add?.("hidden");
      element.classList?.remove?.("hidden");
      if (permission.allowed === false) {
        setState("permission-denied", permission.message || "You have read-only access.");
      } else {
        setState(rowCount ? "ready" : "empty", rowCount ? "" : (config.emptyMessage || options.placeholder || ""));
      }
    };
    const options = { layout: "fitColumns", ...(config.options || {}) };
    const pinRowsLast = config.pinRowsLast === false
      ? null
      : (typeof config.pinRowsLast === "function" ? config.pinRowsLast : (data) => Boolean(data?.is_new));
    if (pinRowsLast && Array.isArray(options.columns)) {
      options.columns = withPinnedLastSorters(options.columns, pinRowsLast);
    }
    const actions = config.rowActions || options.rowContextMenu || [];
    const enabledActions = permission.allowed === false ? [] : actions;
    const openRow = typeof config.onOpenRow === "function" ? config.onOpenRow : null;
    const originalFormatter = options.rowFormatter;

    if (actions.length) options.rowContextMenu = enabledActions;
    if (enabledActions.length || openRow) {
      options.rowFormatter = (row) => {
        originalFormatter?.(row);
        const rowElement = row?.getElement?.();
        if (!rowElement || rowElement.dataset.atlasoKeyboardActions === "true") return;
        rowElement.dataset.atlasoKeyboardActions = "true";
        rowElement.tabIndex = 0;
        rowElement.addEventListener("keydown", (event) => {
          if (event.key === "Enter" && openRow) {
            event.preventDefault();
            openRow(row.getData?.(), row, event);
            return;
          }
          if ((event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) && enabledActions.length) {
            event.preventDefault();
            const bounds = rowElement.getBoundingClientRect?.() || { left: 0, top: 0, height: 0 };
            rowElement.dispatchEvent(new global.MouseEvent("contextmenu", {
              bubbles: true,
              clientX: bounds.left + 16,
              clientY: bounds.top + Math.min(bounds.height || 16, 16),
            }));
          }
        });
      };
    }

    setState("loading", config.loadingMessage || "Loading…");
    try {
      if (typeof global.Tabulator !== "function") throw new Error("Tabulator is unavailable.");
      table = new global.Tabulator(element, options);
      if (openRow) {
        table.on?.("rowDblClick", (event, row) => {
          openRow(row?.getData?.(), row, event);
        });
      }
      table.on?.("tableBuilt", () => {
        tableBuilt = true;
        if (!loadFailed) {
          const rowCount = table.getDataCount?.("active") ?? table.getData?.("active")?.length ?? 0;
          showLoadedState(rowCount);
        }
        config.onReady?.(table);
      });
      table.on?.("dataLoadError", (error) => {
        loadFailed = true;
        setError(config.errorMessage || error?.message || "The grid data could not be loaded.");
      });
      table.on?.("dataLoaded", (data) => {
        loadFailed = false;
        if (!tableBuilt) return;
        const rowCount = Array.isArray(data)
          ? data.length
          : (table.getDataCount?.("active") ?? table.getData?.("active")?.length ?? 0);
        showLoadedState(rowCount);
      });
    } catch (error) {
      setError(config.errorMessage || error?.message || "The grid could not be loaded.");
      config.onError?.(error);
    }

    return {
      get table() {
        return table;
      },
      get state() {
        return currentState;
      },
      setState,
      setError,
      destroy() {
        table?.destroy?.();
        table = null;
        fallback?.classList?.remove?.("hidden");
        element.classList?.add?.("hidden");
      },
    };
  }

  function createWizard(config = {}) {
    const form = resolveElement(config.form, global.document);
    const dialog = resolveElement(config.dialog || form?.closest?.("dialog"), global.document);
    if (!form || !dialog) throw new Error("Atlaso wizard foundation requires a form and dialog.");

    const steps = (config.steps || []).map((step, index) => ({
      id: String(step.id ?? index),
      title: step.title || "",
      description: step.description || "",
    }));
    if (!steps.length) throw new Error("Atlaso wizard foundation requires at least one step.");

    const pages = [...form.querySelectorAll("[data-atlaso-wizard-step]")];
    const navButtons = [...form.querySelectorAll("[data-atlaso-wizard-nav]")];
    const kicker = form.querySelector("[data-atlaso-wizard-kicker]");
    const title = form.querySelector("[data-atlaso-wizard-title]");
    const description = form.querySelector("[data-atlaso-wizard-description]");
    const errorSummary = form.querySelector("[data-atlaso-wizard-error]");
    const backButton = form.querySelector("[data-atlaso-wizard-back]");
    const nextButton = form.querySelector("[data-atlaso-wizard-next]");
    const submitButton = form.querySelector("[data-atlaso-wizard-submit]");
    const cancelButtons = [...form.querySelectorAll("[data-atlaso-wizard-cancel]")];
    let currentIndex = 0;
    let highestIndex = 0;
    let skippedStepIds = new Set();
    let dirty = false;
    let launcher = null;
    let closing = false;
    let submitting = false;
    let invalidControl = null;

    form.setAttribute("data-atlaso-wizard", "");
    dialog.setAttribute("data-atlaso-wizard-dialog", "");
    errorSummary?.setAttribute?.("role", "alert");
    errorSummary?.setAttribute?.("aria-live", "assertive");

    const indexFor = (target) => {
      if (typeof target === "number") return Math.max(0, Math.min(target, steps.length - 1));
      const index = steps.findIndex((step) => step.id === String(target));
      return index < 0 ? 0 : index;
    };
    const pageAt = (index) => pages.find((page, pageIndex) => {
      const id = page.dataset.atlasoWizardStep;
      return id ? id === steps[index].id : pageIndex === index;
    });
    const navIndex = (button, fallbackIndex) => {
      const id = button.dataset.atlasoWizardNav || button.dataset.step;
      return id ? indexFor(id) : fallbackIndex;
    };
    const visibleStepIndices = () => steps
      .map((_step, index) => index)
      .filter((index) => !skippedStepIds.has(steps[index].id));
    const adjacentVisibleIndex = (index, direction) => {
      const visible = visibleStepIndices();
      const position = visible.indexOf(index);
      if (position < 0) return index;
      return visible[Math.max(0, Math.min(position + direction, visible.length - 1))];
    };
    const clearInvalidControl = () => {
      invalidControl?.removeAttribute?.("aria-invalid");
      invalidControl = null;
    };
    const setError = (message = "", field = null) => {
      if (errorSummary) {
        errorSummary.textContent = message;
        errorSummary.classList?.toggle?.("hidden", !message);
      }
      clearInvalidControl();
      let control = field;
      if (typeof field === "string") {
        control = form.elements?.namedItem?.(field) || form.querySelector(`[name="${global.CSS?.escape?.(field) || field}"]`);
      }
      if (control) {
        invalidControl = control;
        control.setAttribute?.("aria-invalid", "true");
        control.focus?.({ preventScroll: true });
      }
    };
    const clearError = () => setError();

    const showStep = (target, options = {}) => {
      const nextIndex = indexFor(target);
      if (options.unlock) highestIndex = Math.max(highestIndex, nextIndex);
      if (!options.force && nextIndex > highestIndex) return false;
      currentIndex = nextIndex;
      const step = steps[currentIndex];
      pages.forEach((page, pageIndex) => {
        const active = pageAt(currentIndex) === page;
        page.classList?.toggle?.("hidden", !active);
        page.toggleAttribute?.("hidden", !active);
        page.setAttribute?.("aria-hidden", active ? "false" : "true");
        if (!page.dataset.atlasoWizardStep) page.dataset.atlasoWizardStep = steps[pageIndex]?.id || String(pageIndex);
      });
      navButtons.forEach((button, buttonIndex) => {
        const index = navIndex(button, buttonIndex);
        const skipped = skippedStepIds.has(steps[index]?.id);
        const active = index === currentIndex;
        button.disabled = skipped || index > highestIndex;
        button.classList?.toggle?.("hidden", skipped);
        button.toggleAttribute?.("hidden", skipped);
        const navItem = button.closest?.("li");
        navItem?.classList?.toggle?.("hidden", skipped);
        navItem?.toggleAttribute?.("hidden", skipped);
        button.classList?.toggle?.("active", active);
        button.classList?.toggle?.("complete", index < currentIndex);
        button.setAttribute?.("aria-current", active ? "step" : "false");
        button.setAttribute?.("aria-disabled", button.disabled ? "true" : "false");
      });
      const visible = visibleStepIndices();
      const visiblePosition = visible.indexOf(currentIndex);
      const lastVisibleIndex = visible[visible.length - 1];
      if (kicker) kicker.textContent = `Step ${visiblePosition + 1} of ${visible.length}`;
      if (title) title.textContent = step.title;
      if (description) description.textContent = step.description;
      backButton?.classList?.toggle?.("hidden", currentIndex === 0);
      nextButton?.classList?.toggle?.("hidden", currentIndex === lastVisibleIndex);
      submitButton?.classList?.toggle?.("hidden", currentIndex !== lastVisibleIndex);
      if (submitButton) submitButton.disabled = currentIndex !== lastVisibleIndex || submitting;
      clearError();
      config.onStepChange?.({
        controller,
        form,
        dialog,
        step,
        index: currentIndex,
        previous: options.previous,
      });
      return true;
    };

    const nativeValidation = (index) => {
      const page = pageAt(index);
      const controls = [...(page?.querySelectorAll?.("input, select, textarea") || [])]
        .filter((control) => {
          if (control.disabled) return false;
          const hiddenAncestor = control.closest?.("[hidden], .hidden");
          return !hiddenAncestor || hiddenAncestor === page;
        });
      const invalid = controls.find((control) => typeof control.checkValidity === "function" && !control.checkValidity());
      if (!invalid) return { valid: true };
      invalid.reportValidity?.();
      return { valid: false, field: invalid };
    };

    const validate = async (target = currentIndex) => {
      const index = indexFor(target);
      clearError();
      const nativeResult = nativeValidation(index);
      if (!nativeResult.valid) {
        setError("", nativeResult.field);
        return false;
      }
      if (typeof config.validateStep !== "function") return true;
      const result = normalizeValidationResult(await config.validateStep({
        controller,
        form,
        dialog,
        step: steps[index],
        index,
      }));
      if (!result.valid) {
        if (result.step !== undefined) showStep(result.step, { force: true, unlock: true });
        setError(result.message, result.field);
        return false;
      }
      return true;
    };

    const next = async () => {
      if (!(await validate(currentIndex))) return false;
      let target = adjacentVisibleIndex(currentIndex, 1);
      if (typeof config.onNext === "function") {
        const result = await config.onNext({
          controller,
          form,
          dialog,
          step: steps[currentIndex],
          index: currentIndex,
          nextStep: steps[target],
        });
        if (result === false || result?.stay) return false;
        if (typeof result === "string" || typeof result === "number") target = indexFor(result);
        else if (result?.target !== undefined) target = indexFor(result.target);
      }
      target = Math.min(target, steps.length - 1);
      if (target === visibleStepIndices().at(-1)) {
        await config.prepareReview?.({ controller, form, dialog, step: steps[target], index: target });
      }
      return showStep(target, { unlock: true, previous: currentIndex });
    };

    const back = async () => {
      let target = adjacentVisibleIndex(currentIndex, -1);
      if (typeof config.onBack === "function") {
        const result = await config.onBack({
          controller,
          form,
          dialog,
          step: steps[currentIndex],
          index: currentIndex,
          previousStep: steps[target],
        });
        if (result === false || result?.stay) return false;
        if (typeof result === "string" || typeof result === "number") target = indexFor(result);
        else if (result?.target !== undefined) target = indexFor(result.target);
      }
      return showStep(target, { previous: currentIndex });
    };
    const confirmDiscard = async () => {
      if (!dirty) return true;
      if (typeof config.confirmDiscard === "function") return Boolean(await config.confirmDiscard({ controller, form, dialog }));
      if (typeof global.requestConfirmation === "function") {
        return Boolean(await global.requestConfirmation({
          title: config.discardTitle || "Discard unsaved changes?",
          message: config.discardMessage || "The values entered in this wizard will be lost.",
          confirmLabel: config.discardConfirmLabel || "Discard changes",
          tone: "danger",
        }));
      }
      return false;
    };
    const restoreLauncherFocus = () => {
      const target = launcher;
      launcher = null;
      global.requestAnimationFrame?.(() => target?.focus?.({ preventScroll: true }));
    };
    const close = (returnValue = "") => {
      dirty = false;
      closing = true;
      dialog.close?.(returnValue);
      closing = false;
      config.onClose?.({ controller, form, dialog, returnValue });
      restoreLauncherFocus();
    };
    const requestClose = async () => {
      if (!(await confirmDiscard())) return false;
      close("cancel");
      return true;
    };
    const reset = () => {
      form.reset?.();
      skippedStepIds = new Set();
      dirty = false;
      highestIndex = 0;
      currentIndex = 0;
      clearError();
      showStep(0, { force: true });
    };
    const open = async (options = {}) => {
      launcher = options.launcher || global.document?.activeElement || null;
      if (options.reset !== false) reset();
      await config.onOpen?.({ controller, form, dialog, context: options.context });
      highestIndex = Math.max(0, options.highestStep ? indexFor(options.highestStep) : 0);
      showStep(options.step || 0, { force: true });
      dialog.showModal?.();
      global.requestAnimationFrame?.(() => {
        const currentPage = pageAt(currentIndex);
        const firstControl = [...(currentPage?.querySelectorAll?.("input, select, textarea") || [])]
          .find((element) => element.type !== "hidden" && !element.disabled && !isHidden(element));
        const first = firstControl || firstFocusable(currentPage) || firstFocusable(dialog);
        first?.focus?.({ preventScroll: true });
      });
      return controller;
    };
    const markClean = () => {
      dirty = false;
    };

    const controller = {
      get currentStep() {
        return currentIndex;
      },
      get currentStepId() {
        return steps[currentIndex].id;
      },
      get highestStep() {
        return highestIndex;
      },
      get isDirty() {
        return dirty;
      },
      steps,
      showStep,
      next,
      back,
      validate,
      setError,
      clearError,
      open,
      close,
      requestClose,
      reset,
      markClean,
      setHighestStep(target) {
        highestIndex = Math.max(highestIndex, indexFor(target));
      },
      setSkippedSteps(targets = []) {
        skippedStepIds = new Set((targets || []).map(String).filter((id) => steps.some((step) => step.id === id)));
        showStep(currentIndex, { force: true });
      },
    };

    form.addEventListener?.("input", () => {
      dirty = true;
    });
    form.addEventListener?.("change", () => {
      dirty = true;
    });
    nextButton?.addEventListener?.("click", () => {
      next().catch((error) => setError(error?.message || "The next step could not be opened."));
    });
    backButton?.addEventListener?.("click", () => {
      back().catch((error) => setError(error?.message || "The previous step could not be opened."));
    });
    navButtons.forEach((button, buttonIndex) => {
      button.addEventListener?.("click", async () => {
        const target = navIndex(button, buttonIndex);
        if (target > highestIndex) return;
        if (target > currentIndex && !(await validate(currentIndex))) return;
        if (target === steps.length - 1) {
          await config.prepareReview?.({ controller, form, dialog, step: steps[target], index: target });
        }
        showStep(target, { previous: currentIndex });
      });
    });
    cancelButtons.forEach((button) => button.addEventListener?.("click", () => {
      requestClose().catch((error) => setError(error?.message || "The wizard could not be closed."));
    }));
    dialog.addEventListener?.("cancel", (event) => {
      event.preventDefault?.();
      requestClose().catch((error) => setError(error?.message || "The wizard could not be closed."));
    });
    dialog.addEventListener?.("close", () => {
      if (!closing) {
        dirty = false;
        config.onClose?.({ controller, form, dialog, returnValue: dialog.returnValue || "" });
        restoreLauncherFocus();
      }
    });
    dialog.addEventListener?.("keydown", (event) => {
      if (event.key !== "Tab") return;
      const focusable = [...dialog.querySelectorAll(FOCUSABLE_SELECTOR)].filter((element) => !isHidden(element));
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && global.document?.activeElement === first) {
        event.preventDefault();
        last.focus?.();
      } else if (!event.shiftKey && global.document?.activeElement === last) {
        event.preventDefault();
        first.focus?.();
      }
    });
    form.addEventListener?.("submit", async (event) => {
      event.preventDefault?.();
      if (currentIndex !== steps.length - 1) {
        await next();
        return;
      }
      if (!(await validate(currentIndex))) {
        return;
      }
      if (typeof config.onSubmit !== "function") {
        markClean();
        form.submit?.();
        return;
      }
      if (submitting) return;
      submitting = true;
      if (submitButton) submitButton.disabled = true;
      try {
        const result = await config.onSubmit({ controller, form, dialog, step: steps[currentIndex], index: currentIndex });
        const normalized = normalizeValidationResult(result);
        if (!normalized.valid) {
          if (normalized.step !== undefined) showStep(normalized.step, { force: true, unlock: true });
          setError(normalized.message, normalized.field);
          return;
        }
        markClean();
        if (result?.close !== false && config.closeOnSubmit !== false) close("submit");
      } catch (error) {
        setError(error?.message || "The request could not be completed. Check the connection and try again.");
      } finally {
        submitting = false;
        if (submitButton && currentIndex === steps.length - 1) submitButton.disabled = false;
      }
    });

    showStep(0, { force: true });
    return controller;
  }

  const api = Object.freeze({
    createGrid,
    createWizard,
    patterns: Object.freeze([...GRID_PATTERNS]),
  });

  global.AtlasoUiPatterns = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : window);

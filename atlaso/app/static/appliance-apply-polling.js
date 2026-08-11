(function exposeApplianceApplyPolling(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AtlasoApplianceApplyPolling = api;
})(typeof globalThis === "object" ? globalThis : this, function applianceApplyPollingFactory() {
  function createController(options) {
    const activeInterval = options.activeInterval || 2000;
    const idleInitialInterval = options.idleInitialInterval || 10000;
    const idleMaximumInterval = options.idleMaximumInterval || 60000;
    let idleInterval = idleInitialInterval;
    let timer = 0;
    let inFlight = null;
    let forceNextRequest = false;
    let stopped = false;
    let requestSequence = 0;

    const clearScheduled = () => {
      if (timer) options.clearTimer(timer);
      timer = 0;
    };

    const schedule = (delay) => {
      clearScheduled();
      if (!stopped && !options.isHidden()) timer = options.setTimer(() => refresh(), delay);
    };

    const refresh = () => {
      clearScheduled();
      if (stopped || options.isHidden()) return Promise.resolve(null);
      if (inFlight) return inFlight;
      const force = forceNextRequest;
      forceNextRequest = false;
      const sequence = typeof options.beginRequest === "function" ? options.beginRequest() : ++requestSequence;
      inFlight = Promise.resolve(options.request(force, sequence))
        .then(async (payload) => {
          const result = await options.onStatus(payload, { sequence });
          const active = typeof result?.active === "boolean" ? result.active : Boolean(payload && payload.active_task);
          if (active) {
            idleInterval = idleInitialInterval;
            schedule(activeInterval);
          } else {
            schedule(idleInterval);
            idleInterval = Math.min(idleInterval * 2, idleMaximumInterval);
          }
          return payload;
        })
        .catch((error) => {
          const active = typeof options.isActive === "function" && options.isActive();
          if (typeof options.onError === "function") options.onError(error, { active });
          if (active) {
            idleInterval = idleInitialInterval;
            schedule(activeInterval);
          } else {
            schedule(idleInterval);
            idleInterval = Math.min(idleInterval * 2, idleMaximumInterval);
          }
          return null;
        })
        .finally(() => {
          inFlight = null;
          if (forceNextRequest && !stopped && !options.isHidden()) schedule(0);
        });
      return inFlight;
    };

    return {
      refresh,
      refreshImmediately() {
        idleInterval = idleInitialInterval;
        forceNextRequest = true;
        return refresh();
      },
      visibilityChanged() {
        if (options.isHidden()) {
          clearScheduled();
          return Promise.resolve(null);
        }
        return this.refreshImmediately();
      },
      stop() {
        stopped = true;
        clearScheduled();
      },
    };
  }

  function taskActive(task) {
    return ["pending", "running"].includes(String(task?.status || ""));
  }

  function createMonitor(options) {
    let sequence = 0;
    let acceptedSequence = 0;
    let currentTask = null;
    let trackedJobId = "";

    const beginRequest = () => ++sequence;
    const hasTrackedTask = () => Boolean(trackedJobId);

    const acceptTask = (task, observedSequence = beginRequest()) => {
      const taskId = String(task?.id || "");
      if (!taskId) return false;
      const sameTask = String(currentTask?.id || "") === taskId;
      if (sameTask && observedSequence < acceptedSequence) return false;
      if (sameTask && !taskActive(currentTask) && taskActive(task)) return false;
      currentTask = task;
      acceptedSequence = observedSequence;
      if (taskActive(task)) trackedJobId = taskId;
      else if (trackedJobId === taskId) trackedJobId = "";
      options.onTask(task);
      return true;
    };

    let controller;
    controller = createController({
      activeInterval: options.activeInterval,
      idleInitialInterval: options.idleInitialInterval,
      idleMaximumInterval: options.idleMaximumInterval,
      beginRequest,
      request: options.requestStatus,
      onStatus: async (payload, context) => {
        if (currentTask && context.sequence < acceptedSequence) {
          return { active: hasTrackedTask() };
        }
        if (payload?.active_task) {
          if (!acceptTask(payload.active_task, context.sequence)) {
            return { active: hasTrackedTask() };
          }
          await options.onStatus(payload);
          if (typeof options.onRecovered === "function") options.onRecovered();
          return { active: true };
        }
        await options.onStatus(payload);
        if (!trackedJobId) {
          if (typeof options.onRecovered === "function") options.onRecovered();
          return { active: false };
        }
        const jobId = trackedJobId;
        const task = await options.requestTask(jobId, context.sequence);
        if (!task || String(task.id || "") !== jobId) {
          throw new Error("Appliance Apply returned an invalid task status response.");
        }
        const accepted = acceptTask(task, context.sequence);
        if (accepted && !taskActive(task)) {
          if (typeof options.onTerminal === "function") await options.onTerminal(task);
          controller.refreshImmediately();
        }
        if (typeof options.onRecovered === "function") options.onRecovered();
        return { active: hasTrackedTask() };
      },
      onError: (error, state) => {
        if (typeof options.onError === "function") options.onError(error, state);
      },
      isActive: hasTrackedTask,
      isHidden: options.isHidden,
      setTimer: options.setTimer,
      clearTimer: options.clearTimer,
    });

    return {
      refresh: controller.refresh,
      refreshImmediately: controller.refreshImmediately,
      visibilityChanged: controller.visibilityChanged,
      stop: controller.stop,
      observeTask(task) {
        const accepted = acceptTask(task);
        if (accepted) controller.refreshImmediately();
        return accepted;
      },
      trackJob(jobId) {
        const normalized = String(jobId || "");
        if (normalized) trackedJobId = normalized;
      },
      trackedJobId: () => trackedJobId,
    };
  }

  return { createController, createMonitor };
});

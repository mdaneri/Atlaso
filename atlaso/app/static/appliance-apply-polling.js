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
      inFlight = Promise.resolve(options.request(force))
        .then(async (payload) => {
          await options.onStatus(payload);
          if (payload && payload.active_task) {
            idleInterval = idleInitialInterval;
            schedule(activeInterval);
          } else {
            schedule(idleInterval);
            idleInterval = Math.min(idleInterval * 2, idleMaximumInterval);
          }
          return payload;
        })
        .catch((error) => {
          if (typeof options.onError === "function") options.onError(error);
          schedule(idleInterval);
          idleInterval = Math.min(idleInterval * 2, idleMaximumInterval);
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

  return { createController };
});

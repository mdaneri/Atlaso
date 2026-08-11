(function () {
  const managementScope = "/ui/management/";
  if (!("serviceWorker" in navigator) || !window.location.pathname.startsWith(managementScope)) {
    return;
  }

  window.addEventListener("load", async function () {
    try {
      const legacyScope = new URL("/", window.location.origin).href;
      const registrations = await navigator.serviceWorker.getRegistrations();
      await Promise.all(
        registrations
          .filter((registration) => registration.scope === legacyScope)
          .map((registration) => registration.unregister()),
      );
    } catch (_error) {
      // A failed migration must not prevent the management-scoped registration attempt.
    }
    navigator.serviceWorker.register("/service-worker.js", { scope: managementScope }).catch(function () {});
  });
})();

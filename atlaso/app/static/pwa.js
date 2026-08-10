(function () {
  const managementScope = "/ui/management/";
  if (!("serviceWorker" in navigator) || !window.location.pathname.startsWith(managementScope)) {
    return;
  }

  window.addEventListener("load", function () {
    navigator.serviceWorker.register("/service-worker.js", { scope: managementScope }).catch(function () {});
  });
})();

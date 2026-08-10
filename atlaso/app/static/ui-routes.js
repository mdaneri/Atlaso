(function () {
  const documentRoot = document.documentElement;
  const managementRoot = documentRoot.dataset.managementUiRoot || "/ui/management";
  const publicRoot = documentRoot.dataset.publicUiRoot || "/ui/public";

  function join(root, path) {
    const candidate = String(path || "").trim();
    if (!candidate || candidate === "/") {
      return root;
    }
    if (candidate === root || candidate.startsWith(`${root}/`)) {
      return candidate;
    }
    return `${root}${candidate.startsWith("/") ? candidate : `/${candidate}`}`;
  }

  window.AtlasoRoutes = Object.freeze({
    managementRoot,
    publicRoot,
    management: (path) => join(managementRoot, path),
    public: (path) => join(publicRoot, path),
  });
})();

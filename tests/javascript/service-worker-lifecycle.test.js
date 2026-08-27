const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const workerSource = fs.readFileSync("atlaso/app/static/service-worker.js", "utf8");
const cachePrefix = workerSource.match(/const ATLASO_CACHE_PREFIX = "([^"]+)";/)?.[1];
const cacheVersion = Number(workerSource.match(/ATLASO_CACHE_PREFIX}(\d+)`;/)?.[1]);
assert.ok(cachePrefix, "service worker must declare an Atlaso cache prefix");
assert.ok(Number.isInteger(cacheVersion), "service worker must declare a numeric cache version");
const currentCache = `${cachePrefix}${cacheVersion}`;
const previousCache = `${cachePrefix}${cacheVersion - 1}`;
const unrelatedCache = "operator-unrelated-cache";
const requiredFailureAsset = "/manifest.webmanifest";

function lifecycleScenario(failureMode = null) {
  const listeners = new Map();
  const entries = new Map([
    [previousCache, new Map([["/static/app.js", { ok: true }]])],
    [unrelatedCache, new Map([
      ["/operator-data", { ok: true }],
      [requiredFailureAsset, { ok: true, source: "unrelated" }],
      ["/static/offline.html", { ok: true, source: "unrelated" }],
    ])],
  ]);
  let skipWaitingCalls = 0;
  let claimCalls = 0;
  let networkUnavailable = false;
  let navigationResponse = null;

  function cacheKey(request) {
    return typeof request === "string" ? request : new URL(request.url).pathname + new URL(request.url).search;
  }

  const caches = {
    async open(name) {
      if (!entries.has(name)) entries.set(name, new Map());
      return {
        async put(asset, response) {
          if (failureMode === "cache-put" && asset === requiredFailureAsset) {
            throw new Error("simulated cache write failure");
          }
          entries.get(name).set(cacheKey(asset), response);
        },
        async match(request) {
          return entries.get(name).get(cacheKey(request));
        },
      };
    },
    async keys() {
      return [...entries.keys()];
    },
    async delete(name) {
      return entries.delete(name);
    },
  };

  const context = vm.createContext({
    caches,
    fetch: async (asset) => {
      if (networkUnavailable) throw new Error("simulated offline state");
      if (typeof asset === "object" && navigationResponse) return navigationResponse;
      if (asset === requiredFailureAsset && failureMode === "network") {
        throw new Error("simulated network failure");
      }
      return {
        ok: !(asset === requiredFailureAsset && failureMode === "http"),
        source: "network",
        clone() { return this; },
      };
    },
    self: {
      addEventListener(name, handler) {
        listeners.set(name, handler);
      },
      async skipWaiting() {
        skipWaitingCalls += 1;
      },
      clients: {
        async claim() {
          claimCalls += 1;
        },
      },
      location: { origin: "https://atlaso.example" },
    },
    URL,
    Response,
  });
  vm.runInContext(workerSource, context);

  async function dispatch(name) {
    let lifecyclePromise;
    listeners.get(name)({
      waitUntil(promise) {
        lifecyclePromise = promise;
      },
    });
    assert.ok(lifecyclePromise, `${name} must register a waitUntil promise`);
    return lifecyclePromise;
  }

  async function dispatchFetch(request) {
    let responsePromise;
    listeners.get("fetch")({
      request,
      respondWith(promise) {
        responsePromise = Promise.resolve(promise);
      },
    });
    assert.ok(responsePromise, "eligible fetch must register a response promise");
    return responsePromise;
  }

  return {
    dispatch,
    dispatchFetch,
    entries,
    setNavigationResponse(value) { navigationResponse = value; },
    setNetworkUnavailable(value) { networkUnavailable = value; },
    get skipWaitingCalls() { return skipWaitingCalls; },
    get claimCalls() { return claimCalls; },
  };
}

test("controlled update 503 remains authoritative instead of using the offline shell", async () => {
  const scenario = lifecycleScenario();
  await scenario.dispatch("install");
  await scenario.dispatch("activate");
  const controlled = {
    status: 503,
    headers: { get(name) { return name === "X-Atlaso-Update-Mode" ? "active" : null; } },
    source: "update-only",
  };
  scenario.setNavigationResponse(controlled);

  const response = await scenario.dispatchFetch({
    method: "GET",
    mode: "navigate",
    url: "https://atlaso.example/ui/management/appliance-update",
    headers: { get() { return "text/html"; } },
  });

  assert.equal(response, controlled);
  assert.equal(response.source, "update-only");
});

for (const failureMode of ["network", "http", "cache-put"]) {
  test(`required ${failureMode} failure rejects installation and preserves the complete cache`, async () => {
    const scenario = lifecycleScenario(failureMode);

    await assert.rejects(scenario.dispatch("install"));

    assert.equal(scenario.skipWaitingCalls, 0);
    assert.equal(scenario.claimCalls, 0);
    assert.equal(scenario.entries.has(previousCache), true);
    assert.equal(scenario.entries.has(currentCache), false);
    assert.equal(scenario.entries.has(unrelatedCache), true);
  });
}

test("complete precache activates and retires only prior Atlaso management caches", async () => {
  const scenario = lifecycleScenario();

  await scenario.dispatch("install");
  assert.equal(scenario.skipWaitingCalls, 1);
  assert.equal(scenario.entries.has(previousCache), true);
  assert.equal(scenario.entries.get(currentCache).has(requiredFailureAsset), true);

  await scenario.dispatch("activate");
  assert.equal(scenario.claimCalls, 1);
  assert.equal(scenario.entries.has(currentCache), true);
  assert.equal(scenario.entries.has(previousCache), false);
  assert.equal(scenario.entries.has(unrelatedCache), true);
});

test("asset and offline fallback reads ignore overlapping unrelated cache entries", async () => {
  const scenario = lifecycleScenario();
  await scenario.dispatch("install");
  await scenario.dispatch("activate");

  const assetResponse = await scenario.dispatchFetch({
    method: "GET",
    mode: "no-cors",
    url: `https://atlaso.example${requiredFailureAsset}`,
    headers: { get() { return ""; } },
  });
  assert.equal(assetResponse.source, "network");

  scenario.setNetworkUnavailable(true);
  const offlineResponse = await scenario.dispatchFetch({
    method: "GET",
    mode: "navigate",
    url: "https://atlaso.example/ui/management/dashboard",
    headers: { get() { return "text/html"; } },
  });
  assert.equal(offlineResponse.source, "network");
});

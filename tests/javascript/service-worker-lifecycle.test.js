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
    [unrelatedCache, new Map([["/operator-data", { ok: true }]])],
  ]);
  let skipWaitingCalls = 0;
  let claimCalls = 0;

  const caches = {
    async open(name) {
      if (!entries.has(name)) entries.set(name, new Map());
      return {
        async put(asset, response) {
          if (failureMode === "cache-put" && asset === requiredFailureAsset) {
            throw new Error("simulated cache write failure");
          }
          entries.get(name).set(asset, response);
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
      if (asset === requiredFailureAsset && failureMode === "network") {
        throw new Error("simulated network failure");
      }
      return {
        ok: !(asset === requiredFailureAsset && failureMode === "http"),
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

  return {
    dispatch,
    entries,
    get skipWaitingCalls() { return skipWaitingCalls; },
    get claimCalls() { return claimCalls; },
  };
}

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

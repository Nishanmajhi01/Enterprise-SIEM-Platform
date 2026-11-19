const test = require("node:test");
const assert = require("node:assert/strict");
const Module = require("node:module");

test("DDoS detection emits one alert for a burst of concurrent events", async () => {
  const servicePath = require.resolve("../services/alertService");
  const detectorPath = require.resolve("../detection/ddos");
  const original = require.cache[servicePath];
  let calls = 0;
  require.cache[servicePath] = {
    id: servicePath, filename: servicePath, loaded: true,
    exports: { createSecurityAlert: async data => {
      calls++;
      await new Promise(resolve => setImmediate(resolve));
      return { alert: { id: calls, ...data } };
    }}
  };
  delete require.cache[detectorPath];
  try {
    const detect = require("../detection/ddos");
    const workspaceId = "bf763ca9-113f-40c4-b5cf-ed412a6e0474";
    assert.equal(await detect("invalid-ip", workspaceId), null);
    const results = await Promise.all(
      Array.from({ length: 150 }, () => detect("192.0.2.44", workspaceId))
    );
    assert.equal(calls, 1);
    assert.equal(results.filter(Boolean).length, 1);
    assert.equal(await detect("192.0.2.44", workspaceId), null);
  } finally {
    delete require.cache[detectorPath];
    if (original) require.cache[servicePath] = original;
    else delete require.cache[servicePath];
  }
});

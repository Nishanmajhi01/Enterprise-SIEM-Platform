const test = require("node:test");
const assert = require("node:assert/strict");

test("phishing heuristic validates web URLs and does not flag benign hostname words", async () => {
  const servicePath = require.resolve("../services/alertService");
  const detectorPath = require.resolve("../detection/phishing");
  const original = require.cache[servicePath];
  const alerts = [];
  require.cache[servicePath] = { id: servicePath, filename: servicePath, loaded: true,
    exports: { createSecurityAlert: async data => { alerts.push(data); } } };
  delete require.cache[detectorPath];
  try {
    const detect = require("../detection/phishing");
    const workspaceId = "bf763ca9-113f-40c4-b5cf-ed412a6e0474";
    assert.equal(await detect(null, workspaceId), false);
    assert.equal(await detect("javascript:alert(1)", workspaceId), false);
    assert.equal(await detect("not-a-url-login", workspaceId), false);
    assert.equal(await detect("https://login.example.org/about", workspaceId), false);
    assert.equal(await detect("https://example.org/account/verify", workspaceId), true);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].workspaceId, workspaceId);
  } finally {
    delete require.cache[detectorPath];
    if (original) require.cache[servicePath] = original;
    else delete require.cache[servicePath];
  }
});

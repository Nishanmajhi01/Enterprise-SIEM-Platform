const test = require("node:test");
const assert = require("node:assert/strict");
const { corsOrigin, allowedOrigins } = require("../config/corsOrigins");

test("default local frontend origins are trusted", () => {
  assert.ok(allowedOrigins().includes("http://localhost:5173"));
  corsOrigin("http://localhost:5173", (error, allowed) => {
    assert.equal(error, null);
    assert.equal(allowed, true);
  });
});

test("unlisted browser origins are rejected", () => {
  corsOrigin("https://untrusted.example", (error, allowed) => {
    assert.match(error.message, /not allowed/);
    assert.equal(allowed, undefined);
  });
});

test("explicit LAN frontend origins can be configured", () => {
  const previous = process.env.CORS_ALLOWED_ORIGINS;
  try {
    process.env.CORS_ALLOWED_ORIGINS = "http://192.168.1.50:5173";
    corsOrigin("http://192.168.1.50:5173", (error, allowed) => {
      assert.equal(error, null);
      assert.equal(allowed, true);
    });
  } finally {
    if (previous === undefined) delete process.env.CORS_ALLOWED_ORIGINS;
    else process.env.CORS_ALLOWED_ORIGINS = previous;
  }
});

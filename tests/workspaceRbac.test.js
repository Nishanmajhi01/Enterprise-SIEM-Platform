"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const rbac = require("../middleware/workspaceRbac");

function check(allowed, role, options = {}) {
  let status;
  let body;
  let nextCalled = false;
  const req = {
    user: options.authenticated === false ? undefined : { id: 1 },
    workspaceId: options.membership === false ? undefined : "test-workspace",
    workspaceMembership: options.membership === false ? undefined : { role },
    workspaceRole: role
  };
  const res = {
    status(code) { status = code; return this; },
    json(value) { body = value; return this; }
  };
  rbac(allowed)(req, res, () => { nextCalled = true; });
  return { status, body, nextCalled };
}

test("viewer may access read-only workspace resources", () => {
  assert.equal(check(["ADMIN", "ANALYST", "VIEWER"], "VIEWER").nextCalled, true);
});

test("viewer cannot execute analyst or admin actions", () => {
  const result = check(["ADMIN", "ANALYST"], "VIEWER");
  assert.equal(result.status, 403);
  assert.equal(result.nextCalled, false);
});

test("analyst can execute analyst actions", () => {
  assert.equal(check(["ADMIN", "ANALYST"], "ANALYST").nextCalled, true);
});

test("admin can execute admin-only actions", () => {
  assert.equal(check(["ADMIN"], "ADMIN").nextCalled, true);
  assert.equal(check(["ADMIN"], "ANALYST").status, 403);
});

test("unauthenticated requests are rejected", () => {
  assert.equal(check(["VIEWER"], "VIEWER", { authenticated: false }).status, 401);
});

test("workspace membership is required", () => {
  assert.equal(check(["VIEWER"], "VIEWER", { membership: false }).status, 403);
});

test("invalid role configuration fails closed", () => {
  assert.throws(() => rbac(["SUPERADMIN"]), /Invalid workspace RBAC configuration/);
  assert.throws(() => rbac([]), /Invalid workspace RBAC configuration/);
});

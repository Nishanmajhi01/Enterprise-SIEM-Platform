"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");

const workspaceRbac = require("../middleware/workspaceRbac");

function invoke(middleware, request) {
  let status = 200;
  let payload;
  let proceeded = false;
  const response = {
    status(code) { status = code; return this; },
    json(body) { payload = body; return this; }
  };
  middleware(request, response, () => { proceeded = true; });
  return { status, payload, proceeded };
}

test("workspace RBAC rejects unauthenticated requests", () => {
  const result = invoke(workspaceRbac("ADMIN"), {});
  assert.equal(result.status, 401);
  assert.equal(result.proceeded, false);
});

test("workspace RBAC rejects JWT users without a verified membership", () => {
  const result = invoke(workspaceRbac("ADMIN"), { user: { id: 1, role: "ADMIN" } });
  assert.equal(result.status, 403);
  assert.equal(result.proceeded, false);
});

for (const role of ["ANALYST", "VIEWER", "UNKNOWN"]) {
  test(`workspace RBAC denies ${role} from ADMIN-only endpoints`, () => {
    const result = invoke(workspaceRbac("ADMIN"), {
      user: { id: 2, role: "ADMIN" },
      workspaceId: "workspace-1",
      workspaceMembership: { role },
      workspaceRole: role
    });
    assert.equal(result.status, 403);
    assert.equal(result.proceeded, false);
  });
}

test("workspace RBAC permits verified workspace ADMIN regardless of platform role", () => {
  const result = invoke(workspaceRbac("ADMIN"), {
    user: { id: 3, role: "VIEWER" },
    workspaceId: "workspace-1",
    workspaceMembership: { role: "ADMIN" },
    workspaceRole: "ADMIN"
  });
  assert.equal(result.proceeded, true);
});

test("workspace RBAC supports multiple allowed roles", () => {
  const result = invoke(workspaceRbac("ADMIN", "ANALYST"), {
    user: { id: 3 }, workspaceId: "workspace-1",
    workspaceMembership: { role: "ANALYST" }, workspaceRole: "ANALYST"
  });
  assert.equal(result.proceeded, true);
});

test("workspace RBAC rejects invalid configurations", () => {
  assert.throws(() => workspaceRbac(), /Invalid workspace RBAC/);
  assert.throws(() => workspaceRbac("SUPERADMIN"), /Invalid workspace RBAC/);
});

test("email action tokens are hashed, expiring, and single-use", async () => {
  // Stub only the persistence boundary: no live DB, accounts, or email required.
  const modelPath = require.resolve("../models/EmailActionToken");
  const servicePath = require.resolve("../services/emailActionTokens");
  const originalModel = require.cache[modelPath];
  const originalService = require.cache[servicePath];
  const records = [];
  const fakeModel = {
    async create(data) {
      const record = { ...data, async save() {} };
      records.push(record);
      return record;
    },
    async findOne({ where, transaction, lock }) {
      assert.equal(lock, transaction.LOCK.UPDATE);
      return records.find(record =>
        record.tokenHash === where.tokenHash &&
        record.purpose === where.purpose &&
        record.consumedAt == null &&
        record.expiresAt > new Date()
      ) || null;
    }
  };
  try {
    require.cache[modelPath] = { id: modelPath, filename: modelPath, loaded: true, exports: fakeModel };
    delete require.cache[servicePath];
    const { issue, consume } = require("../services/emailActionTokens");
    const transaction = { LOCK: { UPDATE: "UPDATE" } };
    const token = await issue({
      purpose: "INVITE", email: "Person@Example.com",
      workspaceId: "workspace-1", workspaceRole: "VIEWER"
    });
    assert.match(token, /^[a-f0-9]{64}$/);
    assert.notEqual(records[0].tokenHash, token);
    assert.equal(records[0].email, "person@example.com");
    assert.ok(records[0].expiresAt > new Date());
    assert.equal((await consume({ token, purpose: "INVITE", transaction })).email, "person@example.com");
    assert.equal(await consume({ token, purpose: "INVITE", transaction }), null);
    const expired = await issue({
      purpose: "INVITE", email: "expired@example.com",
      workspaceId: "workspace-1", workspaceRole: "ANALYST"
    });
    records[1].expiresAt = new Date(Date.now() - 1000);
    assert.equal(await consume({ token: expired, purpose: "INVITE", transaction }), null);
    assert.equal(await consume({ token: "invalid", purpose: "INVITE", transaction }), null);
    await assert.rejects(() => consume({ token: expired, purpose: "INVITE" }), /transaction/);
    await assert.rejects(() => issue({
      purpose: "INVITE", email: "person@example.com",
      workspaceId: "workspace-1", workspaceRole: "SUPERADMIN"
    }), /workspace and role/);
  } finally {
    if (originalModel) require.cache[modelPath] = originalModel;
    else delete require.cache[modelPath];
    if (originalService) require.cache[servicePath] = originalService;
    else delete require.cache[servicePath];
  }
});

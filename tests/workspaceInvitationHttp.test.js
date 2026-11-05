"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const express = require("express");
const { createHash } = require("node:crypto");

// Integration-style HTTP tests with isolated model, email, and transaction stubs.
// No PostgreSQL connection, Resend request, or production user is involved.
test("invitation HTTP routes enforce permissions, delivery cleanup and safe acceptance", async () => {
  const overrides = new Map();
  const set = (path, exports) => {
    const id = require.resolve(path);
    overrides.set(id, require.cache[id]);
    require.cache[id] = { id, filename: id, loaded: true, exports };
  };
  const tokens = [];
  const members = [];
  const emails = [];
  let failDelivery = false;
  let currentUser = { id: 10, email: "admin@example.com", emailVerifiedAt: new Date() };
  let currentRole = "ADMIN";
  const workspace = { id: "workspace-1", name: "Test SOC", status: "ACTIVE" };
  const users = [
    currentUser,
    { id: 11, email: "recipient@example.com", emailVerifiedAt: new Date() },
    { id: 12, email: "other@example.com", emailVerifiedAt: new Date() }
  ];
  let nextToken = 1;
  const digest = raw => createHash("sha256").update(raw).digest("hex");
  const tokenService = {
    async issue({ email, workspaceId, workspaceRole }) {
      const raw = nextToken.toString(16).padStart(64, "0");
      nextToken++;
      tokens.push({ tokenHash: digest(raw), raw, purpose: "INVITE", email, workspaceId, workspaceRole, consumedAt: null, expiresAt: new Date(Date.now() + 100000) });
      return raw;
    },
    async consume({ token, transaction }) {
      const found = tokens.find(t => t.raw === token && !t.consumedAt && t.expiresAt > new Date());
      if (!found) return null;
      found.consumedAt = new Date();
      transaction.touched.push(found);
      return found;
    }
  };
  const tokenModel = {
    async destroy({ where }) {
      const index = tokens.findIndex(t => t.tokenHash === where.tokenHash);
      if (index >= 0) tokens.splice(index, 1);
    },
    async update(values, { where }) {
      for (const token of tokens) {
        if (token.email === where.email && token.workspaceId === where.workspaceId &&
            token.purpose === where.purpose && !token.consumedAt &&
            token.tokenHash !== where.tokenHash[Object.getOwnPropertySymbols(where.tokenHash)[0]]) {
          token.consumedAt = values.consumedAt;
        }
      }
    }
  };
  const membershipModel = {
    async findOne({ where }) {
      return members.find(m => m.userId === where.userId && m.workspaceId === where.workspaceId) || null;
    },
    async create(data) { members.push(data); return data; }
  };
  const userModel = {
    async findOne({ where }) { return users.find(u => u.email === where.email) || null; },
    async findByPk(id) { return users.find(u => u.id === id) || null; },
    async create(data) { const user = { ...data, id: 100 + users.length }; users.push(user); return user; }
  };
  const transactionDb = {
    async transaction(fn) {
      const tx = { touched: [] };
      try { return await fn(tx); }
      catch (error) {
        for (const record of tx.touched) record.consumedAt = null;
        throw error;
      }
    }
  };
  const auth = (req, _res, next) => { req.user = currentUser; next(); };
  const workspaceAuth = (req, _res, next) => {
    req.workspaceId = workspace.id;
    req.workspaceRole = currentRole;
    req.workspaceMembership = { role: currentRole };
    next();
  };
  let server;
  try {
    set("../config/database", { sequelize: transactionDb });
    set("../models/User", userModel);
    set("../models/Workspace", { findByPk: async () => workspace });
    set("../models/WorkspaceMembership", membershipModel);
    set("../models/EmailActionToken", tokenModel);
    set("../services/emailActionTokens", tokenService);
    set("../services/resendEmailService", {
      configured: () => true,
      async sendInvitationEmail({ to, token }) {
        if (failDelivery) throw new Error("Simulated provider rejection");
        emails.push({ to, token });
      }
    });
    set("../middleware/authMiddleware", auth);
    set("../middleware/workspaceAuth", workspaceAuth);
    const routeId = require.resolve("../routes/workspaceInvitationRoutes");
    overrides.set(routeId, require.cache[routeId]);
    delete require.cache[routeId];
    const router = require("../routes/workspaceInvitationRoutes");
    const app = express();
    app.use(express.json());
    app.use("/api/workspace-invitations", router);
    server = app.listen(0, "127.0.0.1");
    await new Promise(resolve => server.once("listening", resolve));
    const base = `http://127.0.0.1:${server.address().port}/api/workspace-invitations`;
    const post = async (path, body) => {
      const response = await fetch(base + path, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      return { status: response.status, body: await response.json() };
    };

    currentRole = "VIEWER";
    assert.equal((await post("/", { email: "recipient@example.com" })).status, 403);
    assert.equal(tokens.length, 0);

    currentRole = "ADMIN";
    failDelivery = true;
    assert.equal((await post("/", { email: "recipient@example.com" })).status, 503);
    assert.equal(tokens.length, 0, "failed delivery cleans up token");

    failDelivery = false;
    assert.equal((await post("/", { email: "recipient@example.com", role: "ANALYST" })).status, 202);
    const first = emails.at(-1).token;
    assert.equal((await post("/", { email: "recipient@example.com", role: "VIEWER" })).status, 202);
    const second = emails.at(-1).token;
    assert.ok(tokens.find(t => t.raw === first).consumedAt, "old invitation superseded");
    assert.equal(tokens.find(t => t.raw === second).consumedAt, null);

    currentUser = users[2]; // Wrong signed-in account cannot burn recipient's link.
    assert.equal((await post("/accept-existing", { token: second })).status, 400);
    assert.equal(tokens.find(t => t.raw === second).consumedAt, null);

    currentUser = users[1];
    assert.equal((await post("/accept-existing", { token: second })).status, 200);
    assert.equal(members.length, 1);
    assert.equal(members[0].role, "VIEWER");
    assert.equal((await post("/accept-existing", { token: second })).status, 400);
    assert.equal(members.length, 1);

    assert.equal((await post("/", { email: "fresh@example.com", role: "ANALYST" })).status, 202);
    const expired = emails.at(-1).token;
    tokens.find(t => t.raw === expired).expiresAt = new Date(0);
    assert.equal((await post("/accept-new", { token: expired, username: "Fresh Person", password: "a-strong-test-password" })).status, 400);
    assert.equal(users.some(u => u.email === "fresh@example.com"), false);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    for (const [id, prior] of overrides) {
      if (prior) require.cache[id] = prior;
      else delete require.cache[id];
    }
  }
});

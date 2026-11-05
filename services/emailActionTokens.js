"use strict";
const { randomBytes, randomUUID, createHash } = require("crypto");
const { Op } = require("sequelize");
const EmailActionToken = require("../models/EmailActionToken");

const TTL_MS = Object.freeze({
  VERIFY_EMAIL: 24 * 60 * 60 * 1000,
  INVITE: 48 * 60 * 60 * 1000,
  RESET_PASSWORD: 30 * 60 * 1000
});
const ROLES = new Set(["ADMIN", "ANALYST", "VIEWER"]);

function digest(raw) {
  if (typeof raw !== "string" || !/^[a-f0-9]{64}$/.test(raw)) return null;
  return createHash("sha256").update(raw).digest("hex");
}

async function issue({ purpose, email, userId = null, workspaceId = null, workspaceRole = null, transaction }) {
  if (!Object.hasOwn(TTL_MS, purpose)) throw new Error("Invalid token purpose");
  if (typeof email !== "string" || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("Invalid token email");
  }
  if (purpose === "INVITE" && (!workspaceId || !ROLES.has(workspaceRole))) {
    throw new Error("Invitations require workspace and role");
  }
  if (purpose !== "INVITE" && (!Number.isSafeInteger(userId) || userId <= 0)) {
    throw new Error("Account action requires user");
  }
  const token = randomBytes(32).toString("hex");
  await EmailActionToken.create({
    id: randomUUID(),
    tokenHash: digest(token),
    purpose,
    email: email.trim().toLowerCase(),
    userId,
    workspaceId,
    workspaceRole,
    expiresAt: new Date(Date.now() + TTL_MS[purpose])
  }, { transaction });
  return token;
}

// Must be invoked inside a DB transaction. Locks the row until commit, so
// concurrent consumers cannot both redeem a single-use token.
async function consume({ token, purpose, transaction }) {
  if (!transaction || !Object.hasOwn(TTL_MS, purpose)) throw new Error("Invalid token transaction");
  const tokenHash = digest(token);
  if (!tokenHash) return null;
  const record = await EmailActionToken.findOne({
    where: {
      tokenHash, purpose, consumedAt: null,
      expiresAt: { [Op.gt]: new Date() }
    },
    transaction,
    lock: transaction.LOCK.UPDATE
  });
  if (!record) return null;
  record.consumedAt = new Date();
  await record.save({ transaction });
  return record;
}

module.exports = { issue, consume };

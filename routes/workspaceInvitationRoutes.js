"use strict";
const express = require("express");
const bcrypt = require("bcrypt");
const { randomUUID } = require("crypto");
const rateLimit = require("express-rate-limit");
const { sequelize } = require("../config/database");
const User = require("../models/User");
const Workspace = require("../models/Workspace");
const WorkspaceMembership = require("../models/WorkspaceMembership");
const { issue, consume } = require("../services/emailActionTokens");
const { sendInvitationEmail, configured } = require("../services/resendEmailService");
const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");
const router = express.Router();
const throttle = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });
const validEmail = value => typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
const validToken = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const roles = ["ADMIN", "ANALYST", "VIEWER"];
const ineligible = () => { const error = new Error("Invitation is not eligible"); error.code = "INVITE_INELIGIBLE"; throw error; };

router.post("/", authenticate, workspaceAuth, workspaceRbac("ADMIN"), throttle, async (req, res) => {
  const { email, role = "VIEWER" } = req.body || {};
  if (!validEmail(email) || !roles.includes(role)) return res.status(400).json({ message: "Valid email and workspace role required" });
  if (!configured()) return res.status(503).json({ message: "Invitation email delivery is not configured" });
  const normalized = email.trim().toLowerCase();
  try {
    const existing = await User.findOne({ where: { email: normalized } });
    if (existing) {
      const membership = await WorkspaceMembership.findOne({ where: { workspaceId: req.workspaceId, userId: existing.id } });
      if (membership) return res.status(409).json({ message: "This user already has a membership in this workspace" });
    }
    const workspace = await Workspace.findByPk(req.workspaceId);
    if (!workspace || workspace.status !== "ACTIVE") return res.status(403).json({ message: "Workspace is not active" });
    const token = await issue({ purpose: "INVITE", email: normalized, workspaceId: workspace.id, workspaceRole: role });
    await sendInvitationEmail({ to: normalized, workspaceName: workspace.name, token });
    return res.status(202).json({ message: "Invitation email requested. Link expires in 48 hours." });
  } catch (error) {
    console.error("Workspace invitation failed:", error.message);
    return res.status(503).json({ message: "Unable to send invitation. Try again later." });
  }
});

// Existing users must sign in before joining an additional workspace.
// The authenticated account must match the email the invitation was sent to.
router.post("/accept-existing", authenticate, throttle, async (req, res) => {
  const { token } = req.body || {};
  if (!validToken(token)) return res.status(400).json({ message: "Invalid or expired invitation" });
  try {
    const accepted = await sequelize.transaction(async transaction => {
      const action = await consume({ token, purpose: "INVITE", transaction });
      if (!action) return false;
      const user = await User.findByPk(req.user.id, { transaction });
      if (!user || user.email.toLowerCase() !== action.email || !user.emailVerifiedAt) ineligible();
      const workspace = await Workspace.findByPk(action.workspaceId, { transaction });
      if (!workspace || workspace.status !== "ACTIVE") ineligible();
      const membership = await WorkspaceMembership.findOne({ where: { workspaceId: action.workspaceId, userId: user.id }, transaction });
      if (membership) ineligible();
      await WorkspaceMembership.create({
        id: randomUUID(), workspaceId: action.workspaceId, userId: user.id,
        role: action.workspaceRole, status: "ACTIVE"
      }, { transaction });
      return true;
    });
    return accepted ? res.json({ message: "Invitation accepted. Workspace access granted." }) :
      res.status(400).json({ message: "Invalid, expired, or ineligible invitation" });
  } catch (error) {
    if (error.code === "INVITE_INELIGIBLE") return res.status(400).json({ message: "Invalid, expired, or ineligible invitation" });
    if (error.name === "SequelizeUniqueConstraintError") return res.status(409).json({ message: "Workspace membership already exists" });
    console.error("Invitation acceptance failed:", error.message);
    return res.status(500).json({ message: "Unable to accept invitation" });
  }
});

// A new invitee chooses their own password. The invitation itself proves
// control of the destination mailbox; no password is ever sent by email.
router.post("/accept-new", throttle, async (req, res) => {
  const { token, username, password } = req.body || {};
  if (!validToken(token) || typeof username !== "string" || username.trim().length < 3 ||
      username.trim().length > 100 || typeof password !== "string" ||
      password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
    return res.status(400).json({ message: "Valid invitation, name, and password (12-72 UTF-8 bytes) required" });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const accepted = await sequelize.transaction(async transaction => {
      const action = await consume({ token, purpose: "INVITE", transaction });
      if (!action) return false;
      const existing = await User.findOne({ where: { email: action.email }, transaction });
      if (existing) ineligible();
      const workspace = await Workspace.findByPk(action.workspaceId, { transaction });
      if (!workspace || workspace.status !== "ACTIVE") ineligible();
      const user = await User.create({
        username: username.trim(), email: action.email, password: hash,
        role: "VIEWER", emailVerifiedAt: new Date()
      }, { transaction });
      await WorkspaceMembership.create({
        id: randomUUID(), workspaceId: action.workspaceId, userId: user.id,
        role: action.workspaceRole, status: "ACTIVE"
      }, { transaction });
      return true;
    });
    return accepted ? res.status(201).json({ message: "Invitation accepted. Please sign in." }) :
      res.status(400).json({ message: "Invalid, expired, or ineligible invitation. Existing users must sign in first." });
  } catch (error) {
    if (error.code === "INVITE_INELIGIBLE") return res.status(400).json({ message: "Invalid, expired, or ineligible invitation" });
    if (error.name === "SequelizeUniqueConstraintError") return res.status(409).json({ message: "Account or membership already exists" });
    console.error("New invitation acceptance failed:", error.message);
    return res.status(500).json({ message: "Unable to accept invitation" });
  }
});
module.exports = router;

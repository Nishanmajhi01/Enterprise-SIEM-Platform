"use strict";
const express = require("express");
const bcrypt = require("bcrypt");
const { randomUUID } = require("crypto");
const rateLimit = require("express-rate-limit");
const { sequelize } = require("../config/database");
const User = require("../models/User");
const Workspace = require("../models/Workspace");
const WorkspaceMembership = require("../models/WorkspaceMembership");
const generateToken = require("../utils/jwt");

const router = express.Router();
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many registration attempts. Try again later." }
});

router.post("/", signupLimiter, async (req, res) => {
  const { username, email, password, accountType, organizationName } = req.body || {};
  const name = typeof username === "string" ? username.trim() : "";
  const mail = typeof email === "string" ? email.trim().toLowerCase() : "";
  const org = typeof organizationName === "string" ? organizationName.trim() : "";
  if (name.length < 3 || name.length > 100 ||
      mail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail) ||
      typeof password !== "string" || password.length < 12 ||
      Buffer.byteLength(password, "utf8") > 72 ||
      !["PERSONAL", "ORGANIZATION"].includes(accountType) ||
      (accountType === "ORGANIZATION" && (org.length < 2 || org.length > 120))) {
    return res.status(400).json({ message: "Provide a valid name, email, password (12 characters minimum, maximum 72 UTF-8 bytes), and account type. Organizations require a name." });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await sequelize.transaction(async (transaction) => {
      const existing = await User.findOne({ where: { email: mail }, transaction });
      if (existing) {
        const err = new Error("Email already registered");
        err.statusCode = 409;
        throw err;
      }
      // Public signups never receive platform-wide ADMIN permissions.
      const user = await User.create({
        username: name, email: mail, password: hash, role: "VIEWER"
      }, { transaction });
      const workspaceId = randomUUID();
      const workspace = await Workspace.create({
        id: workspaceId,
        name: accountType === "PERSONAL" ? name + "'s Workspace" : org,
        slug: "workspace-" + workspaceId,
        type: accountType,
        status: "ACTIVE"
      }, { transaction });
      await WorkspaceMembership.create({
        id: randomUUID(),
        workspaceId,
        userId: user.id,
        role: "ADMIN",
        status: "ACTIVE"
      }, { transaction });
      return { user, workspace };
    });
    return res.status(201).json({
      message: "Workspace created",
      token: generateToken(result.user),
      workspace: {
        id: result.workspace.id,
        name: result.workspace.name,
        type: result.workspace.type,
        role: "ADMIN"
      }
    });
  } catch (err) {
    if (err.statusCode === 409 || err.name === "SequelizeUniqueConstraintError") {
      return res.status(409).json({ message: "Email already registered" });
    }
    console.error("Public signup failed:", err);
    return res.status(500).json({ message: "Unable to create account" });
  }
});

module.exports = router;

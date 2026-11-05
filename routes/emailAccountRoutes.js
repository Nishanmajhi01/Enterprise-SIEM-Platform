"use strict";
const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const { sequelize } = require("../config/database");
const User = require("../models/User");
const EmailActionToken = require("../models/EmailActionToken");
const { issue, consume } = require("../services/emailActionTokens");
const { sendEmail } = require("../services/resendEmailService");
const authenticate = require("../middleware/authMiddleware");

const router = express.Router();
const limit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many email requests. Try again later." }
});
const generic = "If the account is eligible, an email will be sent.";
const emailValid = (email) => typeof email === "string" && email.length <= 254 &&
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
const publicUrl = (path, token) => {
  const url = new URL(path, process.env.APP_PUBLIC_URL);
  url.searchParams.set("token", token);
  return url.toString();
};

// Password reset is intentionally available to both legacy and workspace users.
// Unknown emails receive the same response; token delivery errors are never exposed.
router.post("/forgot-password", limit, async (req, res) => {
  const { email } = req.body || {};
  if (!emailValid(email)) return res.status(400).json({ message: "Valid email required" });
  const normalized = email.trim().toLowerCase();
  try {
    const user = await User.findOne({ where: { email: normalized } });
    if (user) {
      const token = await issue({ purpose: "RESET_PASSWORD", email: normalized, userId: user.id });
      const link = publicUrl("/reset-password", token);
      try {
        await sendEmail({
          to: normalized,
          subject: "Reset your Enterprise SIEM password",
          text: `A password reset was requested. Open this link within 30 minutes:\n${link}\n\nIf this wasn't you, ignore this email.`,
          html: `<p>A password reset was requested for your Enterprise SIEM account.</p><p><a href="${link}">Reset password</a> (valid for 30 minutes).</p><p>If this wasn't you, ignore this email.</p>`
        });
      } catch (deliveryError) {
        console.error("Password reset delivery failed:", deliveryError.message);
      }
    }
    return res.json({ message: generic });
  } catch (error) {
    console.error("Password reset request failed:", error.message);
    return res.status(500).json({ message: "Unable to process request" });
  }
});

router.post("/reset-password", limit, async (req, res) => {
  const { token, password } = req.body || {};
  if (typeof token !== "string" || typeof password !== "string" ||
      password.length < 12 || Buffer.byteLength(password, "utf8") > 72) {
    return res.status(400).json({ message: "Valid token and password (12-72 UTF-8 bytes) required" });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await sequelize.transaction(async (transaction) => {
      const action = await consume({ token, purpose: "RESET_PASSWORD", transaction });
      if (!action || !action.userId) return false;
      const user = await User.findByPk(action.userId, { transaction, lock: transaction.LOCK.UPDATE });
      if (!user || user.email.toLowerCase() !== action.email) return false;
      await user.update({ password: hash }, { transaction });
      // Invalidate any other pending password-reset links for this account.
      await EmailActionToken.update({ consumedAt: new Date() }, {
        where: { userId: user.id, purpose: "RESET_PASSWORD", consumedAt: null },
        transaction
      });
      return true;
    });
    if (!result) return res.status(400).json({ message: "Invalid or expired reset link" });
    return res.json({ message: "Password updated. Please sign in." });
  } catch (error) {
    console.error("Password reset failed:", error.message);
    return res.status(500).json({ message: "Unable to reset password" });
  }
});

// Current signed-in users may request a verification email. Verification does
// not yet gate login: that requires a separate additive user-column migration.
router.post("/request-verification", authenticate, limit, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(401).json({ message: "Authentication required" });
    const token = await issue({ purpose: "VERIFY_EMAIL", email: user.email, userId: user.id });
    const link = publicUrl("/verify-email", token);
    await sendEmail({
      to: user.email,
      subject: "Verify your Enterprise SIEM email",
      text: `Verify your email using this link within 24 hours:\n${link}`,
      html: `<p><a href="${link}">Verify your Enterprise SIEM email</a> (valid for 24 hours).</p>`
    });
    return res.json({ message: "Verification email requested" });
  } catch (error) {
    console.error("Verification request failed:", error.message);
    return res.status(503).json({ message: "Unable to send verification email" });
  }
});


/*
 * Redeem a single-use email verification link.
 * The account email must still match the address to which the link was sent.
 * Legacy users remain usable; signup enforcement is a separate deployment step.
 */
router.post("/verify-email", limit, async (req, res) => {
  const { token } = req.body || {};
  if (typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).json({ message: "Invalid or expired verification link" });
  }
  try {
    const verified = await sequelize.transaction(async transaction => {
      const action = await consume({ token, purpose: "VERIFY_EMAIL", transaction });
      if (!action || !action.userId) return false;
      const user = await User.findByPk(action.userId, {
        transaction, lock: transaction.LOCK.UPDATE
      });
      if (!user || user.email.trim().toLowerCase() !== action.email) return false;
      if (!user.emailVerifiedAt) {
        await user.update({ emailVerifiedAt: new Date() }, { transaction });
      }
      await EmailActionToken.update({ consumedAt: new Date() }, {
        where: { userId: user.id, purpose: "VERIFY_EMAIL", consumedAt: null },
        transaction
      });
      return true;
    });
    if (!verified) return res.status(400).json({ message: "Invalid or expired verification link" });
    return res.json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verification failed:", error.message);
    return res.status(500).json({ message: "Unable to verify email" });
  }
});

module.exports = router;

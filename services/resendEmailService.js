"use strict";

const RESEND_ENDPOINT = "https://api.resend.com/emails";

function configured() {
  return Boolean(process.env.RESEND_API_KEY && process.env.RESEND_FROM_EMAIL && process.env.APP_PUBLIC_URL);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[character]));
}

async function sendEmail({ to, subject, text, html }) {
  if (!configured()) {
    throw new Error("Resend email delivery is not configured");
  }
  if (typeof to !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    throw new Error("Invalid email recipient");
  }
  const response = await fetch(RESEND_ENDPOINT, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM_EMAIL,
      to: [to],
      subject,
      text,
      html
    }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) {
    // Avoid logging provider response bodies, addresses or API keys.
    throw new Error(`Resend delivery failed (HTTP ${response.status})`);
  }
  return { accepted: true };
}

function applicationLink(path, token) {
  const base = new URL(process.env.APP_PUBLIC_URL);
  if (!["/verify-email", "/accept-invitation"].includes(path)) {
    throw new Error("Unsupported email action");
  }
  base.pathname = path;
  base.search = new URLSearchParams({ token }).toString();
  return base.toString();
}

async function sendVerificationEmail({ to, name, token }) {
  const link = applicationLink("/verify-email", token);
  const greeting = `Hello ${name},`;
  return sendEmail({
    to,
    subject: "Verify your Enterprise SIEM email",
    text: `${greeting}\n\nVerify your email by opening this link:\n${link}\n\nIf you did not register, ignore this email.`,
    html: `<p>Hello ${escapeHtml(name)},</p><p>Verify your email to activate your Enterprise SIEM account:</p><p><a href="${escapeHtml(link)}">Verify email</a></p><p>If you did not register, ignore this email.</p>`
  });
}

async function sendInvitationEmail({ to, workspaceName, token }) {
  const link = applicationLink("/accept-invitation", token);
  return sendEmail({
    to,
    subject: "Enterprise SIEM workspace invitation",
    text: `You have been invited to join ${workspaceName} on Enterprise SIEM.\n\nAccept the invitation:\n${link}\n\nIf unexpected, ignore this email.`,
    html: `<p>You have been invited to join <strong>${escapeHtml(workspaceName)}</strong> on Enterprise SIEM.</p><p><a href="${escapeHtml(link)}">Accept invitation</a></p><p>If unexpected, ignore this email.</p>`
  });
}

module.exports = { configured, sendEmail, sendVerificationEmail, sendInvitationEmail };

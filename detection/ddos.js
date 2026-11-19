const net = require("node:net");
const { createSecurityAlert } = require("../services/alertService");

// Per-workspace and per-source rate tracker. State is intentionally in memory;
// a durable, distributed counter is required for multi-instance deployments.
const traffic = new Map();
const pendingAlerts = new Set();
const WINDOW_MS = 60_000;
const THRESHOLD = 100;
const COOLDOWN_MS = 60_000;
const MAX_TRACKERS = 10_000;

function prune(now) {
  for (const [key, state] of traffic) {
    state.times = state.times.filter(time => now - time < WINDOW_MS);
    if (!state.times.length && now >= state.cooldownUntil && !pendingAlerts.has(key)) {
      traffic.delete(key);
    }
  }
}

async function detectDDoS(ip, workspaceId) {
  if (
    typeof workspaceId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
  ) {
    throw new Error("Valid workspace ID required for DDoS detection");
  }

  if (typeof ip !== "string" || net.isIP(ip) === 0) return null;
  const key = JSON.stringify([workspaceId, ip]);
  const now = Date.now();
  prune(now);
  let state = traffic.get(key);
  if (!state) {
    if (traffic.size >= MAX_TRACKERS) return null;
    state = { times: [], cooldownUntil: 0 };
    traffic.set(key, state);
  }

  if (pendingAlerts.has(key) || now < state.cooldownUntil) return null;
  state.times.push(now);
  if (state.times.length <= THRESHOLD) return null;

  pendingAlerts.add(key);
  try {
    const result = await createSecurityAlert({
      workspaceId,
      title: "DDoS Attack Detected",
      description: `High volume traffic detected from ${ip}. Possible denial of service attack.`,
      severity: "CRITICAL",
      sourceIP: ip,
      attackType: "DDOS",
      mitreTechnique: "T1498",
      tactic: "Impact",
      riskScore: 95
    });
    state.times = [];
    state.cooldownUntil = Date.now() + COOLDOWN_MS;
    return result;
  } finally {
    pendingAlerts.delete(key);
  }
}

module.exports = detectDDoS;

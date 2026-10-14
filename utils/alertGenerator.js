
const { mapThreat } = require("../services/mitreMapper");

function generateAlert(correlation = {}, event = {}) {
  const attackType = correlation.attackType || "UNKNOWN";
  const mitre = mapThreat(attackType);

  const recommendations = {
    BRUTE_FORCE:
      "Block source IP and investigate compromised accounts",
    MALWARE:
      "Isolate infected system and perform malware analysis",
    PHISHING:
      "Block malicious URL and warn users",
    DDOS:
      "Investigate traffic sources and destinations. Apply rate limiting or traffic filtering after validation."
  };

  const recommendation =
    recommendations[attackType] ||
    "Investigate security event";

  const detectionEvidence = Array.isArray(correlation.evidence)
    ? correlation.evidence
    : [];

  const reasons = Array.isArray(correlation.reason)
    ? correlation.reason
    : [];

  const primaryEvidence = detectionEvidence[0] || {};

  const sourceIP =
    primaryEvidence.sourceIP ||
    event.sourceIP ||
    "unknown";

  const evidence = [
    ...reasons.map(reason => ({
      type: "DETECTION_REASON",
      description: reason
    })),
    ...detectionEvidence
  ];

  return {
    alertID: "ALERT-" + Date.now(),

    title: `${mitre.name} Detected`,

    attackType,

    mitre: {
      id: mitre.technique,
      technique: mitre.name,
      tactic: mitre.tactic
    },

    severity: correlation.severity || "LOW",

    riskScore: correlation.score || 0,

    evidence,

    sourceIP,

    description: mitre.description,

    recommendation,

    status: "OPEN",

    createdAt: new Date()
  };
}

module.exports = generateAlert;

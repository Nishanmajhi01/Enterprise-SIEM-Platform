
function normalizeEvent(event = {}) {
  const parsedTimestamp = new Date(event.timestamp || Date.now());

  const normalized = {
    eventType: "UNKNOWN",
    sourceIP: event.sourceIP || event.ip || "unknown",
    destinationIP: event.destinationIP || event.destIP || null,
    username: event.username || "unknown",
    timestamp: Number.isNaN(parsedTimestamp.getTime())
      ? new Date()
      : parsedTimestamp,
    severity: "LOW",
    description: "",
    requestCount: Number.isFinite(Number(event.requestCount))
      ? Math.max(0, Number(event.requestCount))
      : 1,
    bytes: Number.isFinite(Number(event.bytes))
      ? Math.max(0, Number(event.bytes))
      : 0,
    protocol: event.protocol || null,
    ipReputation: event.ipReputation || null,
    malware: event.malware === true,
    fileHash: event.fileHash || null,
    url: event.url || null
  };

  if (event.failedLogin) {
    normalized.eventType = "LOGIN_FAILURE";
    normalized.severity = "MEDIUM";
    normalized.description = "Failed login attempt detected";
  }

  if (event.url) {
    normalized.eventType = "URL_ACCESS";
    normalized.description = "URL activity detected";
  }

  if (event.fileHash) {
    normalized.eventType = "FILE_SCAN";
    normalized.description = "File hash submitted for malware analysis";
  }

  if (event.requests || event.eventType === "NETWORK_TRAFFIC") {
    normalized.eventType = "NETWORK_TRAFFIC";
    normalized.description = "Network traffic activity detected";
  }

  return normalized;
}

module.exports = normalizeEvent;


const WINDOW_MS = 60 * 1000;
const SINGLE_SOURCE_THRESHOLD = 100;
const DISTRIBUTED_THRESHOLD = 100;
const MIN_DISTRIBUTED_SOURCES = 3;

function analyseEvents(events = []) {
  const result = {
    threatDetected: false,
    attackType: null,
    severity: "LOW",
    score: 0,
    reason: [],
    evidence: []
  };

  if (!Array.isArray(events)) {
    return result;
  }

  const now = Date.now();

  // Preserve existing brute-force detection
  const failedLogins = events.filter(
    event => event.eventType === "LOGIN_FAILURE"
  );

  if (failedLogins.length >= 5) {
    result.threatDetected = true;
    result.attackType = "BRUTE_FORCE";
    result.score += 40;
    result.reason.push(
      "Multiple failed login attempts detected"
    );
  }

  // Preserve existing malware detection
  const malwareEvents = events.filter(
    event =>
      event.eventType === "FILE_SCAN" &&
      event.malware === true
  );

  if (malwareEvents.length > 0) {
    result.threatDetected = true;
    result.attackType = "MALWARE";
    result.score += 60;
    result.reason.push(
      "Malware indicator detected"
    );
  }

  // DDoS V2: only recent network traffic
  const networkEvents = events.filter(event => {
    if (event.eventType !== "NETWORK_TRAFFIC") {
      return false;
    }

    const timestamp = new Date(event.timestamp).getTime();

    return Number.isFinite(timestamp) &&
      timestamp <= now &&
      now - timestamp <= WINDOW_MS;
  });

  // Group network events by source IP
  const sourceCounts = new Map();

  for (const event of networkEvents) {
    const source = event.sourceIP;

    if (!source || source === "unknown") {
      continue;
    }

    sourceCounts.set(
      source,
      (sourceCounts.get(source) || 0) + 1
    );
  }

  const topSource = [...sourceCounts.entries()]
    .sort((a, b) => b[1] - a[1])[0];

  // Single-source high-volume traffic
  if (
    topSource &&
    topSource[1] >= SINGLE_SOURCE_THRESHOLD
  ) {
    result.threatDetected = true;
    result.attackType = "DDOS";
    result.score = Math.max(result.score, 70);

    result.reason.push(
      "High-volume traffic from a single source"
    );

    result.evidence.push({
      detectionType: "SINGLE_SOURCE_FLOOD",
      sourceIP: topSource[0],
      eventCount: topSource[1],
      windowSeconds: WINDOW_MS / 1000
    });
  }

  // Distributed traffic must target the same destination
  const destinationGroups = new Map();

  for (const event of networkEvents) {
    const destination = event.destinationIP;
    const source = event.sourceIP;

    if (
      !destination ||
      !source ||
      source === "unknown"
    ) {
      continue;
    }

    if (!destinationGroups.has(destination)) {
      destinationGroups.set(destination, {
        count: 0,
        sources: new Set()
      });
    }

    const group = destinationGroups.get(destination);
    group.count += 1;
    group.sources.add(source);
  }

  for (const [destinationIP, group] of destinationGroups) {
    if (
      group.count >= DISTRIBUTED_THRESHOLD &&
      group.sources.size >= MIN_DISTRIBUTED_SOURCES
    ) {
      result.threatDetected = true;
      result.attackType = "DDOS";
      result.score = Math.max(result.score, 85);

      result.reason.push(
        "Multiple sources generated high traffic toward one destination"
      );

      result.evidence.push({
        detectionType: "DISTRIBUTED_FLOOD",
        destinationIP,
        eventCount: group.count,
        uniqueSources: group.sources.size,
        windowSeconds: WINDOW_MS / 1000
      });
    }
  }

  // Add reputation risk before severity calculation
  if (events.some(event => event.ipReputation === "BAD")) {
    result.score += 30;
    result.reason.push(
      "Malicious IP reputation detected"
    );
  }

  result.score = Math.min(result.score, 100);

  if (result.score >= 80) {
    result.severity = "CRITICAL";
  } else if (result.score >= 50) {
    result.severity = "HIGH";
  } else if (result.score >= 30) {
    result.severity = "MEDIUM";
  }

  return result;
}

module.exports = analyseEvents;

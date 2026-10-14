/**
 * ENTERPRISE SIEM - DDOS V2
 * Stateful firewall event-rate detector
 *
 * Monitoring only:
 * - No database writes
 * - No firewall blocking
 * - No automatic incident creation
 */

const CONFIG = {
    WINDOW_MS: 60 * 1000,
    SINGLE_THRESHOLD: 100,
    DISTRIBUTED_THRESHOLD: 150,
    MIN_DISTRIBUTED_SOURCES: 3,
    COOLDOWN_MS: 60 * 1000,
    MAX_DESTINATIONS: 10000
};

const traffic = new Map();
const cooldowns = new Map();

function detectDDoSV2(event) {

    const sourceIP = event.sourceIP;
    const destinationIP = event.destinationIP;

    const eventType = event.eventType;

    const protocol = String(
        event.raw?.protocol ??
        event.raw?.raw?.protocol ??
        ""
    ).toUpperCase();

    const destinationPort = Number(
        event.raw?.destinationPort ??
        event.raw?.raw?.destinationPort ??
        0
    );

    // Only inspect pfSense firewall events.
    if (eventType !== "PFSENSE_FIREWALL") {
        return { detected: false, shouldAlert: false };
    }

    if (!sourceIP || !destinationIP) {
        return { detected: false, shouldAlert: false };
    }

    // Exclude routine time synchronization traffic.
    if (protocol === "UDP" && destinationPort === 123) {
        return { detected: false, shouldAlert: false };
    }

    const now = Date.now();

    // Prevent unbounded growth during long-running operation.
    for (const [ip, entries] of traffic) {
        const recent = entries.filter(
            entry => now - entry.time < CONFIG.WINDOW_MS
        );

        if (recent.length === 0) {
            traffic.delete(ip);
        } else {
            traffic.set(ip, recent);
        }
    }

    for (const [key, lastAlert] of cooldowns) {
        if (now - lastAlert >= CONFIG.COOLDOWN_MS) {
            cooldowns.delete(key);
        }
    }

    if (
        !traffic.has(destinationIP) &&
        traffic.size >= CONFIG.MAX_DESTINATIONS
    ) {
        return {
            detected: false,
            shouldAlert: false,
            reason: "TRACKER_CAPACITY_REACHED"
        };
    }

    const entries = traffic.get(destinationIP) || [];

    entries.push({
        sourceIP,
        time: now
    });

    traffic.set(destinationIP, entries);

    const sourceCounts = new Map();

    for (const entry of entries) {
        sourceCounts.set(
            entry.sourceIP,
            (sourceCounts.get(entry.sourceIP) || 0) + 1
        );
    }

    const singleCount = sourceCounts.get(sourceIP) || 0;
    const totalCount = entries.length;
    const uniqueSources = sourceCounts.size;

    const distributed =
        totalCount >= CONFIG.DISTRIBUTED_THRESHOLD &&
        uniqueSources >= CONFIG.MIN_DISTRIBUTED_SOURCES;

    const single =
        singleCount >= CONFIG.SINGLE_THRESHOLD;

    if (!distributed && !single) {
        return {
            detected: false,
            shouldAlert: false
        };
    }

    // Prefer distributed detection when both conditions match.
    const detectionType = distributed
        ? "DISTRIBUTED_FLOOD"
        : "SINGLE_SOURCE_FLOOD";

    const cooldownKey = distributed
        ? `DISTRIBUTED:${destinationIP}`
        : `SINGLE:${sourceIP}:${destinationIP}`;

    const shouldAlert = !cooldowns.has(cooldownKey);

    if (shouldAlert) {
        cooldowns.set(cooldownKey, now);
    }

    return {
        detected: true,
        shouldAlert,
        attackType: "DDOS",
        detectionType,
        severity: distributed ? "CRITICAL" : "HIGH",
        riskScore: distributed ? 85 : 70,
        sourceIP,
        destinationIP,
        eventCount: distributed ? totalCount : singleCount,
        totalDestinationEvents: totalCount,
        uniqueSources,
        sourceIPs: [...sourceCounts.keys()],
        windowSeconds: CONFIG.WINDOW_MS / 1000,
        detectedAt: new Date(now).toISOString()
    };
}

module.exports = {
    detectDDoSV2
};

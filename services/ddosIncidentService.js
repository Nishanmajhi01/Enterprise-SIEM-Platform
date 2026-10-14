
/**
 * Enterprise SIEM - DDoS V2 Incident Service
 *
 * Detects potential flooding based on pfSense firewall logs.
 * Creates incidents and structured evidence.
 *
 * SAFETY:
 * - No automatic IP blocking
 * - No response playbook execution
 * - Test transactions do not emit dashboard notifications
 */

const Incident = require("../models/Incident");
const Evidence = require("../models/Evidence");
const { sequelize } = require("../config/database");
const { Op } = require("sequelize");
const { emitIncident } = require("../utils/socketEmitter");

const CORRELATION_WINDOW_MS = 10 * 60 * 1000;

async function findExistingDDoSIncident(result, options = {}) {
    const cutoff = new Date(
        Date.now() - CORRELATION_WINDOW_MS
    );

    const candidates = await Incident.findAll({
        where: {
            attackType: "DDOS",

            status: {
                [Op.in]: [
                    "OPEN",
                    "ACKNOWLEDGED",
                    "INVESTIGATING",
                    "CONTAINED"
                ]
            },

            updatedAt: {
                [Op.gte]: cutoff
            },

            evidence: {
                [Op.contains]: [{
                    detectionSource: "PFSENSE_LIVE",
                    destinationIP: result.destinationIP,
                    detectionType: result.detectionType
                }]
            }
        },

        order: [["updatedAt", "DESC"]],
        limit: 1,
        transaction: options.transaction
    });

    return candidates[0] || null;
}

async function createDDoSIncident(result, options = {}) {

    // Only process detections that require an alert.
    if (!result || result.shouldAlert !== true) {
        return null;
    }

    if (
        result.attackType !== "DDOS" ||
        ![
            "SINGLE_SOURCE_FLOOD",
            "DISTRIBUTED_FLOOD"
        ].includes(result.detectionType) ||
        typeof result.destinationIP !== "string" ||
        !result.destinationIP.trim()
    ) {
        throw new Error("Invalid DDoS V2 detection result");
    }

    // A caller-supplied transaction is useful for rollback tests.
    const externalTransaction = options.transaction || null;

    const transaction = externalTransaction ||
        await sequelize.transaction();

    const ownsTransaction = !externalTransaction;

    try {

        // Serialise DDoS incident creation within PostgreSQL.
        // This prevents concurrent calls using this same lock
        // from creating duplicate incidents for one destination.
        await sequelize.query(
            "SELECT pg_advisory_xact_lock(hashtext(:lockKey))",
            {
                replacements: {
                    lockKey:
                        "DDOS_V2:" +
                        result.destinationIP +
                        ":" +
                        result.detectionType
                },
                transaction
            }
        );

        const existing = await findExistingDDoSIncident(
            result,
            { transaction }
        );

        if (existing) {
            if (ownsTransaction) {
                await transaction.commit();
            }

            console.log(
                "DDOS V2: Existing incident matched:",
                existing.id
            );

            return existing;
        }

        const distributed =
            result.detectionType === "DISTRIBUTED_FLOOD";

        const severity = distributed
            ? "CRITICAL"
            : "HIGH";

        const riskScore = distributed ? 85 : 70;

        const evidenceData = {
            detectionSource: "PFSENSE_LIVE",
            detectionType: result.detectionType,
            destinationIP: result.destinationIP,
            sourceIP: result.sourceIP || null,

            sourceIPs: Array.isArray(result.sourceIPs)
                ? result.sourceIPs
                : [],

            eventCount: result.eventCount ?? null,
            totalDestinationEvents:
                result.totalDestinationEvents ?? null,

            uniqueSources: result.uniqueSources ?? null,
            windowSeconds: result.windowSeconds ?? 60,
            detectedAt: result.detectedAt || new Date(),
            mitreTechnique: "T1498",
            tactic: "Impact"
        };

        const incident = await Incident.create({

            title: distributed
                ? "Potential Distributed DDoS Activity Detected"
                : "Potential Single-Source Flood Detected",

            attackType: "DDOS",
            mitreTechnique: "T1498",
            tactic: "Impact",
            severity,
            riskScore,

            sourceIP: result.sourceIP || null,

            description:
                "Suspicious firewall event volume detected " +
                "toward " + result.destinationIP +
                " within " + evidenceData.windowSeconds +
                " seconds. This indicates a traffic anomaly, " +
                "not a confirmed service outage.",

            evidence: [{
                type: "DDOS_V2_DETECTION",
                ...evidenceData
            }],

            recommendation:
                "Review pfSense firewall logs, validate traffic " +
                "volume and service availability, investigate " +
                "the source IPs, and verify whether the traffic " +
                "is legitimate before taking containment action.",

            status: "OPEN",
            relatedAlerts: 1,

            timeline: [{
                action: "INCIDENT_CREATED",
                user: "DDOS_V2_DETECTOR",
                time: new Date()
            }]

        }, { transaction });

        await Evidence.create({

            incidentId: incident.id,
            type: "DDOS_V2_DETECTION",

            description:
                "Potential DDoS traffic anomaly detected " +
                "from pfSense firewall logs",

            source: "PFSENSE_LIVE",
            data: evidenceData

        }, { transaction });

        // Only notify after a successful commit.
        // External transactions must be committed by the caller.
        if (ownsTransaction) {
            await transaction.commit();

            try {
                emitIncident(incident);
            } catch (notificationError) {
                console.error(
                    "DDOS V2 dashboard notification failed:",
                    notificationError.message
                );
            }
        }

        console.log(
            "DDOS V2 INCIDENT CREATED:",
            incident.id,
            "| Destination:",
            result.destinationIP,
            "| Type:",
            result.detectionType,
            "| Severity:",
            severity
        );

        // Never execute a response playbook for DDoS.
        return incident;

    } catch (error) {

        if (ownsTransaction && !transaction.finished) {
            await transaction.rollback();
        }

        console.error(
            "DDOS V2 incident creation failed:",
            error.message
        );

        throw error;
    }
}

module.exports = {
    findExistingDDoSIncident,
    createDDoSIncident
};

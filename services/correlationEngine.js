const Incident = require("../models/Incident");
const { emitAlert } = require("../utils/socketEmitter");
const { enrichThreat } = require("../services/threatIntelService");

/**
 * 🔥 ENTERPRISE CORRELATION ENGINE
 * IOC + Threat Intel + Rules + Risk Scoring
 */
exports.runCorrelation = async (event, iocMatches = []) => {

    try {

        // ==============================
        // 1. THREAT INTELLIGENCE ENRICHMENT
        // ==============================
        const threatIntel = await enrichThreat(event);

        // ==============================
        // 2. BASE DETECTION SCORE
        // ==============================
        let riskScore = 0;
        let severity = "LOW";
        let alert = null;

        // ==============================
        // 3. IOC MATCHING IMPACT
        // ==============================
        if (iocMatches.length > 0) {
            riskScore += 40;
        }

        // ==============================
        // 4. THREAT INTEL IMPACT
        // ==============================
        if (threatIntel?.virusTotal?.malicious > 10) {
            riskScore += 50;
        }

        if (threatIntel?.abuseIPDB?.abuseScore > 50) {
            riskScore += 30;
        }

        // ==============================
        // 5. BEHAVIOR RULES ENGINE
        // ==============================
        if (event.failedLogins > 5) {
            riskScore += 30;
        }

        if (event.portScan === true) {
            riskScore += 40;
        }

        // ==============================
        // 6. SEVERITY MAPPING
        // ==============================
        if (riskScore >= 120) severity = "CRITICAL";
        else if (riskScore >= 80) severity = "HIGH";
        else if (riskScore >= 40) severity = "MEDIUM";

        // ==============================
        // 7. ALERT DECISION
        // ==============================
        if (riskScore >= 80) {
            alert = "MALICIOUS ACTIVITY DETECTED";
        }

        const result = {
            event,
            iocMatches,
            threatIntel,
            detection: {
                alert,
                severity,
                riskScore,
                mitre: {
                    technique: "T1071",
                    tactic: "Command and Control",
                    name: "Network Communication"
                }
            },
            timestamp: new Date()
        };

        // ==============================
        // 8. REAL-TIME ALERTING
        // ==============================
        if (alert) {
            emitAlert(result);

            await Incident.create({
                title: alert,
                attackType: event.attackType || "UNKNOWN",
                severity,
                sourceIP: event.sourceIP,
                status: "OPEN"
            });
        }

        return result;

    } catch (error) {
        console.log("Correlation Engine Error:", error.message);

        return {
            event,
            error: "Correlation failed",
            timestamp: new Date()
        };
    }
};
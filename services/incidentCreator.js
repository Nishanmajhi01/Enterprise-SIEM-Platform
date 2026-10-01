const Incident = require("../models/Incident");
const Evidence = require("../models/Evidence");
const Alert = require("../models/Alert");

const { Op } = require("sequelize");

const {
    emitIncident
} = require("../utils/socketEmitter");

const {
    executePlaybook
} = require("./playbookEngine");


// ============================================================
// CONFIGURATION
// ============================================================

const INCIDENT_RISK_THRESHOLD = 70;

const INCIDENT_CORRELATION_WINDOW_MS =
    10 * 60 * 1000;


// ============================================================
// NON-ATTACK EVENT TYPES
// ============================================================

const NON_ATTACK_TYPES = new Set([
    "NETWORK_TRAFFIC",
    "NORMAL_TRAFFIC",
    "UNKNOWN"
]);


// ============================================================
// VALID PORT SCAN TYPES
// ============================================================

const VALID_SCAN_TYPES = new Set([
    "VERTICAL_PORT_SCAN",
    "HORIZONTAL_PORT_SCAN",
    "MIXED_PORT_SCAN"
]);


// ============================================================
// CREATE / CORRELATE INCIDENT
// ============================================================

async function createIncidentFromAlert(alert) {

    try {

        // ====================================================
        // NORMALISE ATTACK TYPE
        // ====================================================

        const attackType =
            String(
                alert.attackType || "UNKNOWN"
            )
                .trim()
                .toUpperCase();


        // ====================================================
        // NORMALISE SCAN TYPE
        // ====================================================

        let scanType =
            alert.scanType ||
            alert.portScanType ||
            null;


        if (scanType) {

            scanType =
                String(scanType)
                    .trim()
                    .toUpperCase();

        }


        /*
         * scanType only has meaning for PORT_SCAN incidents.
         */

        if (attackType !== "PORT_SCAN") {

            scanType = null;

        }


        /*
         * Protect the database from unexpected scan-type values.
         */

        if (
            scanType &&
            !VALID_SCAN_TYPES.has(scanType)
        ) {

            console.log(
                `Unknown port scan type received: ${scanType}`
            );

            scanType = null;

        }


        // ====================================================
        // DO NOT CREATE INCIDENTS FOR BENIGN TRAFFIC
        // ====================================================

        if (
            NON_ATTACK_TYPES.has(attackType)
        ) {

            console.log(
                `INCIDENT SKIPPED: ${attackType} is not an attack`
            );

            return null;

        }


        // ====================================================
        // RISK THRESHOLD
        // ====================================================

        const riskScore =
            Number(alert.riskScore) || 0;


        if (
            riskScore <
            INCIDENT_RISK_THRESHOLD
        ) {

            console.log(
                `INCIDENT SKIPPED: risk ${riskScore} below threshold ${INCIDENT_RISK_THRESHOLD}`
            );

            return null;

        }


        // ====================================================
        // CORRELATION TIME WINDOW
        // ====================================================

        const timeWindow =
            new Date(
                Date.now() -
                INCIDENT_CORRELATION_WINDOW_MS
            );


        // ====================================================
        // BUILD CORRELATION QUERY
        // ====================================================

        const correlationWhere = {

            sourceIP:
                alert.sourceIP,

            attackType:
                attackType,

           status: {
    [Op.in]: [
        "OPEN",
        "INVESTIGATING",
        "CONTAINED"
    ]
},

            updatedAt: {
    [Op.gte]: timeWindow
}

        };


        /*
         * IMPORTANT:
         *
         * Port scans must also match their scan type.
         *
         * This means:
         *
         * PORT_SCAN + VERTICAL_PORT_SCAN
         *
         * will NOT automatically correlate with:
         *
         * PORT_SCAN + HORIZONTAL_PORT_SCAN
         */

        if (
            attackType === "PORT_SCAN" &&
            scanType
        ) {

            correlationWhere.scanType =
                scanType;

        }


        // ====================================================
        // SEARCH FOR EXISTING INCIDENT
        // ====================================================

        const existingIncident =
            await Incident.findOne({

                where:
                    correlationWhere,

                order: [
                    ["updatedAt", "DESC"]
                ]

            });


        // ====================================================
        // CORRELATE WITH EXISTING INCIDENT
        // ====================================================

        if (existingIncident) {

            console.log(
                "Correlated with existing incident:",
                existingIncident.id,
                "| Attack:",
                attackType,
                "| Scan Type:",
                scanType || "N/A"
            );


            // =================================================
            // INCREASE RELATED ALERT COUNT SAFELY
            // =================================================

            existingIncident.relatedAlerts =
                Number(
                    existingIncident.relatedAlerts || 0
                ) + 1;


            // =================================================
            // UPDATE RISK SCORE
            // =================================================

            existingIncident.riskScore =
                Math.min(

                    100,

                    Number(
                        existingIncident.riskScore || 0
                    ) + riskScore

                );


            // =================================================
            // UPDATE INCIDENT TIMELINE
            // =================================================

            existingIncident.timeline = [

                ...(
                    existingIncident.timeline ||
                    []
                ),

                {

                    action:
                        "RELATED_ALERT",

                    user:
                        "CORRELATION_ENGINE",

                    alertId:
                        alert.id || null,

                    attackType:
                        attackType,

                    scanType:
                        scanType,

                    riskScore:
                        riskScore,

                    time:
                        new Date()

                }

            ];


            existingIncident.changed(
                "timeline",
                true
            );


            await existingIncident.save();


            // =================================================
            // LINK REAL ALERT ROW TO INCIDENT
            // =================================================

            if (alert.id) {

                await Alert.update(

                    {
                        incidentId:
                            existingIncident.id
                    },

                    {
                        where: {
                            id:
                                alert.id
                        }
                    }

                );

            }


            return existingIncident;

        }


        // ====================================================
        // BUILD INCIDENT TITLE
        // ====================================================

        let incidentTitle;


        if (alert.title) {

            incidentTitle =
                alert.title;

        }

        else if (
            attackType === "PORT_SCAN" &&
            scanType
        ) {

            incidentTitle =
                `${scanType} Detected from ${alert.sourceIP}`;

        }

        else {

            incidentTitle =
                `${attackType} Attack Detected`;

        }


        // ====================================================
        // CREATE NEW INCIDENT
        // ====================================================

        const incident =
            await Incident.create({

                title:
                    incidentTitle,


                attackType:
                    attackType,


                scanType:
                    scanType,


                mitreTechnique:
                    alert.mitreTechnique ||
                    "UNKNOWN",


                tactic:
                    alert.tactic ||
                    "UNKNOWN",


                severity:
                    alert.severity ||
                    "LOW",


                riskScore:
                    riskScore,


                alertId:
                    alert.id || null,


                sourceIP:
                    alert.sourceIP || null,


                description:
                    alert.description ||
                    null,


                // --------------------------------------------
                // Legacy embedded evidence
                // --------------------------------------------

                evidence: [

                    {

                        type:
                            "SECURITY_ALERT",

                        alertId:
                            alert.id || null,

                        attackType:
                            attackType,

                        scanType:
                            scanType,

                        collectedAt:
                            new Date()

                    }

                ],


                recommendation:

                    attackType === "PORT_SCAN"

                        ? "Investigate reconnaissance activity, review firewall logs, validate the source host, and apply containment if required"

                        : "Investigate source activity and apply containment actions",


                status:
                    "OPEN",


                relatedAlerts:
                    1,


                timeline: [

                    {

                        action:
                            "INCIDENT_CREATED",

                        user:
                            "CORRELATION_ENGINE",

                        attackType:
                            attackType,

                        scanType:
                            scanType,

                        riskScore:
                            riskScore,

                        time:
                            new Date()

                    }

                ]

            });


        // ====================================================
        // LINK ALERT INSTANCE
        // ====================================================

        if (
            alert.alertInstance
        ) {

            await alert.alertInstance.update({

                incidentId:
                    incident.id

            });

        }


        // ====================================================
        // CREATE STRUCTURED EVIDENCE ROW
        // ====================================================

        await Evidence.create({

            incidentId:
                incident.id,

            type:
                "SECURITY_ALERT",

            description:

                scanType

                    ? `${scanType} security detection evidence`

                    : "Initial security alert evidence",

            source:
                "CORRELATION_ENGINE",

            data: {

                alertId:
                    alert.id || null,

                sourceIP:
                    alert.sourceIP || null,

                attackType:
                    attackType,

                scanType:
                    scanType,

                severity:
                    alert.severity || null,

                riskScore:
                    riskScore,

                mitreTechnique:
                    alert.mitreTechnique ||
                    "UNKNOWN",

                tactic:
                    alert.tactic ||
                    "UNKNOWN"

            }

        });


        // ====================================================
        // LOG INCIDENT CREATION
        // ====================================================

        console.log(
            "INCIDENT CREATED:",
            incident.id,
            "| Attack:",
            attackType,
            "| Scan Type:",
            scanType || "N/A",
            "| Risk:",
            riskScore
        );


        // ====================================================
        // AUTOMATED RESPONSE PLAYBOOK
        // ====================================================

        await executePlaybook(
            incident
        );


        // ====================================================
        // REAL-TIME SOC UPDATE
        // ====================================================

        emitIncident(
            incident
        );


        return incident;

    }

    catch (error) {

        console.log(
            "Incident creation failed:",
            error.message
        );


        throw error;

    }

}


// ============================================================
// EXPORT
// ============================================================

module.exports =
    createIncidentFromAlert;
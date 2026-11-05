const Incident = require("../models/Incident");
const Evidence = require("../models/Evidence");
const Alert = require("../models/Alert");

const { Op } = require("sequelize");
const { sequelize } = require("../config/database");

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
// WORKSPACE-SCOPED CORRELATION LOCK KEY
// ============================================================

function buildCorrelationLockKey(
    workspaceId,
    sourceIP,
    attackType,
    scanType
) {
    return JSON.stringify([
        "INCIDENT_CORRELATION_V1",
        workspaceId,
        sourceIP ?? null,
        attackType,
        attackType === "PORT_SCAN"
            ? "ALL_PORT_SCAN_TYPES"
            : null
    ]);
}

async function acquireCorrelationLock(transaction, lockKey) {
    if (!transaction || transaction.finished) {
        throw new Error(
            "Active transaction required for correlation locking"
        );
    }

    if (typeof lockKey !== "string" || !lockKey) {
        throw new Error("Valid correlation lock key required");
    }

    await sequelize.query(
        "SELECT pg_advisory_xact_lock(hashtext(:lockKey))",
        {
            replacements: { lockKey },
            transaction
        }
    );
}




// ============================================================
// ATOMIC INCIDENT TRANSACTION WRAPPER
// ============================================================

async function withIncidentTransaction(lockKey, callback) {
    if (typeof callback !== "function") {
        throw new Error("Transaction callback required");
    }

    return sequelize.transaction(async transaction => {
        await acquireCorrelationLock(transaction, lockKey);
        return callback(transaction);
    });
}


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
// TRANSACTIONAL INCIDENT DATABASE OPERATIONS
// ============================================================

// Database-only incident operations will be moved here.
// Do not execute response playbooks or WebSocket notifications
// inside this transaction callback.
async function runIncidentDatabaseOperations(transaction, callback) {
    if (!transaction || transaction.finished) {
        throw new Error(
            "Active transaction required for incident operations"
        );
    }

    if (typeof callback !== "function") {
        throw new Error("Incident database callback required");
    }

    return callback(transaction);
}


// ============================================================
// WORKSPACE-SCOPED ALERT LINKING
// ============================================================

async function getLockedAlert(
    alertId,
    workspaceId,
    transaction
) {
    if (!transaction || transaction.finished) {
        throw new Error(
            "Active transaction required for alert lookup"
        );
    }

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error("Valid workspace ID required");
    }

    if (!Number.isSafeInteger(alertId) || alertId <= 0) {
        throw new Error("Valid alert ID required");
    }

    if (!transaction.LOCK || !transaction.LOCK.UPDATE) {
        throw new Error(
            "Transaction row locking unavailable"
        );
    }

    const alertRecord = await Alert.findOne({
        where: {
            id: alertId,
            workspaceId
        },
        transaction,
        lock: transaction.LOCK.UPDATE
    });

    if (!alertRecord) {
        throw new Error(
            "Alert not found in incident workspace"
        );
    }

    return alertRecord;
}


async function linkUnassignedAlert(
    alertId,
    incidentId,
    workspaceId,
    transaction
) {
    if (!transaction || transaction.finished) {
        throw new Error(
            "Active transaction required for alert linking"
        );
    }

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error("Valid workspace ID required");
    }

    if (!Number.isSafeInteger(alertId) || alertId <= 0) {
        throw new Error("Valid alert ID required");
    }

    if (!Number.isSafeInteger(incidentId) || incidentId <= 0) {
        throw new Error("Valid incident ID required");
    }

    const [updatedCount] = await Alert.update(
        { incidentId },
        {
            where: {
                id: alertId,
                workspaceId,
                incidentId: null
            },
            transaction
        }
    );

    if (updatedCount !== 1) {
        throw new Error(
            "Alert missing, already linked, or outside workspace"
        );
    }

    return true;
}


// ============================================================
// CREATE / CORRELATE INCIDENT
// ============================================================

async function createIncidentFromAlert(alert) {


    try {

        const workspaceId = alert?.workspaceId;

        if (
            typeof workspaceId !== "string" ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
        ) {
            throw new Error(
                "Valid workspace ID required for incident creation"
            );
        }

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

            workspaceId,

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

        const lockKey = buildCorrelationLockKey(
            workspaceId,
            alert.sourceIP,
            attackType,
            scanType
        );

        const result = await withIncidentTransaction(
            lockKey,
            async transaction => runIncidentDatabaseOperations(
                transaction,
                async () => {

        // Lock and validate the source alert before correlation.
        const lockedAlert = await getLockedAlert(
            alert.id,
            workspaceId,
            transaction
        );

        if (
            lockedAlert.incidentId !== null &&
            lockedAlert.incidentId !== undefined
        ) {
            throw new Error(
                "Alert is already linked to an incident"
            );
        }

        const existingIncident =
            await Incident.findOne({

                where:
                    correlationWhere,

                order: [
                    ["updatedAt", "DESC"]
                ],

                ...(transaction ? { transaction } : {})

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


            await existingIncident.save(
                transaction ? { transaction } : {}
            );


            // =================================================
            // LINK REAL ALERT ROW TO INCIDENT
            // =================================================

            if (alert.id) {

                await linkUnassignedAlert(
                    alert.id,
                    existingIncident.id,
                    workspaceId,
                    transaction
                );


            }


            return {
                incident: existingIncident,
                created: false
            };

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

                workspaceId,

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

            }, transaction ? { transaction } : {});


        // ====================================================
        // LINK ALERT INSTANCE
        // ====================================================

        if (
            alert.alertInstance
        ) {

            await linkUnassignedAlert(
                alert.alertInstance.id,
                incident.id,
                workspaceId,
                transaction
            );

        }


        // ====================================================
        // CREATE STRUCTURED EVIDENCE ROW
        // ====================================================

        await Evidence.create({

            workspaceId,

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

        }, transaction ? { transaction } : {});


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



                    return {
                        incident,
                        created: true
                    };
                }
            )
        );

        if (!result.created) {
            return result.incident;
        }

        const incident = result.incident;

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
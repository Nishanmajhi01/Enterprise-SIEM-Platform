/**
 * ============================================================
 * ENTERPRISE SIEM - EVENT PIPELINE
 * ============================================================
 *
 * Handles:
 *  - Security event storage
 *  - IOC matching
 *  - Threat intelligence enrichment
 *  - Stateful port-scan detection
 *  - Detection rule evaluation
 *  - Risk calculation
 *  - MITRE ATT&CK mapping
 *  - Incident creation / correlation
 *  - Brute-force detection
 *  - Real-time SOC updates
 * ============================================================
 */


// ============================================================
// MODELS
// ============================================================

const SecurityEvent =
require("../models/SecurityEvent");

const IOCMatch =
require("../models/IOCMatch");


// ============================================================
// DETECTION MODULES
// ============================================================

const detectBruteForce =
require("../detection/bruteForce");

const detectPortScan =
require("../detection/portScan");


// ============================================================
// SERVICES
// ============================================================

const matchIOC =
require("./iocMatcher");

const enrichIOC =
require("./iocEnrichment");

const {
    calculateRisk
} = require("./riskEngine");

const {
    evaluateRules
} = require("./ruleEngine");

const {
    mapThreat
} = require("./mitreMapper");

const createIncidentFromAlert =
require("./incidentCreator");


// ============================================================
// REAL-TIME SOCKET
// ============================================================

const {
    emitAlert
} = require("../utils/socketEmitter");


// ============================================================
// CONFIGURATION
// ============================================================

const INCIDENT_RISK_THRESHOLD = 70;


// ============================================================
// MAIN EVENT PIPELINE
// ============================================================

async function processSecurityEvent(eventData) {

    try {

        /*
        ========================================================
        STEP 1 - NORMALISE EVENT
        ========================================================
        */

        const normalisedEvent = {

            ...eventData,

            severity:
                eventData.severity ||
                "LOW",

            attackType:
                eventData.attackType ||
                "UNKNOWN",

            raw:
                eventData.raw || {}

        };


        /*
        ========================================================
        STEP 2 - STORE SECURITY EVENT
        ========================================================
        */

        const securityEvent =
            await SecurityEvent.create(
                normalisedEvent
            );


        /*
        ========================================================
        STEP 3 - IOC MATCHING
        ========================================================
        */

        let matchedIOCs = [];

        try {

            matchedIOCs =
                await matchIOC(
                    securityEvent
                );

            if (!Array.isArray(matchedIOCs)) {

                matchedIOCs = [];

            }

        }
        catch (error) {

            console.log(
                "IOC matching failed:",
                error.message
            );

            matchedIOCs = [];

        }


        /*
        ========================================================
        STEP 4 - SAVE IOC MATCHES
        ========================================================
        */

        for (const ioc of matchedIOCs) {

            try {

                await IOCMatch.create({

                    securityEventId:
                        securityEvent.id,

                    iocId:
                        ioc.id,

                    confidence:
                        ioc.confidence || 0,

                    matchType:
                        "AUTOMATIC"

                });

            }
            catch (error) {

                console.log(
                    "IOC match storage failed:",
                    error.message
                );

            }

        }


        /*
        ========================================================
        STEP 5 - THREAT INTELLIGENCE ENRICHMENT
        ========================================================
        */

        let maxMalicious = 0;

        let maxAbuseScore = 0;

        const threatRecords = [];


        for (const ioc of matchedIOCs) {

            try {

                const intel =
                    await enrichIOC(ioc);


                if (!intel) {

                    continue;

                }


                if (intel.threatRecord) {

                    threatRecords.push(
                        intel.threatRecord
                    );

                }


                maxMalicious =
                    Math.max(

                        maxMalicious,

                        Number(
                            intel.malicious || 0
                        )

                    );


                maxAbuseScore =
                    Math.max(

                        maxAbuseScore,

                        Number(
                            intel.abuseScore || 0
                        )

                    );

            }
            catch (error) {

                /*
                 * Threat-intelligence failure should NOT
                 * stop security-event ingestion.
                 */

                console.log(
                    "Threat enrichment failed:",
                    error.message
                );

            }

        }


        /*
        ========================================================
        STEP 6 - STATEFUL PORT-SCAN DETECTION
        ========================================================
        */

        let portScanResult = {

            detected: false,

            shouldAlert: false,

            scanType: null,

            uniquePorts: 0,

            uniqueHosts: 0,

            ports: [],

            hosts: [],

            windowSeconds: 30,

            detectedAt: null

        };


        try {

            portScanResult =
                detectPortScan(
                    securityEvent
                );

        }
        catch (error) {

            console.log(
                "Port-scan detector error:",
                error.message
            );

        }


        /*
        ========================================================
        STEP 7 - CLASSIFY PORT SCAN
        ========================================================
        */

        if (portScanResult.detected) {

            securityEvent.attackType =
                "PORT_SCAN";

            securityEvent.severity =
                "CRITICAL";


            /*
             * Store correlation evidence inside raw JSONB.
             */

            const existingRaw =
                securityEvent.raw || {};


            securityEvent.raw = {

                ...existingRaw,

                detection: {

                    ...(existingRaw.detection || {}),

                    portScan: {

                        detected:
                            true,

                        scanType:
                            portScanResult.scanType,

                        uniquePorts:
                            portScanResult.uniquePorts,

                        ports:
                            portScanResult.ports,

                        uniqueHosts:
                            portScanResult.uniqueHosts,

                        hosts:
                            portScanResult.hosts,

                        windowSeconds:
                            portScanResult.windowSeconds,

                        detectedAt:
                            portScanResult.detectedAt

                    }

                }

            };


            /*
             * Sequelize needs this because raw is JSONB
             * and we replaced/modified the JSON object.
             */

            securityEvent.changed(
                "raw",
                true
            );


            await securityEvent.save();


            /*
             * shouldAlert is controlled by portScan.js
             * cooldown logic.
             */

            if (portScanResult.shouldAlert) {

                console.log(
                    "\n=========================================="
                );

                console.log(
                    "PORT SCAN DETECTED"
                );

                console.log(
                    "Source IP:",
                    securityEvent.sourceIP
                );

                console.log(
                    "Destination IP:",
                    securityEvent.destinationIP
                );

                console.log(
                    "Scan Type:",
                    portScanResult.scanType
                );

                console.log(
                    "Unique Ports:",
                    portScanResult.uniquePorts
                );

                console.log(
                    "Ports:",
                    portScanResult.ports
                );

                console.log(
                    "Unique Hosts:",
                    portScanResult.uniqueHosts
                );

                console.log(
                    "==========================================\n"
                );

            }

        }


        /*
        ========================================================
        STEP 8 - BUILD DETECTION RULE CONTEXT
        ========================================================
        */

        const ruleContext = {

            ...securityEvent.dataValues,

            ...(securityEvent.raw || {}),


            // Stateful port-scan fields

            portScan:
                portScanResult.detected,

            uniqueDestinationPorts:
                portScanResult.uniquePorts,

            uniqueDestinationHosts:
                portScanResult.uniqueHosts,

            scanType:
                portScanResult.scanType,


            // IOC rule context

            iocMatches:
                matchedIOCs

        };


        /*
        ========================================================
        STEP 9 - RUN DETECTION RULE ENGINE
        ========================================================
        */

        let ruleResult = {

            alerts: [],

            totalRisk: 0

        };


        try {

            ruleResult =
                evaluateRules(

                    ruleContext,

                    matchedIOCs

                );

        }
        catch (error) {

            console.log(
                "Rule engine failed:",
                error.message
            );

        }


        /*
         * Safety check in case a rule-engine implementation
         * returns incomplete data.
         */

        if (!Array.isArray(ruleResult.alerts)) {

            ruleResult.alerts = [];

        }


        if (
            typeof ruleResult.totalRisk !==
            "number"
        ) {

            ruleResult.totalRisk = 0;

        }


        /*
        ========================================================
        STEP 10 - FIND MATCHED PORT-SCAN RULE
        ========================================================
        */

        const portScanRule =
            ruleResult.alerts.find(

                alert =>
                    alert.ruleId ===
                    "PORT_SCAN_ATTACK"

            );


        /*
         * Use rule metadata when PORT_SCAN_ATTACK matched.
         */

        if (portScanRule) {

            securityEvent.attackType =
                "PORT_SCAN";

            securityEvent.severity =
                portScanRule.severity ||
                "CRITICAL";

        }


        /*
        ========================================================
        STEP 11 - PREPARE DETECTION RISK
        ========================================================
        */

        const detection = {

            riskScore:
                ruleResult.totalRisk,

            alerts:
                ruleResult.alerts

        };


        /*
        ========================================================
        STEP 12 - FINAL RISK CALCULATION
        ========================================================
        */

        let risk;


        try {

            risk =
                calculateRisk(

                    {

                        ...securityEvent.dataValues,

                        severity:
                            securityEvent.severity,

                        attackType:
                            securityEvent.attackType,

                        threatIntel: {

                            virusTotal: {

                                malicious:
                                    maxMalicious

                            },

                            abuseIPDB: {

                                abuseScore:
                                    maxAbuseScore

                            }

                        }

                    },

                    matchedIOCs,

                    detection

                );

        }
        catch (error) {

            console.log(
                "Risk calculation failed:",
                error.message
            );


            risk = {

                score: 0,

                level: "LOW",

                factors: {}

            };

        }


        console.log(
            "\n========== RISK DEBUG =========="
        );

        console.log({

            eventId:
                securityEvent.id,

            sourceIP:
                securityEvent.sourceIP,

            destinationIP:
                securityEvent.destinationIP,

            attackType:
                securityEvent.attackType,

            severity:
                securityEvent.severity,

            ruleAlerts:
                ruleResult.alerts,

            detectionRisk:
                detection.riskScore,

            matchedIOCs:
                matchedIOCs.map(
                    ioc => ({

                        id:
                            ioc.id,

                        type:
                            ioc.type,

                        value:
                            ioc.value,

                        confidence:
                            ioc.confidence

                    })
                ),

            virusTotalMalicious:
                maxMalicious,

            abuseIPDBScore:
                maxAbuseScore,

            portScanDetected:
                portScanResult.detected,

            portScanType:
                portScanResult.scanType,

            uniquePorts:
                portScanResult.uniquePorts,

            uniqueHosts:
                portScanResult.uniqueHosts,

            finalRisk:
                risk.score,

            riskLevel:
                risk.level,

            factors:
                risk.factors

        });

        console.log(
            "================================\n"
        );


        /*
        ========================================================
        STEP 13 - SAVE FINAL EVENT CLASSIFICATION
        ========================================================
        */

        securityEvent.riskScore =
            risk.score;


        await securityEvent.save();


        /*
        ========================================================
        STEP 14 - MITRE ATT&CK MAPPING
        ========================================================
        */

        let mitre = {

            technique:
                "UNKNOWN",

            tactic:
                "UNKNOWN"

        };


        try {

            const mapped =
                mapThreat(

                    securityEvent.attackType ||
                    "UNKNOWN"

                );


            if (mapped) {

                mitre = mapped;

            }

        }
        catch (error) {

            console.log(
                "MITRE mapping failed:",
                error.message
            );

        }


        /*
         * For port scans, detectionRules.json already
         * contains the exact MITRE mapping:
         *
         * T1046 - Network Service Discovery
         * Discovery
         */

        if (
            portScanRule &&
            portScanRule.mitre
        ) {

            mitre = {

                technique:
                    portScanRule
                        .mitre
                        .technique ||
                    "T1046",

                tactic:
                    portScanRule
                        .mitre
                        .tactic ||
                    "Discovery"

            };

        }


        /*
        ========================================================
        STEP 15 - INCIDENT CREATION / CORRELATION
        ========================================================

        Normal firewall traffic should remain a SecurityEvent.

        Only high-risk events should become incidents.

        Port-scan incidents additionally pass scanType so that:

        PORT_SCAN + VERTICAL_PORT_SCAN

        does NOT correlate with:

        PORT_SCAN + HORIZONTAL_PORT_SCAN
        */

        let incident = null;


        if (
            risk.score >=
            INCIDENT_RISK_THRESHOLD
        ) {

            try {

                // =============================================
                // DETERMINE INCIDENT SCAN TYPE
                // =============================================

                const incidentScanType =

                    securityEvent.attackType === "PORT_SCAN"

                        ? (
                            portScanResult.scanType ||

                            securityEvent.raw
                                ?.detection
                                ?.portScan
                                ?.scanType ||

                            null
                        )

                        : null;


                // =============================================
                // CREATE OR CORRELATE INCIDENT
                // =============================================

                incident =
                    await createIncidentFromAlert({

                        title:
                            buildIncidentTitle(
                                securityEvent,
                                portScanResult
                            ),

                        attackType:
                            securityEvent.attackType ||
                            "UNKNOWN",

                        /*
                         * IMPORTANT:
                         * incidentCreator.js uses this field
                         * when correlating PORT_SCAN incidents.
                         */

                        scanType:
                            incidentScanType,

                        severity:
                            risk.level,

                        riskScore:
                            risk.score,

                        sourceIP:
                            securityEvent.sourceIP,

                        description:
                            buildIncidentDescription(
                                securityEvent,
                                portScanResult
                            ),

                        mitreTechnique:
                            mitre?.technique ||
                            "UNKNOWN",

                        tactic:
                            mitre?.tactic ||
                            "UNKNOWN"

                    });


                // =============================================
                // LINK SECURITY EVENT TO INCIDENT
                // =============================================

                if (incident) {

                    securityEvent.incidentId =
                        incident.id;

                    await securityEvent.save();


                    console.log(

                        "EVENT LINKED TO INCIDENT:",

                        securityEvent.id,

                        "->",

                        incident.id,

                        "| Attack:",

                        securityEvent.attackType,

                        "| Scan Type:",

                        incidentScanType ||
                        "N/A"

                    );

                }

            }
            catch (error) {

                console.log(
                    "Incident processing failed:",
                    error.message
                );

            }

        }


        /*
        ========================================================
        STEP 16 - SUPPLEMENTARY BRUTE-FORCE DETECTOR
        ========================================================
        */

        try {

            await detectBruteForce(
                securityEvent
            );

        }
        catch (error) {

            /*
             * A secondary detector should not stop
             * the primary event pipeline.
             */

            console.log(
                "Brute-force detector error:",
                error.message
            );

        }


        /*
        ========================================================
        STEP 17 - REAL-TIME SOC UPDATE
        ========================================================
        */

        try {

            emitAlert({

                id:
                    securityEvent.id,

                title:
                    buildAlertTitle(
                        securityEvent,
                        portScanResult
                    ),

                description:
                    securityEvent.message,

                severity:
                    securityEvent.severity,

                status:
                    "NEW",

                sourceIP:
                    securityEvent.sourceIP,

                destinationIP:
                    securityEvent.destinationIP,

                attackType:
                    securityEvent.attackType,

                riskScore:
                    securityEvent.riskScore,

                incidentId:
                    securityEvent.incidentId,

                detection: {

                    portScan:
                        portScanResult.detected,

                    scanType:
                        portScanResult.scanType,

                    uniquePorts:
                        portScanResult.uniquePorts,

                    ports:
                        portScanResult.ports,

                    uniqueHosts:
                        portScanResult.uniqueHosts,

                    hosts:
                        portScanResult.hosts

                },

                createdAt:
                    securityEvent.createdAt

            });

        }
        catch (error) {

            console.log(
                "WebSocket alert emission failed:",
                error.message
            );

        }


        /*
        ========================================================
        STEP 18 - RETURN COMPLETE PIPELINE RESULT
        ========================================================
        */

        return {

            event:
                securityEvent,

            incident,

            matchedIOCs,

            threatRecords,

            risk,

            detection: {

                rules:
                    ruleResult.alerts,

                portScan:
                    portScanResult

            }

        };

    }
    catch (error) {

        /*
         * Core pipeline failure.
         */

        console.log(
            "Security event pipeline failed:",
            error.message
        );


        throw error;

    }

}


// ============================================================
// INCIDENT TITLE BUILDER
// ============================================================

function buildIncidentTitle(
    securityEvent,
    portScanResult
) {

    if (
        securityEvent.attackType ===
        "PORT_SCAN"
    ) {

        const scanType =
            portScanResult.scanType ||
            "PORT_SCAN";


        return (
            `${scanType} Detected from ` +
            `${securityEvent.sourceIP}`
        );

    }


    return (
        `${securityEvent.attackType || "Security"} ` +
        `Attack Detected`
    );

}


// ============================================================
// INCIDENT DESCRIPTION BUILDER
// ============================================================

function buildIncidentDescription(
    securityEvent,
    portScanResult
) {

    if (
        securityEvent.attackType ===
        "PORT_SCAN"
    ) {

        const ports =
            Array.isArray(
                portScanResult.ports
            )
                ? portScanResult.ports
                : [];


        return (

            `Port scanning activity detected from ` +

            `${securityEvent.sourceIP} targeting ` +

            `${securityEvent.destinationIP}. ` +

            `Observed ` +

            `${portScanResult.uniquePorts || 0} ` +

            `unique destination ports within ` +

            `${portScanResult.windowSeconds || 30} seconds. ` +

            `Ports: ${ports.join(", ")}.`

        );

    }


    return (
        securityEvent.message ||
        "Security event exceeded the incident risk threshold."
    );

}


// ============================================================
// ALERT TITLE BUILDER
// ============================================================

function buildAlertTitle(
    securityEvent,
    portScanResult
) {

    if (
        securityEvent.attackType ===
        "PORT_SCAN"
    ) {

        return (
            `${portScanResult.scanType || "PORT_SCAN"} Detected`
        );

    }


    return "Security Event Detected";

}


// ============================================================
// EXPORT
// ============================================================

module.exports = {

    processSecurityEvent

};
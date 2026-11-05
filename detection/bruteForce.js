const net = require("node:net");
const {
    createSecurityAlert
} = require("../services/alertService");


// Temporary in-memory failed-login tracker.
// Key = source IP
// Value = array of timestamps.
const attempts = {};


// 5 failed logins within 2 minutes
const THRESHOLD = 5;
const WINDOW_MS = 2 * 60 * 1000;


async function detectBruteForce(event) {

    const workspaceId = event?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error(
            "Valid workspace ID required for brute-force detection"
        );
    }


    /*
    ==========================================
    Only process REAL failed-login events
    ==========================================
    */

    const isFailedLogin =
        event.eventType === "WINDOWS_SECURITY_4625" ||
        event.attackType === "FAILED_LOGIN";

    if (!isFailedLogin) {
        return null;
    }


    /*
    ==========================================
    Validate source IP
    ==========================================
    */

    const ip = event.sourceIP;
    const attemptKey = `${workspaceId}:${ip}`;

    if (
        !ip ||
        net.isIP(ip) === 0 ||
        ip === "::1" ||
        ip.startsWith("127.") ||
        ip.toLowerCase().startsWith("::ffff:127.")
    ) {
        return null;
    }


    /*
    ==========================================
    Record failed-login attempt
    ==========================================
    */

    if (!attempts[attemptKey]) {
        attempts[attemptKey] = [];
    }

    const now = Date.now();

    attempts[attemptKey].push(now);


    /*
    ==========================================
    Keep attempts from last 2 minutes only
    ==========================================
    */

    attempts[attemptKey] = attempts[attemptKey].filter(
        time => now - time <= WINDOW_MS
    );

    const recentAttempts = attempts[attemptKey];

    console.log(
        `FAILED LOGIN: ${ip} | Attempts: ${recentAttempts.length}/${THRESHOLD}`
    );


    /*
    ==========================================
    Brute-force threshold reached
    ==========================================
    */

    if (recentAttempts.length < THRESHOLD) {
        return null;
    }


    /*
    ==========================================
    Create Brute-Force Alert
    ==========================================
    */

    const alert = await createSecurityAlert({
        workspaceId,

        title:
            "Brute Force Attack Detected",

        description:
            `${recentAttempts.length} failed login attempts detected from ${ip} within 2 minutes`,

        severity:
            "HIGH",

        sourceIP:
            ip,

        attackType:
            "BRUTE_FORCE",

        mitreTechnique:
            "T1110",

        tactic:
            "Credential Access",

        riskScore:
            85

    });


    console.log(
        `BRUTE FORCE DETECTED: ${ip}`
    );


    /*
    ==========================================
    Reset counter after alert
    ==========================================
    */

    attempts[attemptKey] = [];


    return alert;
}


module.exports = detectBruteForce;
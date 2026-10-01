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

    if (!ip) {
        return null;
    }


    /*
    ==========================================
    Record failed-login attempt
    ==========================================
    */

    if (!attempts[ip]) {
        attempts[ip] = [];
    }

    const now = Date.now();

    attempts[ip].push(now);


    /*
    ==========================================
    Keep attempts from last 2 minutes only
    ==========================================
    */

    attempts[ip] = attempts[ip].filter(
        time => now - time <= WINDOW_MS
    );

    const recentAttempts = attempts[ip];

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

    attempts[ip] = [];


    return alert;
}


module.exports = detectBruteForce;
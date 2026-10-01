const {
    checkIP
} = require("./virusTotalService");

const {
    checkIPReputation
} = require("./abuseIPDBService");

const ThreatIntel =
    require("../models/ThreatIntel");

const IOC =
    require("../models/IOC");


// ============================================================
// ENRICHMENT CACHE
// ============================================================

// Cache an IP reputation result for 24 hours.
const CACHE_TTL =
    24 * 60 * 60 * 1000;

// Maximum number of cached IPs kept in memory.
const MAX_CACHE_SIZE = 5000;

const enrichmentCache =
    new Map();

// Prevent several events for the same IP from starting
// several VirusTotal/AbuseIPDB requests simultaneously.
const pendingLookups =
    new Map();


// ============================================================
// CACHE HELPERS
// ============================================================

function getCachedResult(ip) {

    const cached =
        enrichmentCache.get(ip);

    if (!cached) {
        return null;
    }

    if (
        Date.now() -
        cached.cachedAt >
        CACHE_TTL
    ) {

        enrichmentCache.delete(ip);

        return null;
    }

    return cached.result;
}


function setCachedResult(ip, result) {

    // Basic cache-size protection.
    if (
        enrichmentCache.size >=
        MAX_CACHE_SIZE
    ) {

        const oldestKey =
            enrichmentCache.keys().next().value;

        if (oldestKey) {
            enrichmentCache.delete(oldestKey);
        }

    }

    enrichmentCache.set(ip, {

        cachedAt:
            Date.now(),

        result

    });
}


// ============================================================
// SAFE VIRUSTOTAL LOOKUP
// ============================================================

async function safeVirusTotalLookup(ip) {

    try {

        const result =
            await checkIP(ip);

        return {

            malicious:
                Number(
                    result?.malicious || 0
                ),

            available: true

        };

    }
    catch (error) {

        const status =
            error?.response?.status;

        if (status === 429) {

            console.log(
                `VirusTotal rate limit reached for ${ip}. ` +
                `Skipping VT enrichment.`
            );

        }
        else {

            console.log(
                `VirusTotal lookup failed for ${ip}:`,
                error.message
            );

        }

        return {

            malicious: 0,
            available: false

        };

    }

}


// ============================================================
// SAFE ABUSEIPDB LOOKUP
// ============================================================

async function safeAbuseIPDBLookup(ip) {

    try {

        const result =
            await checkIPReputation(ip);

        return {

            score:
                Number(
                    result?.score || 0
                ),

            available: true

        };

    }
    catch (error) {

        const status =
            error?.response?.status;

        if (status === 429) {

            console.log(
                `AbuseIPDB rate limit reached for ${ip}. ` +
                `Skipping AbuseIPDB enrichment.`
            );

        }
        else {

            console.log(
                `AbuseIPDB lookup failed for ${ip}:`,
                error.message
            );

        }

        return {

            score: 0,
            available: false

        };

    }

}


// ============================================================
// PERFORM FRESH ENRICHMENT
// ============================================================

async function performEnrichment(ioc) {

    const ip =
        ioc.value;


    /*
     * Run the two independent reputation services
     * concurrently rather than waiting for one and
     * then starting the other.
     */

    const [
        vt,
        abuse
    ] = await Promise.all([

        safeVirusTotalLookup(ip),

        safeAbuseIPDBLookup(ip)

    ]);


    let severity =
        "LOW";

    let riskScore =
        0;

    let reputation =
        "CLEAN";

    let confidence =
        "LOW";


    // ========================================================
    // CLASSIFY REPUTATION
    // ========================================================

    if (
        vt.malicious > 10 ||
        abuse.score > 80
    ) {

        severity =
            "HIGH";

        riskScore =
            80;

        reputation =
            "MALICIOUS";

        confidence =
            "HIGH";

    }
    else if (
        vt.malicious > 0 ||
        abuse.score > 50
    ) {

        severity =
            "MEDIUM";

        riskScore =
            40;

        reputation =
            "SUSPICIOUS";

        confidence =
            "MEDIUM";

    }


    /*
     * If BOTH external services failed, do not claim
     * that the IP is CLEAN. We simply don't know.
     */

    const enrichmentAvailable =
        vt.available ||
        abuse.available;


    if (!enrichmentAvailable) {

        console.log(
            `IOC enrichment unavailable for ${ip}`
        );

        return {

            threatRecord: null,

            malicious: 0,

            abuseScore: 0,

            cached: false,

            enrichmentAvailable: false

        };

    }


    // ========================================================
    // UPDATE IOC
    // ========================================================

    await IOC.update(

        {

            reputation,

            lastSeen:
                new Date()

        },

        {

            where: {
                id: ioc.id
            }

        }

    );


    // ========================================================
    // STORE THREAT INTELLIGENCE
    // ========================================================

    const threatRecord =
        await ThreatIntel.create({

            name:
                `IOC Reputation ${ip}`,

            description:
                `VirusTotal detected ${vt.malicious} ` +
                `malicious engines, AbuseIPDB ` +
                `confidence score ${abuse.score}`,

            attackType:
                "IOC_REPUTATION",

            severity,

            riskScore,

            confidence,

            status:
                "NEW",

            sourceIP:
                ip

        });


    return {

        threatRecord,

        malicious:
            vt.malicious,

        abuseScore:
            abuse.score,

        cached:
            false,

        enrichmentAvailable:
            true

    };

}


// ============================================================
// MAIN IOC ENRICHMENT
// ============================================================

async function enrichIOC(ioc) {

    try {

        // Currently external reputation enrichment
        // is only supported for IP IOCs.

        if (
            !ioc ||
            ioc.type !== "IP" ||
            !ioc.value
        ) {

            return null;

        }


        const ip =
            String(ioc.value).trim();


        // ====================================================
        // 1. CHECK CACHE
        // ====================================================

        const cached =
            getCachedResult(ip);


        if (cached) {

            console.log(
                `IOC CACHE HIT: ${ip}`
            );

            return {

                ...cached,

                cached: true

            };

        }


        // ====================================================
        // 2. CHECK FOR AN EXISTING IN-FLIGHT LOOKUP
        // ====================================================

        if (
            pendingLookups.has(ip)
        ) {

            console.log(
                `IOC LOOKUP ALREADY RUNNING: ${ip}`
            );

            return await pendingLookups.get(ip);

        }


        // ====================================================
        // 3. START FRESH LOOKUP
        // ====================================================

        console.log(
            `IOC ENRICHMENT LOOKUP: ${ip}`
        );


        const lookupPromise =
            performEnrichment(ioc);


        pendingLookups.set(
            ip,
            lookupPromise
        );


        try {

            const result =
                await lookupPromise;


            /*
             * Only cache results when at least one
             * enrichment provider actually responded.
             */

            if (
                result &&
                result.enrichmentAvailable
            ) {

                setCachedResult(
                    ip,
                    result
                );

            }


            return result;

        }
        finally {

            pendingLookups.delete(ip);

        }

    }
    catch (error) {

        console.log(
            "IOC Enrichment Error:",
            error.message
        );

        return null;

    }

}


// ============================================================
// EXPORT
// ============================================================

module.exports =
    enrichIOC;
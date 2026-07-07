const axios = require("axios");

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;

/**
 * 🔍 VIRUSTOTAL LOOKUP
 */
const checkVirusTotal = async (ipOrHash) => {

    try {

        const response = await axios.get(
            `https://www.virustotal.com/api/v3/ip_addresses/${ipOrHash}`,
            {
                headers: {
                    "x-apikey": VIRUSTOTAL_API_KEY
                }
            }
        );

        return {
            source: "VirusTotal",
            reputation: response.data?.data?.attributes?.reputation || "UNKNOWN",
            malicious: response.data?.data?.attributes?.last_analysis_stats?.malicious || 0
        };

    } catch (err) {
        return null;
    }
};

/**
 * 🚨 ABUSEIPDB CHECK
 */
const checkAbuseIPDB = async (ip) => {

    try {

        const response = await axios.get(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`,
            {
                headers: {
                    Key: ABUSEIPDB_API_KEY,
                    Accept: "application/json"
                }
            }
        );

        return {
            source: "AbuseIPDB",
            abuseScore: response.data?.data?.abuseConfidenceScore || 0,
            country: response.data?.data?.countryCode
        };

    } catch (err) {
        return null;
    }
};

/**
 * 🌍 GEO IP (simple version fallback)
 */
const geoLookup = async (ip) => {

    try {

        const response = await axios.get(`http://ip-api.com/json/${ip}`);

        return {
            country: response.data.country,
            region: response.data.regionName,
            isp: response.data.isp
        };

    } catch (err) {
        return null;
    }
};

/**
 * 🔥 MAIN ENRICHMENT FUNCTION
 */
exports.enrichThreat = async (event) => {

    const ip = event.sourceIP;

    const vt = await checkVirusTotal(ip);
    const abuse = await checkAbuseIPDB(ip);
    const geo = await geoLookup(ip);

    return {
        ip,
        virusTotal: vt,
        abuseIPDB: abuse,
        geo,
        confidenceScore:
            (vt?.malicious > 10 ? 50 : 0) +
            (abuse?.abuseScore > 50 ? 30 : 0)
    };
};
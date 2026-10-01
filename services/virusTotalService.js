const axios = require("axios");


// ============================================================
// VIRUSTOTAL CONFIGURATION
// ============================================================

const VT_BASE_URL =
    "https://www.virustotal.com/api/v3";


function getHeaders() {

    if (!process.env.VIRUSTOTAL_API_KEY) {

        throw new Error(
            "VIRUSTOTAL_API_KEY is not configured"
        );

    }

    return {

        "x-apikey":
            process.env.VIRUSTOTAL_API_KEY

    };

}


// ============================================================
// IP REPUTATION LOOKUP
// ============================================================

exports.checkIP = async (ip) => {

    try {

        const response =
            await axios.get(

                `${VT_BASE_URL}/ip_addresses/${encodeURIComponent(ip)}`,

                {

                    headers:
                        getHeaders(),

                    timeout:
                        10000

                }

            );


        const attributes =
            response?.data?.data?.attributes || {};


        const stats =
            attributes.last_analysis_stats || {};


        return {

            source:
                "VirusTotal",

            ip,

            malicious:
                Number(stats.malicious || 0),

            suspicious:
                Number(stats.suspicious || 0),

            harmless:
                Number(stats.harmless || 0),

            undetected:
                Number(stats.undetected || 0),

            reputation:
                Number(attributes.reputation || 0),

            country:
                attributes.country || null,

            asn:
                attributes.asn || null,

            network:
                attributes.network || null,

            lastAnalysis:
                new Date(),

            available:
                true

        };

    }
    catch (error) {

        const status =
            error?.response?.status;


        if (status === 429) {

            console.log(
                `VirusTotal rate limit reached for ${ip}`
            );

        }
        else if (status === 401) {

            console.log(
                "VirusTotal authentication failed - check API key"
            );

        }
        else if (status === 403) {

            console.log(
                "VirusTotal request forbidden - check API permissions/quota"
            );

        }
        else if (status === 404) {

            console.log(
                `VirusTotal has no IP record for ${ip}`
            );

        }
        else {

            console.log(
                `VirusTotal IP lookup failed for ${ip}:`,
                error.message
            );

        }


        /*
         * IMPORTANT:
         *
         * Do NOT return malicious: 0 here.
         *
         * Zero means VirusTotal successfully checked the IP
         * and found no malicious detections.
         *
         * An API failure means we DON'T KNOW.
         *
         * Throw the error so iocEnrichment.js can handle it.
         */

        throw error;

    }

};


// ============================================================
// FILE HASH LOOKUP
// ============================================================

exports.checkFileHash = async (hash) => {

    try {

        const response =
            await axios.get(

                `${VT_BASE_URL}/files/${encodeURIComponent(hash)}`,

                {

                    headers:
                        getHeaders(),

                    timeout:
                        10000

                }

            );


        const attributes =
            response?.data?.data?.attributes || {};


        const stats =
            attributes.last_analysis_stats || {};


        return {

            source:
                "VirusTotal",

            hash,

            found:
                true,

            malicious:
                Number(stats.malicious || 0),

            suspicious:
                Number(stats.suspicious || 0),

            harmless:
                Number(stats.harmless || 0),

            undetected:
                Number(stats.undetected || 0),

            reputation:
                Number(attributes.reputation || 0),

            available:
                true,

            data:
                response.data

        };

    }
    catch (error) {

        const status =
            error?.response?.status;


        if (status === 404) {

            console.log(
                `VirusTotal has no record for hash ${hash}`
            );

            return {

                source:
                    "VirusTotal",

                hash,

                found:
                    false,

                available:
                    true,

                malicious:
                    0,

                suspicious:
                    0,

                harmless:
                    0,

                undetected:
                    0,

                data:
                    null

            };

        }


        if (status === 429) {

            console.log(
                `VirusTotal rate limit reached while checking hash ${hash}`
            );

        }
        else if (status === 401) {

            console.log(
                "VirusTotal authentication failed - check API key"
            );

        }
        else if (status === 403) {

            console.log(
                "VirusTotal request forbidden - check API permissions/quota"
            );

        }
        else {

            console.log(
                `VirusTotal hash lookup failed for ${hash}:`,
                error.message
            );

        }


        throw error;

    }

};
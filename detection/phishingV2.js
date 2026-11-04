/**
 * Enterprise SIEM - Phishing V2
 * Offline URL heuristic detection.
 * Does not visit URLs or execute response actions.
 */

const URL_PATTERN = /https?:\/\/[^\s<>"']+/gi;

function extractURLs(event) {
    const urls = new Set();

    function collect(value, depth = 0) {
        if (depth > 6) return;

        if (typeof value === "string") {
            const matches = value.match(URL_PATTERN) || [];

            for (const match of matches) {
                urls.add(
                    match.replace(/[),.;!?]+$/, "")
                );
            }
        } else if (Array.isArray(value)) {
            value.forEach(item => collect(item, depth + 1));
        } else if (value && typeof value === "object") {
            Object.values(value).forEach(
                item => collect(item, depth + 1)
            );
        }
    }

    collect({
        message: event?.message,
        raw: event?.raw
    });

    return [...urls];
}

function analyseURL(value) {
    let parsed;

    try {
        parsed = new URL(value);
    } catch {
        return null;
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        return null;
    }

    const host = parsed.hostname.toLowerCase();
    const indicators = [];
    let score = 0;

    const add = (name, points) => {
        indicators.push(name);
        score += points;
    };

    if (parsed.protocol === "http:") {
        add("UNENCRYPTED_HTTP", 10);
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        add("IP_ADDRESS_HOST", 25);
    }

    if (host.includes("xn--")) {
        add("PUNYCODE_DOMAIN", 20);
    }

    if (host.split(".").length >= 5) {
        add("EXCESSIVE_SUBDOMAINS", 15);
    }

    if (parsed.username || parsed.password) {
        add("URL_USERINFO", 30);
    }

    if (value.length > 150) {
        add("LONG_URL", 10);
    }

    const path = (
        parsed.pathname + parsed.search
    ).toLowerCase();

    if (
        /(?:verify|confirm|reset|update)[-_]?(?:account|password|identity|login)/i
            .test(path)
    ) {
        add("CREDENTIAL_VERIFICATION_LURE", 25);
    }

    if (
        /(?:secure|verify|account|login|support)[-_]?(?:bank|wallet|payment)/i
            .test(host)
    ) {
        add("SUSPICIOUS_DOMAIN_COMBINATION", 30);
    }

    if (
        /(?:password|passwd|token|otp)=/i.test(
            parsed.search
        )
    ) {
        add("CREDENTIAL_IN_QUERY", 25);
    }

    return {
        url: value,
        hostname: host,
        indicators,
        score: Math.min(score, 100)
    };
}

async function detectPhishingV2(event) {
    const urls = extractURLs(event);

    const results = urls
        .map(analyseURL)
        .filter(Boolean);

    const strongest = results
        .sort((a, b) => b.score - a.score)[0];

    if (!strongest || strongest.score < 60) {
        return {
            detected: false,
            urls,
            results,
            reason: "INSUFFICIENT_PHISHING_INDICATORS"
        };
    }

    return {
        detected: true,
        attackType: "PHISHING",
        severity: strongest.score >= 80
            ? "CRITICAL"
            : "HIGH",
        riskScore: strongest.score,
        suspiciousURL: strongest.url,
        indicators: strongest.indicators,
        urls,
        results,
        mitre: {
            technique: "T1566",
            tactic: "Initial Access"
        },
        detectedAt: new Date().toISOString()
    };
}

module.exports = {
    detectPhishingV2,
    extractURLs
};

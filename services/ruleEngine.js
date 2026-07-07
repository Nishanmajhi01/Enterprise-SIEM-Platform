exports.detectAttack = (event, iocMatches) => {

    let alert = null;
    let severity = "LOW";
    let mitre = null;
    let riskScore = 10;

    // RULE 1: Brute Force Detection
    if (event.failedLogins >= 5) {

        alert = "BRUTE FORCE DETECTED";
        severity = "HIGH";
        riskScore += 60;

        mitre = {
            technique: "T1110",
            tactic: "Credential Access",
            name: "Brute Force"
        };
    }

    // RULE 2: IOC Match (critical)
    if (iocMatches.length > 0) {

        alert = "MALICIOUS IOC DETECTED";
        severity = "CRITICAL";
        riskScore += 80;

        mitre = {
            technique: "T1071",
            tactic: "Command and Control",
            name: "Known Bad Indicator"
        };
    }

    // RULE 3: Suspicious Activity
    if (event.portScan === true) {

        alert = "PORT SCANNING DETECTED";
        severity = "MEDIUM";
        riskScore += 40;

        mitre = {
            technique: "T1046",
            tactic: "Discovery",
            name: "Network Scan"
        };
    }

    return {
        alert,
        severity,
        riskScore,
        mitre
    };
};
/**
 * Enterprise SIEM Risk Engine
 *
 * Calculates final risk score using:
 * - Detection rule score
 * - IOC reputation
 * - Threat Intelligence
 * - Severity impact
 * - MITRE impact
 */


exports.calculateRisk = (
    event,
    iocMatches = [],
    detection = {}
) => {


    let riskScore = 0;



    // 1. Detection Rule Risk

    if (detection.riskScore) {

        riskScore += detection.riskScore;

    }



    // 2. IOC Reputation Risk

    if (iocMatches.length > 0) {

        riskScore += 30;

    }



    // 3. Threat Intelligence Risk

    const threatIntel =
        event.threatIntel;



    if (threatIntel) {


        // VirusTotal

        const malicious =
        threatIntel
        ?.virusTotal
        ?.malicious || 0;



        if (malicious > 0) {

            riskScore += 30;

        }


        if (malicious > 10) {

            riskScore += 20;

        }



        // AbuseIPDB

        const abuseScore =
        threatIntel
        ?.abuseIPDB
        ?.abuseScore || 0;



        if (abuseScore > 50) {

            riskScore += 20;

        }


        if (abuseScore > 80) {

            riskScore += 20;

        }



        // Threat confidence

        riskScore +=
        threatIntel.confidenceScore || 0;


    }



    // 4. Severity Weight

    switch(
        event.severity
    ){

        case "CRITICAL":

            riskScore += 30;

            break;


        case "HIGH":

            riskScore += 25;

            break;


        case "MEDIUM":

            riskScore += 15;

            break;


        default:

            riskScore += 5;

    }



    if(event.attackType === "BRUTE_FORCE"){

    riskScore +=20;

}


if(event.attackType === "MALWARE"){

    riskScore +=25;

}


if(event.attackType === "DATA_EXFILTRATION"){

    riskScore +=30;

}



    // 5. Limit Score

    if(riskScore > 100){

        riskScore = 100;

    }



    // Risk Category

    let level;


    if(riskScore >= 90){

        level="CRITICAL";

    }
    else if(riskScore >= 70){

        level="HIGH";

    }
    else if(riskScore >= 40){

        level="MEDIUM";

    }
    else{

        level="LOW";

    }



    return {


        score:riskScore,

        level,


        factors:{


            detectionRisk:
            detection.riskScore || 0,


            iocDetected:
            iocMatches.length > 0,


            threatIntelUsed:
            !!threatIntel


        }


    };


};
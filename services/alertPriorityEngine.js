/**
 * Enterprise SOC Alert Priority Engine
 */


exports.calculateAlertPriority = (risk) => {


    let priority = "LOW";


    if (!risk || risk.score === undefined) {

        return priority;

    }


    if (risk.score >= 90) {

        priority = "CRITICAL";

    } 
    else if (risk.score >= 70) {

        priority = "HIGH";

    } 
    else if (risk.score >= 40) {

        priority = "MEDIUM";

    }


    return priority;


};
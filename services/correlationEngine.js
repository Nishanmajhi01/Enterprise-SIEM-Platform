const {
    createSecurityAlert
} = require("./alertService");


const {
    mapThreat
} = require("./mitreMapper");



exports.runCorrelation = async(
    event,
    iocMatches = [],
    detection = {}
)=>{


    const result = {


        event,

        iocMatches,

        detection,

        timestamp:new Date()


    };





    // No detection matched

    if(
        !detection ||
        !detection.alert
    ){

        return result;

    }







    // ==============================
    // MITRE MAPPING
    // ==============================


    const mitre =
    detection.mitre
    ||
    mapThreat(
        event.attackType || "UNKNOWN"
    );









    // ==============================
    // CREATE ALERT
    // ==============================


    const securityResult =
    await createSecurityAlert({



        title:
        detection.alert,



        description:
        `Security detection triggered from ${event.sourceIP}`,



        severity:
        detection.severity || "LOW",



        sourceIP:
        event.sourceIP,



        attackType:
        event.attackType || "UNKNOWN",



        riskScore:
        detection.riskScore || 0,



        mitreTechnique:
        mitre.technique,



        tactic:
        mitre.tactic,



        evidence:{

            event,

            iocMatches

        }


    });








    result.alertId =
    securityResult.alert.id;




    if(
    securityResult.incident
){


    result.incidentId =
    securityResult.incident.id;


    await event.update({

        incidentId:
        securityResult.incident.id

    });


}







    return result;


};
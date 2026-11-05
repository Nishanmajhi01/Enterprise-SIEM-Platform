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

    const workspaceId = event?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error(
            "Valid workspace ID required for correlation"
        );
    }



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
          workspaceId,



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


    // Event-to-incident linking requires a separate
      // workspace-scoped database operation.


}







    return result;


};
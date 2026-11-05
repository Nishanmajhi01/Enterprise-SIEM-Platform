const Alert = require("../models/Alert");

const {
    emitAlert
} = require("../utils/socketEmitter");


const createIncidentFromAlert =
require("./incidentCreator");



exports.createSecurityAlert = async(data)=>{

    const workspaceId = data?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error(
            "Valid workspace ID required for security alert creation"
        );
    }



    try{


        // ==========================
        // CREATE SECURITY ALERT
        // ==========================


        const alert =
        await Alert.create({

            workspaceId,



            title:
            data.title,



            description:
            data.description,



            severity:
            data.severity || "LOW",



            sourceIP:
            data.sourceIP || null,



            attackType:
            data.attackType || "UNKNOWN",



            riskScore:
            data.riskScore || 0,



            status:
            "NEW",



            createdBy:
            data.createdBy || null


        });




        console.log(
            "ALERT CREATED:",
            alert.id
        );






        // ==========================
        // CREATE INCIDENT IF REQUIRED
        // ==========================


        const incident =
        await createIncidentFromAlert({

            ...alert.toJSON(),

            alertInstance: alert,


            mitreTechnique:
            data.mitreTechnique || "UNKNOWN",


            tactic:
            data.tactic || "UNKNOWN"

        });







        // ==========================
        // REAL TIME ALERT UPDATE
        // ==========================


        emitAlert(alert);





        return {


            alert,


            incident


        };



    }
    catch(error){


        console.log(
            "Alert creation failed:",
            error.message
        );


        throw error;


    }


};
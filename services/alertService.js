const Alert = require("../models/Alert");

const {
    emitAlert
} = require("../utils/socketEmitter");


const createIncidentFromAlert =
require("./incidentCreator");



exports.createSecurityAlert = async(data)=>{


    try{


        // ==========================
        // CREATE SECURITY ALERT
        // ==========================


        const alert =
        await Alert.create({



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
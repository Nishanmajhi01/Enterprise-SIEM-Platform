let io = null;



// =====================================
// INITIALIZE SOCKET.IO INSTANCE
// =====================================

exports.setIO = (socketIO)=>{


    io = socketIO;


};






// =====================================
// EMIT SECURITY ALERT
// =====================================

exports.emitAlert = (alert)=>{


    if(!io){

        console.log(
            "Socket.IO not initialized"
        );

        return;

    }



    io.emit(
        "security-alert",
        {


            id:
            alert.id,


            title:
            alert.title,


            description:
            alert.description,


            severity:
            alert.severity,


            status:
            alert.status,


            sourceIP:
            alert.sourceIP,


            attackType:
            alert.attackType,


            riskScore:
            alert.riskScore,


            createdAt:
            alert.createdAt


        }
    );


};







// =====================================
// EMIT SECURITY INCIDENT
// =====================================

exports.emitIncident = (incident)=>{


    if(!io){

        console.log(
            "Socket.IO not initialized"
        );

        return;

    }



    io.emit(
        "security-incident",
        {


            id:
            incident.id,


            title:
            incident.title,


            attackType:
            incident.attackType,


            severity:
            incident.severity,


            riskScore:
            incident.riskScore,


            status:
            incident.status,


            sourceIP:
            incident.sourceIP,


            mitreTechnique:
            incident.mitreTechnique,


            tactic:
            incident.tactic,


            alertId:
            incident.alertId,


            createdAt:
            incident.createdAt


        }
    );


};
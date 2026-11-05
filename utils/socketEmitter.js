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



    const workspaceId = alert?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        console.error(
            "Security alert emission rejected: invalid workspaceId"
        );
        return;
    }

    io.to(`workspace:${workspaceId}`).emit(
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
            alert.createdAt,

            destinationIP:
            alert.destinationIP,

            incidentId:
            alert.incidentId,

            mitreTechnique:
            alert.mitreTechnique,

            tactic:
            alert.tactic,

            detection:
            alert.detection,

            scanType:
            alert.detection?.scanType ?? alert.scanType


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



    const workspaceId = incident?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        console.error(
            "Security incident emission rejected: invalid workspaceId"
        );
        return;
    }

    io.to(`workspace:${workspaceId}`).emit(
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
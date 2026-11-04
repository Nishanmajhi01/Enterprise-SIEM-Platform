const Incident =
require("../models/Incident");
const Alert = require("../models/Alert");

const ResponseAction =
require("../models/ResponseAction");

const SecurityEvent =
require("../models/SecurityEvent");

const IncidentComment =
require("../models/IncidentComment");
const IncidentAssignment =
require("../models/IncidentAssignment");

const Evidence =
require("../models/Evidence");

const Investigation =
require("../models/Investigation");


const createAuditLog =
require("../utils/auditLogger");







exports.createIncident = async(req,res)=>{


try{


const allowedFields = [
    "title",
    "attackType",
    "scanType",
    "mitreTechnique",
    "tactic",
    "severity",
    "riskScore",
    "sourceIP",
    "description",
    "evidence",
    "recommendation"
];

const incidentData = {};

for (const field of allowedFields) {
    if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
        incidentData[field] = req.body[field];
    }
}

if (
    typeof incidentData.title !== "string" ||
    !incidentData.title.trim() ||
    typeof incidentData.attackType !== "string" ||
    !incidentData.attackType.trim()
) {
    return res.status(400).json({
        message: "Valid title and attackType are required"
    });
}

incidentData.title = incidentData.title.trim();
incidentData.attackType = incidentData.attackType.trim().toUpperCase();

const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

if (
    incidentData.title.length > 255 ||
    incidentData.attackType.length > 100
) {
    return res.status(400).json({
        message: "Title or attack type exceeds maximum length"
    });
}

if (
    incidentData.severity !== undefined &&
    !validSeverities.includes(incidentData.severity)
) {
    return res.status(400).json({
        message: "Invalid incident severity"
    });
}

if (
    incidentData.riskScore !== undefined &&
    (
        !Number.isInteger(incidentData.riskScore) ||
        incidentData.riskScore < 0 ||
        incidentData.riskScore > 100
    )
) {
    return res.status(400).json({
        message: "Risk score must be an integer between 0 and 100"
    });
}

const optionalStrings = [
    "scanType",
    "mitreTechnique",
    "tactic",
    "sourceIP",
    "description",
    "recommendation"
];

for (const field of optionalStrings) {
    if (
        incidentData[field] !== undefined &&
        incidentData[field] !== null &&
        typeof incidentData[field] !== "string"
    ) {
        return res.status(400).json({
            message: `Invalid ${field}: expected a string`
        });
    }
}

if (
    incidentData.evidence !== undefined &&
    !Array.isArray(incidentData.evidence)
) {
    return res.status(400).json({
        message: "Evidence must be an array"
    });
}

const incident =
await Incident.create({

    ...incidentData,
    status: "OPEN",

    timeline:[
        {
            action:"INCIDENT_CREATED",
            user:req.user?.username || "SYSTEM",
            time:new Date()
        }
    ]

});













await createAuditLog({

username:req.user?.username || "SYSTEM",

action:"INCIDENT_CREATED",

module:"INCIDENT",

severity:incident.severity,

ipAddress:req.ip,

description:
`Incident created: ${incident.title}`

});


// Manual incidents must not automatically execute response playbooks.




res.json({

success:true,

incident

});



}
catch(error){


res.status(500).json({

error:error.message

});


}


};









exports.getIncidents = async(req,res)=>{


try{


const incidents = await Incident.findAll({

    include:[

        {
            model: Alert,
            as:"alerts"
        },
        {
            model: SecurityEvent,
            as:"events"
        }

    ],

    order:[
        ["createdAt","DESC"]
    ]

});



res.json({

count:incidents.length,

incidents

});



}
catch(error){


res.status(500).json({

error:error.message

});


}


};









exports.getIncidentById = async(req,res)=>{


try{


const incident =
await Incident.findByPk(

req.params.id,

{

include:[

{

model:Alert,

as:"alerts"

},

{

model:SecurityEvent,

as:"events"

},

{

model:ResponseAction,

as:"responseActions"

},

{
model:IncidentComment,
as:"comments"
},
{
model:Evidence,
as:"evidenceItems"
},
{
model:Investigation,
as:"investigations"
}

]

}

);



if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}



res.json({

success:true,

incident

});


}
catch(error){


console.log(
"Incident details error:",
error.message
);


res.status(500).json({

error:error.message

});


}


};


exports.updateIncident = async(req,res)=>{


try{


const incident =
await Incident.findByPk(
req.params.id
);



if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}





// SECURITY: Closed incidents are immutable.
if (incident.status === "CLOSED") {
    return res.status(409).json({
        message: "Closed incidents cannot be modified"
    });
}

// SECURITY: Only status updates are permitted here.
const body = req.body;

if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.keys(body).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(body, "status")
) {
    return res.status(400).json({
        message: "Only the status field can be updated"
    });
}

// SECURITY: Validate incident lifecycle transitions.
const allowedTransitions = {
    OPEN: ["ACKNOWLEDGED", "INVESTIGATING"],
    ACKNOWLEDGED: ["INVESTIGATING"],
    INVESTIGATING: [],
    CONTAINED: [],
    RESOLVED: [],
    CLOSED: []
};

const nextStatus = body.status;

if (
    typeof nextStatus !== "string" ||
    !allowedTransitions[incident.status]?.includes(nextStatus)
) {
    return res.status(409).json({
        message: "Invalid incident status transition"
    });
}

incident.timeline = incident.timeline || [];

incident.timeline.push({
    action: "INCIDENT_UPDATED",
    user: req.user?.username || "SYSTEM",
    changes: {
        status: {
            from: incident.status,
            to: nextStatus
        }
    },
    time: new Date()
});

incident.status = nextStatus;


incident.changed(
"timeline",
true
);


await incident.save();





res.json({

message:"Incident updated",

incident

});



}
catch(error){


res.status(500).json({

error:error.message

});


}


};









exports.assignIncident = async(req,res)=>{

try{


const incident =
await Incident.findByPk(req.params.id);


if(!incident){

return res.status(404).json({
message:"Incident not found"
});

}



// SECURITY: Prevent assigning closed incidents.
if (incident.status === "CLOSED") {
    return res.status(409).json({
        message: "Closed incidents cannot be assigned"
    });
}

const User =
require("../models/User");



const user =
await User.findByPk(
req.body.userId
);



if(!user){

return res.status(404).json({

message:"Assigned user not found"

});

}




if(
user.role !== "ANALYST" &&
user.role !== "ADMIN"
){

return res.status(403).json({

message:
"Only SOC analysts or admins can receive incidents"

});

}




const assignment =
await IncidentAssignment.create({

incidentId:incident.id,

userId:user.id,

username:user.username,

role:user.role

});





incident.assignedTo =
user.id;



incident.status =
"INVESTIGATING";




incident.timeline =
incident.timeline || [];



incident.timeline.push({

action:"INCIDENT_ASSIGNED",

assignedTo:user.username,

assignedRole:user.role,

assignedBy:
req.user?.username || "SYSTEM",

time:new Date()

});


incident.changed(
"timeline",
true
);


await incident.save();





await createAuditLog({

userId:req.user?.id,

username:
req.user?.username || "SYSTEM",

action:
"INCIDENT_ASSIGNED",

module:
"INCIDENT",

severity:
incident.severity,

ipAddress:
req.ip,


description:
`Incident ${incident.id} assigned to ${user.username}`


});






res.json({

success:true,

message:
"Incident assigned successfully",


assignment,

incident


});




}
catch(error){


console.log(
"Assignment Error:",
error.message
);


res.status(500).json({

error:error.message

});


}


};


exports.getAssignments = async(req,res)=>{

try{


const assignments =
await IncidentAssignment.findAll({

where:{
incidentId:req.params.id
},

order:[
["createdAt","DESC"]
]

});



res.json({

count:assignments.length,

assignments

});


}
catch(error){

res.status(500).json({

error:error.message

});

}


};









exports.resolveIncident = async (req, res) => {

    const resolutionNote = req.body?.resolutionNote;

    if (
        typeof resolutionNote !== "string" ||
        !resolutionNote.trim() ||
        resolutionNote.length > 5000
    ) {
        return res.status(400).json({
            message: "A resolution note is required (maximum 5000 characters)"
        });
    }

    if (!req.user?.id) {
        return res.status(401).json({
            message: "Authenticated analyst identity required"
        });
    }

    const { sequelize } = require("../config/database");

    let incident;

    try {

        await sequelize.transaction(async (transaction) => {

            incident = await Incident.findByPk(req.params.id, {
                transaction,
                lock: transaction.LOCK.UPDATE
            });

            if (!incident) {
                const error = new Error("Incident not found");
                error.statusCode = 404;
                throw error;
            }

            if (incident.status !== "CONTAINED") {
                const error = new Error(
                    "Incident must be CONTAINED before resolution"
                );
                error.statusCode = 409;
                throw error;
            }

            incident.status = "RESOLVED";
            incident.resolutionNote = resolutionNote.trim();
            incident.resolvedBy = req.user.id;

            incident.timeline = [
                ...(Array.isArray(incident.timeline) ? incident.timeline : []),
                {
                    action: "RESOLVED",
                    userId: req.user.id,
                    user: req.user.username || "UNKNOWN",
                    note: resolutionNote.trim(),
                    time: new Date()
                }
            ];

            incident.changed("timeline", true);

            await incident.save({ transaction });

        });

        try {
            await createAuditLog({
                userId: req.user.id,
                username: req.user.username || "UNKNOWN",
                action: "INCIDENT_RESOLVED",
                module: "INCIDENT_RESPONSE",
                severity: incident.severity,
                ipAddress: req.ip,
                description: `Incident ${incident.id} resolved`,
                metadata: {
                    incidentId: incident.id,
                    resolutionNote: resolutionNote.trim()
                }
            });
        } catch (auditError) {
            console.error("Resolution audit logging failed:", auditError);
        }

        return res.json({
            success: true,
            message: "Incident resolved successfully",
            incident
        });

    } catch (error) {

        console.error("Incident resolution failed:", error);

        return res.status(error.statusCode || 500).json({
            message: error.statusCode
                ? error.message
                : "Unable to resolve incident"
        });
    }
};



exports.containIncident = async (req, res) => {
    return res.status(501).json({
        message: "Containment execution is not yet implemented",
        details:
            "No firewall action was executed. " +
            "The incident status and response history remain unchanged."
    });
};


// ============================
// // CLOSE INCIDENT
// ============================

exports.closeIncident = async(req,res)=>{

try{


const incident =
await Incident.findByPk(req.params.id);


if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}



// SECURITY: Prevent duplicate incident closure.
if (incident.status === "CLOSED") {
    return res.status(409).json({
        message: "Incident is already closed"
    });
}

// SECURITY: Only resolved incidents may be closed.
if (incident.status !== "RESOLVED") {
    return res.status(409).json({
        message: "Only RESOLVED incidents can be closed"
    });
}

// SECURITY: Require a meaningful closure note.
const closureNote = req.body?.closureNote;

if (
    typeof closureNote !== "string" ||
    !closureNote.trim() ||
    closureNote.trim().length > 2000
) {
    return res.status(400).json({
        message: "A closure note between 1 and 2000 characters is required"
    });
}

incident.status="CLOSED";


incident.closedBy =
req.user?.id || null;


incident.closedAt =
new Date();


incident.closureNote =
closureNote.trim();



incident.timeline =
incident.timeline || [];


incident.timeline.push({

action:"INCIDENT_CLOSED",

user:req.user?.username || "SYSTEM",

note:closureNote.trim(),

time:new Date()

});


incident.changed(
"timeline",
true
);


await incident.save();



res.json({

success:true,

message:"Incident closed",

incident

});


}
catch(error){

res.status(500).json({

error:error.message

});

}

};

exports.acknowledgeIncident =
async(req,res)=>{


try{


const incident =
await Incident.findByPk(
req.params.id
);



if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}



// SECURITY: Closed incidents cannot be acknowledged.
if (incident.status === "CLOSED") {
    return res.status(409).json({
        message: "Closed incidents cannot be acknowledged"
    });
}

incident.status="ACKNOWLEDGED";



incident.timeline =
incident.timeline || [];



incident.timeline.push({

action:
"INCIDENT_ACKNOWLEDGED",


user:
req.user.username,


time:new Date()

});


incident.changed(
"timeline",
true
);


await incident.save();



res.json({

success:true,

message:
"Incident acknowledged",

incident

});


}
catch(error){


res.status(500).json({

error:error.message

});


}


};

// MANUAL CONTAINMENT CONTROLLER - VERIFIED ANALYST REPORT
exports.manualContainIncident = async (req, res) => {

    const description = req.body?.description;
    const verification = req.body?.verification;

    if (
        typeof description !== "string" ||
        !description.trim() ||
        description.length > 5000 ||
        typeof verification !== "string" ||
        !verification.trim() ||
        verification.length > 5000
    ) {
        return res.status(400).json({
            message: "Description and verification are required (maximum 5000 characters each)"
        });
    }

    if (!req.user?.id) {
        return res.status(401).json({
            message: "Authenticated analyst identity required"
        });
    }

    const { sequelize } = require("../config/database");

    let incident;
    let investigation;

    try {

        await sequelize.transaction(async (transaction) => {

            incident = await Incident.findByPk(req.params.id, {
                transaction,
                lock: transaction.LOCK.UPDATE
            });

            if (!incident) {
                const error = new Error("Incident not found");
                error.statusCode = 404;
                throw error;
            }

            if (incident.status !== "INVESTIGATING") {
                const error = new Error(
                    "Manual containment requires an INVESTIGATING incident"
                );
                error.statusCode = 409;
                throw error;
            }

            investigation = await Investigation.create({
                incidentId: incident.id,
                analystId: req.user.id,
                action: "MANUAL_CONTAINMENT",
                description: description.trim(),
                result: verification.trim()
            }, { transaction });

            incident.status = "CONTAINED";

            incident.timeline = [
                ...(Array.isArray(incident.timeline) ? incident.timeline : []),
                {
                    action: "MANUAL_CONTAINMENT_RECORDED",
                    user: req.user.username || "UNKNOWN",
                    analystId: req.user.id,
                    analyst: req.user.username || "UNKNOWN",
                    description: description.trim(),
                    verification: verification.trim(),
                    time: new Date()
                }
            ];

            incident.changed("timeline", true);

            await incident.save({ transaction });

        });

        try {
            await createAuditLog({
                userId: req.user.id,
                username: req.user.username || "UNKNOWN",
                action: "MANUAL_CONTAINMENT_RECORDED",
                module: "INCIDENT_RESPONSE",
                severity: incident.severity,
                ipAddress: req.ip,
                description:
                    `Analyst recorded manual containment for incident ${incident.id}`,
                metadata: {
                    incidentId: incident.id,
                    investigationId: investigation.id,
                    executionType: "MANUAL_REPORTED",
                    automatedActionExecuted: false
                }
            });
        } catch (auditError) {
            console.error(
                "Manual containment audit logging failed:",
                auditError
            );
        }

        return res.json({
            success: true,
            message:
                "Manual containment recorded. No automated firewall action was executed.",
            incident,
            investigation
        });

    } catch (error) {
        console.error("Manual containment failed:", error);

        return res.status(error.statusCode || 500).json({
            message: error.statusCode
                ? error.message
                : "Unable to record manual containment"
        });
    }
};

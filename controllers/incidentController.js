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


const incident =
await Incident.create({

    ...req.body,

    timeline:[
        {
            action:"INCIDENT_CREATED",
            user:req.user?.username || "SYSTEM",
            time:new Date()
        }
    ]

});


const {executePlaybook}
=
require("../services/playbookEngine");










await createAuditLog({

username:req.user?.username || "SYSTEM",

action:"INCIDENT_CREATED",

module:"INCIDENT",

severity:incident.severity,

ipAddress:req.ip,

description:
`Incident created: ${incident.title}`

});


await executePlaybook(incident);




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





incident.timeline = incident.timeline || [];

incident.timeline.push({

action:"INCIDENT_UPDATED",

user:req.user?.username || "SYSTEM",

changes:req.body,

time:new Date()

});


Object.assign(
incident,
req.body
);


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









exports.resolveIncident = async(req,res)=>{


try{


const incident =
await Incident.findByPk(
req.params.id,
{

include:[

{
model:IncidentAssignment,
as:"assignments"
}

]

}
);



if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}




incident.status =
"RESOLVED";


incident.resolutionNote =
req.body.resolutionNote;


incident.resolvedBy =
req.user?.id || null;




incident.timeline = incident.timeline || [];

incident.timeline.push({

    action:"RESOLVED",

    user:req.user?.username || "SYSTEM",

    note:req.body.resolutionNote,

    time:new Date()

});




incident.changed(
"timeline",
true
);


await incident.save();





res.json({

message:"Incident resolved",

incident

});



}
catch(error){


res.status(500).json({

error:error.message

});


}


};

exports.containIncident = async(req,res)=>{


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




const {
action,
target
}=req.body;




incident.status="CONTAINED";



incident.timeline.push({

action:"INCIDENT_CONTAINED",

user:req.user?.username || "SYSTEM",

target,

time:new Date()

});


incident.changed(
"timeline",
true
);


await incident.save();





await ResponseAction.create({

incidentId:incident.id,

action,

target,

performedBy:req.user?.id || null,

status:"SUCCESS",

details:req.body

});






await createAuditLog({

userId:req.user?.id,

username:req.user?.username || "SYSTEM",

action:"INCIDENT_CONTAINED",

module:"INCIDENT_RESPONSE",

severity:incident.severity,

ipAddress:req.ip,

description:
`Incident ${incident.id} contained`,

metadata:{
action,
target
}

});





res.json({

message:"Incident contained",

incident

});



}

catch(error){


res.status(500).json({

error:error.message

});


}


};




// ============================
// CLOSE INCIDENT
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



incident.status="CLOSED";


incident.closedBy =
req.user?.id || null;


incident.closedAt =
new Date();


incident.closureNote =
req.body.closureNote;



incident.timeline =
incident.timeline || [];


incident.timeline.push({

action:"INCIDENT_CLOSED",

user:req.user?.username || "SYSTEM",

note:req.body.closureNote,

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
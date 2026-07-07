const Incident=require("../models/Incident");
const createAuditLog =
require("../utils/auditLogger");



exports.createIncident=async(req,res)=>{


try{


const incident=
await Incident.create(req.body);

await createAuditLog({

username:
req.user?.username || "SYSTEM",

action:
"INCIDENT_CREATED",

module:
"INCIDENT",

severity:
incident.severity || "MEDIUM",

ipAddress:
req.ip,

description:
`Incident created: ${incident.title}`,

metadata:{
incidentId:incident.id,
attackType:incident.attackType
}

});


res.json({

message:"Incident Created",

incident

});


}

catch(error){


res.status(500)
.json({

error:error.message

});


}


};





exports.getIncidents=async(req,res)=>{


const incidents=
await Incident.findAll({

order:[
["createdAt","DESC"]
]

});


res.json(incidents);


};





exports.updateIncident=async(req,res)=>{


const {
id
}=req.params;



await Incident.update(

req.body,

{
where:{
id
}
}

);


await createAuditLog({

username:
req.user?.username || "SYSTEM",

action:
"INCIDENT_UPDATED",

module:
"INCIDENT",

severity:
"LOW",

ipAddress:
req.ip,

description:
`Incident ${id} updated`,

metadata:req.body

});


res.json({

message:
"Incident Updated"

});


};
const AuditLog =
require("../models/AuditLog");



async function createAuditLog(data){


try{


await AuditLog.create({

userId:data.userId || null,

username:data.username || "SYSTEM",

action:data.action,

module:data.module || "SYSTEM",

severity:data.severity || "LOW",

ipAddress:data.ipAddress || "UNKNOWN",

description:data.description,

metadata:data.metadata || {}

});


}

catch(error){


console.log(
"Audit Logging Failed:",
error.message
);


}


}



module.exports=createAuditLog;
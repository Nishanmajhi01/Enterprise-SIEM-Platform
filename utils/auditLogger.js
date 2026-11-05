const AuditLog =
require("../models/AuditLog");



async function createAuditLog(data){


try{


if (
    !data ||
    typeof data.workspaceId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        data.workspaceId
    )
) {
    throw new Error("Valid workspaceId required for audit logging");
}

await AuditLog.create({

workspaceId:data.workspaceId,

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
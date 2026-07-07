function normalizeEvent(event){


let normalized={

eventType:"UNKNOWN",

sourceIP:event.sourceIP || event.ip || "unknown",

username:event.username || "unknown",

timestamp:new Date(),

severity:"LOW",

description:""

};



if(event.failedLogin){

normalized.eventType="LOGIN_FAILURE";

normalized.severity="MEDIUM";

normalized.description=
"Failed login attempt detected";

}



if(event.url){

normalized.eventType="URL_ACCESS";

normalized.description=
"URL activity detected";

}



if(event.fileHash){

normalized.eventType="FILE_SCAN";

normalized.description=
"File hash submitted for malware analysis";

}



if(event.requests){

normalized.eventType="NETWORK_TRAFFIC";

normalized.description=
"High network request activity";

}



return normalized;


}



module.exports=normalizeEvent;
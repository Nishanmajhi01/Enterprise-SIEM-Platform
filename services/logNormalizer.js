module.exports=(log,device)=>{


return {


deviceId:device.id,

deviceType:device.type,

sourceIP:
log.sourceIP ||
device.ipAddress,


eventType:
log.eventType || "UNKNOWN",


username:
log.username || null,


severity:
log.severity || "LOW",


message:
log.message || "",


raw:log,


timestamp:new Date()


};


};
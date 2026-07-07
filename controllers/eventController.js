const SecurityEvent=require("../models/SecurityEvent");

const detectBruteForce=
require("../detection/bruteForce");



exports.createEvent=async(req,res)=>{


try{


const event=
await SecurityEvent.create(req.body);

const {
sendAlert
}=require("../websocket/socket");

await detectBruteForce(event);

sendAlert({

type:"SECURITY_EVENT",

message:"Suspicious activity detected",

ip:event.sourceIP

});



res.json({

message:
"Security event stored",

event

});


}

catch(error){


res.status(500)
.json({

error:error.message

});


}


};
const Alert=require("../models/Alert");


let traffic={};



async function detectDDoS(ip){


if(!traffic[ip]){

traffic[ip]=[];

}



traffic[ip].push(Date.now());



let requests =
traffic[ip].filter(

time =>
Date.now()-time <60000

);



if(requests.length>100){


await Alert.create({

attackType:
"DDOS",

sourceIP:
ip,

riskLevel:
"CRITICAL",

message:
"Possible DDoS traffic detected"

});


traffic[ip]=[];

}


}



module.exports=detectDDoS;
function analyseEvents(events){


let result={

threatDetected:false,

attackType:null,

severity:"LOW",

score:0,

reason:[]

};



// Brute Force Detection

const failedLogins = events.filter(

event =>
event.eventType==="LOGIN_FAILURE"

);



if(failedLogins.length >= 5){


result.threatDetected=true;

result.attackType="BRUTE_FORCE";

result.score+=40;

result.reason.push(
"Multiple failed login attempts detected"
);


}



// Malware Detection

const malwareEvents = events.filter(

event =>
event.eventType==="FILE_SCAN" &&
event.malware===true

);



if(malwareEvents.length>0){


result.threatDetected=true;

result.attackType="MALWARE";

result.score+=60;


result.reason.push(
"Malware indicator detected"
);


}



// DDoS Detection

const networkEvents = events.filter(

event =>
event.eventType==="NETWORK_TRAFFIC"

);



if(networkEvents.length>=100){


result.threatDetected=true;

result.attackType="DDOS";

result.score+=70;


result.reason.push(
"High traffic volume detected"
);


}



// Risk Calculation


if(result.score>=80){

result.severity="CRITICAL";

}

else if(result.score>=50){

result.severity="HIGH";

}

else if(result.score>=30){

result.severity="MEDIUM";

}


if(events.some(event=>event.ipReputation==="BAD")){


result.score+=30;


result.reason.push(
"Malicious IP reputation detected"
);


}



return result;


}



module.exports=analyseEvents;
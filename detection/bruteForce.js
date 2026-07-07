const Alert=require("../models/Alert");


let attempts={};



async function detectBruteForce(event){


const ip=event.sourceIP;



if(!attempts[ip]){

attempts[ip]=[];

}


attempts[ip].push(Date.now());



const recentAttempts=
attempts[ip]
.filter(
time =>
Date.now()-time <120000
);



if(recentAttempts.length>=5){


await Alert.create({

attackType:"BRUTE_FORCE",

sourceIP:ip,

riskLevel:"HIGH",

message:
"Multiple failed login attempts detected"

});


console.log(
"BRUTE FORCE DETECTED",
ip
);



attempts[ip]=[];

}


}



module.exports=detectBruteForce;
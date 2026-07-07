function calculateRisk(type){

let risk="LOW";


switch(type){

case "BRUTE_FORCE":
risk="HIGH";
break;


case "MALWARE":
risk="CRITICAL";
break;


case "PHISHING":
risk="HIGH";
break;


case "DDOS":
risk="CRITICAL";
break;


default:
risk="LOW";

}


return risk;

}


module.exports=calculateRisk;
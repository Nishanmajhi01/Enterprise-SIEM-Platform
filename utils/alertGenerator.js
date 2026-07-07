const getMitreTechnique =
require("./mitreMapping");



function generateAlert(correlation,event){



const mitre =
getMitreTechnique(
correlation.attackType
);



let recommendation;



switch(correlation.attackType){


case "BRUTE_FORCE":

recommendation=
"Block source IP and investigate compromised accounts";

break;



case "MALWARE":

recommendation=
"Isolate infected system and perform malware analysis";

break;



case "PHISHING":

recommendation=
"Block malicious URL and warn users";

break;



case "DDOS":

recommendation=
"Enable traffic filtering and investigate source traffic";

break;



default:

recommendation=
"Investigate security event";


}




return {


alertID:
"ALERT-"+Date.now(),



title:

`${mitre.name} Detected`,



attackType:
correlation.attackType,



mitre:{


id:
mitre.technique,


technique:
mitre.name,


tactic:
mitre.tactic


},



severity:
correlation.severity,



riskScore:
correlation.score,



evidence:
correlation.reason,



sourceIP:
event.sourceIP,



description:
mitre.description,



recommendation,



status:
"OPEN",



createdAt:
new Date()


};



}



module.exports=generateAlert;
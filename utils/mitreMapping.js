const mitreRules={


BRUTE_FORCE:{

technique:"T1110",

name:"Brute Force",

tactic:"Credential Access",

description:
"Attackers attempt multiple passwords to gain unauthorized access."

},



PHISHING:{

technique:"T1566",

name:"Phishing",

tactic:"Initial Access",

description:
"Attackers use fake websites or messages to steal information."

},



MALWARE:{

technique:"T1204",

name:"User Execution",

tactic:"Execution",

description:
"Malicious files are executed by users or systems."

},



DDOS:{

technique:"T1498",

name:"Network Denial of Service",

tactic:"Impact",

description:
"Attackers overload services with excessive traffic."

}


};



function getMitreTechnique(type){


return mitreRules[type] || {


technique:"UNKNOWN",

name:"Unknown",

tactic:"Unknown",

description:
"No MITRE technique mapped"


};


}



module.exports=getMitreTechnique;
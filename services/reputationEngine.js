function analyzeVirusTotal(data){


const stats =
data.data.attributes.last_analysis_stats;


const malicious =
stats.malicious || 0;


const suspicious =
stats.suspicious || 0;


let reputation="SAFE";

let severity="LOW";


let riskScore=0;



if(malicious > 50){

    reputation="MALICIOUS";

    severity="CRITICAL";

    riskScore=95;


}

else if(malicious > 10){


    reputation="SUSPICIOUS";

    severity="HIGH";

    riskScore=75;


}

else if(malicious > 0){


    reputation="UNKNOWN";

    severity="MEDIUM";

    riskScore=40;


}



return {


reputation,


severity,


riskScore,


detections:{

malicious,

suspicious

},


recommendation:

riskScore >=90

?

"Immediately isolate affected system and block indicator"

:

"Monitor and investigate"


};



}



module.exports={
analyzeVirusTotal
};
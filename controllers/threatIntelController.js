const { checkFileHash } =
require("../services/virusTotalService");

const {
mapThreat
}
=
require("../services/mitreMapper");


const {
analyzeVirusTotal
}
=
require("../services/reputationEngine");



exports.scanHash = async(req,res)=>{


try{


const {
hash
}
=
req.params;



const result =
await checkFileHash(hash);



if(!result.data){


return res.status(400).json({

message:"Unable to analyse hash",

result

});


}



const analysis =
analyzeVirusTotal(result);

const mitre =
mapThreat(
result.data.attributes.type_description
);

const {
calculateRisk
}
=
require("../services/riskEngine");

const risk =
calculateRisk({

maliciousCount:
analysis.detections.malicious,

severity:
analysis.severity,

assetCriticality:"HIGH"

});


res.json({

hash,

threatIntelligence: analysis,

mitre,

risk

});




}


catch(error){


res.status(500).json({

message:"Threat analysis failed",

error:error.message

});


}



};
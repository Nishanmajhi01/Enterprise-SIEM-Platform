const detectPhishing=
require("../detection/phishing");


const detectMalware=
require("../detection/malware");


const detectDDoS=
require("../detection/ddos");



exports.analyseThreat=async(req,res)=>{


const {
type,
data
}=req.body;



let result;



switch(type){


case "URL":

result=
await detectPhishing(data, req.workspaceId);

break;



case "HASH":

result=
await detectMalware(data, req.workspaceId);

break;



case "TRAFFIC":

result=
await detectDDoS(data, req.workspaceId);

break;



}



res.json({

analysisCompleted:true,

result

});


};
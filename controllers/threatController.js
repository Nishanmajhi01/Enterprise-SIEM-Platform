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
await detectPhishing(data);

break;



case "HASH":

result=
await detectMalware(data);

break;



case "TRAFFIC":

result=
await detectDDoS(data);

break;



}



res.json({

analysisCompleted:true,

result

});


};
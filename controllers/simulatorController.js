const normalizeEvent =
require("../utils/eventNormalizer");


const analyseEvents =
require("../utils/correlationEngine");


const generateAlert =
require("../utils/alertGenerator");



const simulateBruteForce =
require("../simulator/bruteForceSimulator");


const simulatePhishing =
require("../simulator/phishingSimulator");


const simulateMalware =
require("../simulator/malwareSimulator");


const simulateDDoS =
require("../simulator/ddosSimulator");

const Incident = require("../models/Incident");



exports.runSimulation = async(req,res)=>{


let events=[];



switch(req.params.type){


case "bruteforce":

events=simulateBruteForce();

break;



case "phishing":

events=simulatePhishing();

break;



case "malware":

events=simulateMalware();

break;



case "ddos":

events=simulateDDoS();

break;



default:

return res.status(400).json({

message:"Invalid simulation type"

});


}



const normalized =
events.map(normalizeEvent);



const analysis =
analyseEvents(normalized);



const alert =
generateAlert(

analysis,

normalized[0]

);

let incident = null;


if(analysis.threatDetected){


incident = await Incident.create({

title: alert.title,

attackType: alert.attackType,

mitreTechnique: alert.mitre.id,

tactic: alert.mitre.tactic,

severity: alert.severity,

riskScore: alert.riskScore,

sourceIP: alert.sourceIP,

evidence: alert.evidence,

description: alert.description,

recommendation: alert.recommendation,

status:"OPEN"


});


}


res.json({

eventsGenerated:
events.length,

analysis,

alert,

incident


});

};
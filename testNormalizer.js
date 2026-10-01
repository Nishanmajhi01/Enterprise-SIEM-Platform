const normalizeEvent=
require("./utils/eventNormalizer");


const { mapThreat: getMitreTechnique }=
require("./services/mitreMapper");



const event={

failedLogin:true,

sourceIP:"192.168.1.50"

};



const result=
normalizeEvent(event);



const mitre=
getMitreTechnique(
result.eventType
);



console.log({

event:result,

mitre

});
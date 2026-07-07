const normalizeEvent =
require("./utils/eventNormalizer");


const analyseEvents =
require("./utils/correlationEngine");


const generateAlert =
require("./utils/alertGenerator");



let rawEvents=[

{
failedLogin:true,
sourceIP:"10.0.0.5"
},

{
failedLogin:true,
sourceIP:"10.0.0.5"
},

{
failedLogin:true,
sourceIP:"10.0.0.5"
},

{
failedLogin:true,
sourceIP:"10.0.0.5"
},

{
failedLogin:true,
sourceIP:"10.0.0.5"
}

];



let events =
rawEvents.map(normalizeEvent);



let analysis =
analyseEvents(events);



let alert =
generateAlert(
analysis,
events[0]
);



console.log(alert);
const analyseEvents =
require("./utils/correlationEngine");



const events=[

{
eventType:"LOGIN_FAILURE",
sourceIP:"192.168.1.20"
},

{
eventType:"LOGIN_FAILURE",
sourceIP:"192.168.1.20"
},

{
eventType:"LOGIN_FAILURE",
sourceIP:"192.168.1.20"
},

{
eventType:"LOGIN_FAILURE",
sourceIP:"192.168.1.20"
},

{
eventType:"LOGIN_FAILURE",
sourceIP:"192.168.1.20"
}

];



console.log(
analyseEvents(events)
);
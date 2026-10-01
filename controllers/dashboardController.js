const { Op } = require("sequelize");


const IOC =
require("../models/IOC");


const Incident =
require("../models/Incident");


const SecurityEvent =
require("../models/SecurityEvent");


const ThreatIntel =
require("../models/ThreatIntel");





exports.getDashboardStats = async(req,res)=>{


try{


const totalIOCs =
await IOC.count();



const maliciousIOCs =
await IOC.count({

where:{
reputation:"MALICIOUS"
}

});




const totalThreats =
await ThreatIntel.count();




const criticalThreats =
await ThreatIntel.count({

where:{
severity:"CRITICAL"
}

});




const highThreats =
await ThreatIntel.count({

where:{
severity:"HIGH"
}

});




const totalIncidents =
await Incident.count();




const openIncidents =
await Incident.count({

where:{
status:"OPEN"
}

});




const highRiskEvents =
await SecurityEvent.count({

where:{

riskScore:{
[Op.gte]:70
}

}

});





const topAttackers =
await SecurityEvent.findAll({

attributes:[

"sourceIP",

[
SecurityEvent.sequelize.fn(
"COUNT",
SecurityEvent.sequelize.col("sourceIP")
),

"count"

]

],

group:["sourceIP"],

order:[

[
"count",
"DESC"
]

],

limit:5

});







const attackTypes =
await SecurityEvent.findAll({

attributes:[

"attackType",

[
SecurityEvent.sequelize.fn(
"COUNT",
SecurityEvent.sequelize.col("attackType")
),

"count"

]

],

group:["attackType"]

});






res.json({

systemStatus:"ACTIVE",


threatIntelligence:{


totalThreats,

criticalThreats,

highThreats


},



ioc:{


totalIOCs,

maliciousIOCs


},



incidents:{


totalIncidents,

openIncidents


},



highRiskEvents,


topAttackers,


attackTypes



});



}

catch(error){


res.status(500).json({

error:error.message

});


}


};
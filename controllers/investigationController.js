const Investigation =
require("../models/Investigation");


const Incident =
require("../models/Incident");



exports.addInvestigationNote =
async(req,res)=>{


try{


const incident =
await Incident.findByPk(
req.params.id
);



if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}




const investigation =
await Investigation.create({

incidentId:
incident.id,


analystId:
req.user.id,


action:
"INVESTIGATION_NOTE",


description:
req.body.description,


result:
req.body.result || null


});





incident.status="INVESTIGATING";



incident.timeline =
incident.timeline || [];



incident.timeline.push({

action:
"INVESTIGATION_UPDATED",


analyst:
req.user.username,


description:
req.body.description,


time:new Date()

});




await incident.save();





res.json({

success:true,

message:
"Investigation note added",

investigation,

incident


});



}
catch(error){


res.status(500).json({

error:error.message

});


}


};
const Investigation =
require("../models/Investigation");


const Incident =
require("../models/Incident");



exports.addInvestigationNote =
async(req,res)=>{


try{


const incident =
await Incident.findOne({
    where: {
        id: req.params.id,
        workspaceId: req.workspaceId
    }
});



if(!incident){

return res.status(404).json({

message:"Incident not found"

});

}




// SECURITY: Validate investigation notes and protect closed incidents.
if (incident.status === "CLOSED") {
    return res.status(409).json({
        message: "Closed incidents cannot be modified"
    });
}

const description = req.body?.description;

if (
    typeof description !== "string" ||
    !description.trim() ||
    description.length > 5000
) {
    return res.status(400).json({
        message: "Investigation description must contain 1-5000 characters"
    });
}

const investigation =
await Investigation.create({

workspaceId: req.workspaceId,

incidentId:
incident.id,


analystId:
req.user.id,


action:
"INVESTIGATION_NOTE",


description:
description.trim(),


result:
req.body.result || null


});





// Preserve the current incident lifecycle status.



incident.timeline =
incident.timeline || [];



incident.timeline.push({

action:
"INVESTIGATION_UPDATED",


analyst:
req.user.username,


description:
description.trim(),


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
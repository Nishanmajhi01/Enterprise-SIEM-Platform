const IncidentComment =
require("../models/IncidentComment");



exports.addComment = async(req,res)=>{


try{


const comment =
await IncidentComment.create({

incidentId:req.params.id,

username:
req.user?.username || "SOC_ANALYST",

comment:req.body.comment

});



res.json({

success:true,

comment

});


}
catch(error){


res.status(500).json({

error:error.message

});


}


};
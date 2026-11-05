const Device = require("../models/Device");
const Workspace = require("../models/Workspace");


module.exports = async(req,res,next)=>{

try{


const apiKey=req.headers["x-api-key"];


if(!apiKey){

return res.status(401).json({

error:"Missing Device API Key"

});

}



const device=await Device.findOne({

where:{
apiKey
}

});



if(!device){

return res.status(403).json({

error:"Unauthorized Device"

});

}



if(device.status !== "ACTIVE"){

return res.status(403).json({

error:"Device Disabled"

});

}







// Validate workspace ownership using the authenticated device.
if (!device.workspaceId) {
    return res.status(403).json({
        error: "Device has no workspace assigned"
    });
}

const workspace = await Workspace.findByPk(device.workspaceId);

if (!workspace || workspace.status !== "ACTIVE") {
    return res.status(403).json({
        error: "Device workspace is inactive or unavailable"
    });
}

// Never trust a workspace ID supplied by the device.
req.workspaceId = workspace.id;
req.workspace = workspace;
req.device = device;

// Update heartbeat only after workspace verification.
await device.update({
    lastHeartbeat: new Date()
});

next();



}

catch(error){

res.status(500).json({

error:"Device authentication failed"

});

}


};
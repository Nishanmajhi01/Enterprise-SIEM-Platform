const Device = require("../models/Device");


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



await device.update({

lastHeartbeat:new Date()

});



req.device=device;


next();



}

catch(error){

res.status(500).json({

error:error.message

});

}


};
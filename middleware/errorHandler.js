const logger=require("../utils/logger");


const errorHandler=(err,req,res,next)=>{


logger.error({

message:err.message,

url:req.originalUrl,

method:req.method

});



res.status(500).json({

message:"Internal Server Error"

});


};


module.exports=errorHandler;
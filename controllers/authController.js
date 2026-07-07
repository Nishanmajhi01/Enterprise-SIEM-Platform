const bcrypt=require("bcrypt");

const User=require("../models/User");

const generateToken=require("../utils/jwt");

const createAuditLog =
require("../utils/auditLogger");



exports.register=async(req,res)=>{


try{


const {
username,
email,
password
}=req.body;



const hashedPassword=
await bcrypt.hash(password,10);



const user=
await User.create({

username,

email,

password:hashedPassword

});

await createAuditLog({

username,

action:"USER_REGISTER",

module:"AUTH",

severity:"LOW",

ipAddress:req.ip,

description:
"New user registered in SIEM platform"

});



res.json({

message:"User Created",

user

});



}catch(error){


res.status(500)
.json({

error:error.message

});


}



};





exports.login=async(req,res)=>{


try{


const {
email,
password
}=req.body;



const user=
await User.findOne({

where:{
email
}

});



if(!user){


await createAuditLog({

username:email,

action:"LOGIN_FAILED",

module:"AUTH",

severity:"MEDIUM",

ipAddress:req.ip,

description:
"Login failed - User not found"

});



return res.status(404)
.json({

message:"User not found"

});


}



const valid=
await bcrypt.compare(
password,
user.password
);



if(!valid){


await createAuditLog({

username:user.username,

action:"LOGIN_FAILED",

module:"AUTH",

severity:"MEDIUM",

ipAddress:req.ip,

description:
"Login failed - Incorrect password"

});



return res.status(401)
.json({

message:"Invalid password"

});


}



const token=
generateToken(user);

await createAuditLog({

username:user.username,

action:"LOGIN_SUCCESS",

module:"AUTH",

severity:"LOW",

ipAddress:req.ip,

description:
"User successfully logged into SIEM platform"

});



res.json({

message:"Login Successful",

token

});



}catch(error){

res.status(500)
.json({

error:error.message

});

}


};
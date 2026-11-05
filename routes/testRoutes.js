const express = require("express");
const router = express.Router();

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");

const detectBruteForce =
require("../detection/bruteForce");


router.get(
    "/bruteforce",
    authenticate,
    workspaceAuth,
    workspaceRbac("ADMIN", "ANALYST"),
    async(req,res)=>{


const event = {

workspaceId: req.workspaceId,

sourceIP:"192.168.1.100",

attackType:"FAILED_LOGIN"

};


for(let i=0;i<5;i++){

await detectBruteForce(event);

}


res.json({

message:"Brute force simulation completed"

});


});


module.exports = router;
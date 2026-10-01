const express = require("express");
const router = express.Router();

const detectBruteForce =
require("../detection/bruteForce");


router.get("/bruteforce", async(req,res)=>{


const event = {

sourceIP:"192.168.1.100",

attackType:"BRUTE_FORCE"

};


for(let i=0;i<5;i++){

await detectBruteForce(event);

}


res.json({

message:"Brute force simulation completed"

});


});


module.exports = router;
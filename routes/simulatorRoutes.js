const express=require("express");

const router=express.Router();


const {
runSimulation
}=require("../controllers/simulatorController");



router.post(

"/:type",

runSimulation

);



module.exports=router;
const express=require("express");

const router=express.Router();

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");


const {
runSimulation
}=require("../controllers/simulatorController");



router.post(

"/:type",

authenticate,
workspaceAuth,
runSimulation

);



module.exports=router;
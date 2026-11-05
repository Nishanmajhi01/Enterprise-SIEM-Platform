const express=require("express");

const router=express.Router();

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");




const {
createEvent
}=require("../controllers/eventController");



router.post(
"/",
authenticate,
workspaceAuth,
createEvent
);



module.exports=router;
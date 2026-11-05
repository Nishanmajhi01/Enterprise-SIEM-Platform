const express=require("express");

const router=express.Router();

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");


const {
analyseThreat
}=require("../controllers/threatController");



router.post(
"/analyse",
authenticate,
workspaceAuth,
workspaceRbac("ADMIN", "ANALYST"),
analyseThreat
);



module.exports=router;
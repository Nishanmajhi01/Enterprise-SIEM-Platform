const express=require("express");

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");



const router=express.Router();


const {

createAuditLog,

getAuditLogs

}=require("../controllers/auditController");



router.post(
"/",
authenticate,
workspaceAuth,
workspaceRbac(["ADMIN"]),
createAuditLog
);



router.get(
"/",
authenticate,
workspaceAuth,
workspaceRbac(["ADMIN"]),
getAuditLogs
);



module.exports=router;
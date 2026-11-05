const express = require("express");

const router = express.Router();

const authenticate =
require("../middleware/authMiddleware");

const workspaceAuth =
require("../middleware/workspaceAuth");

const workspaceRbac =
require("../middleware/workspaceRbac");


const {
    scanHash,
    getThreatIntel
} = require("../controllers/threatIntelController");



/*
    GET ALL THREAT INTELLIGENCE
    Used by SOC Dashboard Threat Cards
*/
router.get(
    "/",
    authenticate,
    workspaceAuth,
    workspaceRbac("ADMIN", "ANALYST", "VIEWER"),
    getThreatIntel
);



/*
    VIRUSTOTAL HASH SCANNER
    Example:
    /api/threat-intel/hash/abc123hash
*/
router.get(
    "/hash/:hash",
    authenticate,
    workspaceAuth,
    workspaceRbac("ADMIN", "ANALYST"),
    scanHash
);



module.exports = router;
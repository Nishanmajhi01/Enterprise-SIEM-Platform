const express = require("express");

const router = express.Router();

const authenticate =
require("../middleware/authMiddleware");


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
    scanHash
);



module.exports = router;
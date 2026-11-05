const express = require("express");

const router = express.Router();


const {

    getAlerts,

    getAlertById,

    createAlert,

    updateAlertStatus,

    assignAlert,

    resolveAlert


} = require("../controllers/alertController");



const authenticate =
require("../middleware/authMiddleware");



const workspaceAuth =
require("../middleware/workspaceAuth");

const workspaceRbac =
require("../middleware/workspaceRbac");





// =====================================
// GET ALL ALERTS
// ADMIN + ANALYST + VIEWER
// =====================================

router.get(

    "/",

    authenticate,

    workspaceAuth,

    workspaceRbac([
        "ADMIN",
        "ANALYST",
        "VIEWER"
    ]),

    getAlerts

);







// =====================================
// CREATE ALERT
// Used by SIEM engines
// ADMIN + ANALYST
// =====================================

router.post(

    "/",

    authenticate,

    workspaceAuth,

    workspaceRbac([
        "ADMIN",
        "ANALYST"
    ]),

    createAlert

);








// =====================================
// GET SINGLE ALERT
// =====================================

router.get(

    "/:id",

    authenticate,

    workspaceAuth,

    workspaceRbac([
        "ADMIN",
        "ANALYST",
        "VIEWER"
    ]),

    getAlertById

);








// =====================================
// UPDATE ALERT STATUS
// =====================================

router.patch(

    "/:id/status",

    authenticate,

    workspaceAuth,

    workspaceRbac([
        "ADMIN",
        "ANALYST"
    ]),

    updateAlertStatus

);








// =====================================
// ASSIGN ALERT
// =====================================

router.patch(

    "/:id/assign",

    authenticate,

    workspaceAuth,

    workspaceRbac([
        "ADMIN",
        "ANALYST"
    ]),

    assignAlert

);








// =====================================
// RESOLVE ALERT
// =====================================

router.patch(

    "/:id/resolve",

    authenticate,

    workspaceAuth,

    workspaceRbac([
        "ADMIN",
        "ANALYST"
    ]),

    resolveAlert

);





module.exports = router;
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



const rbac =
require("../middleware/rbac");





// =====================================
// GET ALL ALERTS
// ADMIN + ANALYST + VIEWER
// =====================================

router.get(

    "/",

    authenticate,

    rbac([
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

    rbac([
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

    rbac([
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

    rbac([
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

    rbac([
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

    rbac([
        "ADMIN",
        "ANALYST"
    ]),

    resolveAlert

);





module.exports = router;
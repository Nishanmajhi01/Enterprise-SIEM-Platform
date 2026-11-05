const express = require("express");
const commentController =
require("../controllers/commentController");

const router = express.Router();


const {

createIncident,

getIncidents,

getIncidentById,

containIncident,

updateIncident,

assignIncident,

getAssignments,

resolveIncident,

closeIncident

}
=
require("../controllers/incidentController");

const {
addInvestigationNote
}
=
require("../controllers/investigationController");

const {

acknowledgeIncident

}
=
require("../controllers/incidentController");



const authenticate =
require("../middleware/authMiddleware");


const rbac =
require("../middleware/workspaceRbac");

const workspaceAuth =
require("../middleware/workspaceAuth");






// CREATE INCIDENT

router.post(
"/",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST"
]),
createIncident
);







// GET ALL INCIDENTS

router.get(
"/",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST",
"VIEWER"
]),
getIncidents
);







// GET SINGLE INCIDENT

router.get(
"/:id",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST",
"VIEWER"
]),
getIncidentById
);


router.patch(
"/:id/contain",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST"
]),
containIncident
);









// UPDATE INCIDENT

router.put(
"/:id",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST"
]),
updateIncident
);








// ASSIGN INCIDENT

router.patch(
"/:id/assign",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST"
]),
assignIncident
);


router.get(
"/:id/assignments",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST",
"VIEWER"
]),
getAssignments
);








// RESOLVE INCIDENT

router.patch(
"/:id/resolve",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST"
]),
resolveIncident
);



router.post(
"/:id/comments",
authenticate,
workspaceAuth,
rbac(["ADMIN", "ANALYST"]),
commentController.addComment
);


router.patch(
"/:id/close",
authenticate,
workspaceAuth,
rbac([
"ADMIN",
"ANALYST"
]),
closeIncident
);

router.post(

"/:id/investigation",

authenticate,
workspaceAuth,

rbac([
"ADMIN",
"ANALYST"
]),

addInvestigationNote

);


router.patch(

"/:id/acknowledge",

authenticate,
workspaceAuth,

rbac([
"ADMIN",
"ANALYST"
]),

acknowledgeIncident

);





// MANUAL CONTAINMENT - ANALYST-REPORTED VERIFICATION
router.patch(
    "/:id/manual-contain",
    authenticate,
workspaceAuth,
    rbac(["ADMIN", "ANALYST"]),
    require("../controllers/incidentController").manualContainIncident
);

module.exports = router;
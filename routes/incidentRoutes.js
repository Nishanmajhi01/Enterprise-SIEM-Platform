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
require("../middleware/rbac");






// CREATE INCIDENT

router.post(
"/",
authenticate,
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
rbac([
"ADMIN",
"ANALYST"
]),
assignIncident
);


router.get(
"/:id/assignments",
authenticate,
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
rbac([
"ADMIN",
"ANALYST"
]),
resolveIncident
);



router.post(
"/:id/comments",
commentController.addComment
);


router.patch(
"/:id/close",
authenticate,
rbac([
"ADMIN",
"ANALYST"
]),
closeIncident
);

router.post(

"/:id/investigation",

authenticate,

rbac([
"ADMIN",
"ANALYST"
]),

addInvestigationNote

);


router.patch(

"/:id/acknowledge",

authenticate,

rbac([
"ADMIN",
"ANALYST"
]),

acknowledgeIncident

);




module.exports = router;
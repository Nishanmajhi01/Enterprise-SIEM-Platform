const express=require("express");

const router=express.Router();


const {

createIncident,
getIncidents,
updateIncident

}=require("../controllers/incidentController");


const authenticate =
require("../middleware/authMiddleware");



// Create Incident
router.post(
"/",
authenticate,
createIncident
);



// Get All Incidents
router.get(
"/",
authenticate,
getIncidents
);



// Update Incident
router.put(
"/:id",
authenticate,
updateIncident
);



module.exports=router;
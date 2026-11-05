const express = require("express");

const router = express.Router();


const playbookController= require("../controllers/playbookController");

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");


router.post(
    "/",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST"]),
    playbookController.createPlaybook
);


router.get(
"/",
authenticate,
workspaceAuth,
workspaceRbac(["ADMIN", "ANALYST", "VIEWER"]),
playbookController.getPlaybooks
);


router.put(
    "/:id",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST"]),
    playbookController.updatePlaybook
);


router.patch(
    "/:id/toggle",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST"]),
    playbookController.togglePlaybook
);

module.exports = router;

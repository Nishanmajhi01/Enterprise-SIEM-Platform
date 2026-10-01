const express = require("express");

const router = express.Router();


const playbookController= require("../controllers/playbookController");

const authenticate = require("../middleware/authMiddleware");
const rbac = require("../middleware/rbac");


router.post(
    "/",
    authenticate,
    rbac(["ADMIN", "ANALYST"]),
    playbookController.createPlaybook
);


router.get(
"/",
authenticate,
rbac(["ADMIN", "ANALYST", "VIEWER"]),
playbookController.getPlaybooks
);


router.put(
    "/:id",
    authenticate,
    rbac(["ADMIN", "ANALYST"]),
    playbookController.updatePlaybook
);


router.patch(
    "/:id/toggle",
    authenticate,
    rbac(["ADMIN", "ANALYST"]),
    playbookController.togglePlaybook
);

module.exports = router;

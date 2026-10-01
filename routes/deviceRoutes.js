const express = require("express");

const router = express.Router();

const deviceController = require("../controllers/deviceController");

const authenticate = require("../middleware/authMiddleware");
const rbac = require("../middleware/rbac");


// Registering a device issues an API key — ADMIN only
router.post(
    "/",
    authenticate,
    rbac(["ADMIN"]),
    deviceController.registerDevice
);

router.get(
    "/",
    authenticate,
    rbac(["ADMIN", "ANALYST", "VIEWER"]),
    deviceController.getDevices
);

router.patch(
    "/:id/status",
    authenticate,
    rbac(["ADMIN"]),
    deviceController.updateDeviceStatus
);

router.patch(
    "/:id/regenerate-key",
    authenticate,
    rbac(["ADMIN"]),
    deviceController.regenerateApiKey
);

router.delete(
    "/:id",
    authenticate,
    rbac(["ADMIN"]),
    deviceController.deleteDevice
);

module.exports = router;

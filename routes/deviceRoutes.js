"use strict";

const express = require("express");
const router = express.Router();

const deviceController =
    require("../controllers/deviceController");

const authenticate =
    require("../middleware/authMiddleware");

const workspaceAuth =
    require("../middleware/workspaceAuth");

const workspaceRbac =
    require("../middleware/workspaceRbac");

router.use(authenticate);
router.use(workspaceAuth);

// Register device: ADMIN only
router.post(
    "/",
    workspaceRbac("ADMIN"),
    deviceController.registerDevice
);

// List devices: all workspace roles
router.get(
    "/",
    workspaceRbac("ADMIN", "ANALYST", "VIEWER"),
    deviceController.getDevices
);

// Update status: ADMIN only
router.patch(
    "/:id/status",
    workspaceRbac("ADMIN"),
    deviceController.updateDeviceStatus
);

// Regenerate API key: ADMIN only
router.patch(
    "/:id/regenerate-key",
    workspaceRbac("ADMIN"),
    deviceController.regenerateApiKey
);

// Delete device: ADMIN only
router.delete(
    "/:id",
    workspaceRbac("ADMIN"),
    deviceController.deleteDevice
);

module.exports = router;

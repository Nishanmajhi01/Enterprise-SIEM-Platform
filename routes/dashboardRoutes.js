const express = require("express");
const router = express.Router();

const { getDashboardStats } = require("../controllers/dashboardController");
const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");

router.get(
  "/",
  authenticate,
  workspaceAuth,
  workspaceRbac("ADMIN", "ANALYST", "VIEWER"),
  getDashboardStats
);

module.exports = router;

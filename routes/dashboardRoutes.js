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

router.get("/report/pdf", authenticate, workspaceAuth, workspaceRbac("ADMIN", "ANALYST"), require("../controllers/reportController").downloadReport);

module.exports = router;

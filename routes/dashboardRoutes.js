const express = require("express");
const router = express.Router();

const { getDashboardStats } = require("../controllers/dashboardController");

const authenticate = require("../middleware/authMiddleware");
const rbac = require("../middleware/rbac");

router.get(
    "/",
    authenticate,
    rbac(["ADMIN", "ANALYST", "VIEWER"]),
    getDashboardStats
);

module.exports = router;
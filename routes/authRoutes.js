const express = require("express");

const router = express.Router();

const authenticate = require("../middleware/authMiddleware");
const rbac = require("../middleware/rbac");

const {
    register,
    login
} = require("../controllers/authController");

/*
 * User registration:
 * Only authenticated administrators can create accounts.
 */
router.post(
    "/register",
    authenticate,
    rbac(["ADMIN"]),
    register
);

/*
 * Login remains publicly accessible.
 */
router.post(
    "/login",
    login
);

module.exports = router;

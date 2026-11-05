const express = require("express");
const router = express.Router();

const {
    createIOC,
    getIOCs,
    searchIOCs,
    getIOCById,
    updateIOC,
    deleteIOC
} = require("../controllers/iocController");

const authenticate = require("../middleware/authMiddleware");
const { validateIOC } = require("../middleware/iocValidator");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");

/**
 * CREATE IOC
 * Only ADMIN + ANALYST
 */
router.post(
    "/",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST"]),
    validateIOC,
    createIOC
);

/**
 * GET ALL IOC
 * ADMIN + ANALYST + VIEWER
 */
router.get(
    "/",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST", "VIEWER"]),
    getIOCs
);

/**
 * SEARCH IOC
 * ADMIN + ANALYST + VIEWER
 * Must be registered before /:id
 */
router.get(
    "/search",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST", "VIEWER"]),
    searchIOCs
);

/**
 * GET SINGLE IOC
 * ADMIN + ANALYST + VIEWER
 */
router.get(
    "/:id",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST", "VIEWER"]),
    getIOCById
);

/**
 * UPDATE IOC
 * Only ADMIN + ANALYST
 */
router.put(
    "/:id",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN", "ANALYST"]),
    validateIOC,
    updateIOC
);

/**
 * DELETE IOC
 * Only ADMIN
 */
router.delete(
    "/:id",
    authenticate,
    workspaceAuth,
    workspaceRbac(["ADMIN"]),
    deleteIOC
);

module.exports = router;
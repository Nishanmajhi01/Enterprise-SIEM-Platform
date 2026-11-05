const express = require("express");
const router = express.Router();

const authenticate = require("../middleware/authMiddleware");
const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");

const { runCorrelation } = require("../services/correlationEngine");

router.post(
    "/",
    authenticate,
    workspaceAuth,
    workspaceRbac("ADMIN", "ANALYST"),
    async (req, res) => {

    try {

        const result = await runCorrelation({
            ...req.body,
            workspaceId: req.workspaceId
        });

        res.json(result);

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }
});

module.exports = router;
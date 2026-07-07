const express = require("express");
const router = express.Router();

const { runCorrelation } = require("../services/correlationEngine");

router.post("/", async (req, res) => {

    try {

        const result = await runCorrelation(req.body);

        res.json(result);

    } catch (error) {

        res.status(500).json({
            error: error.message
        });

    }
});

module.exports = router;
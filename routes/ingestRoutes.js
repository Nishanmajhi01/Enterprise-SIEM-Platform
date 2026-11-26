const express = require("express");
const router = express.Router();

const deviceAuth = require("../middleware/deviceAuth");
const { ingestLog } = require("../controllers/ingestController");

// 🔥 Devices send logs here
router.post("/", deviceAuth, ingestLog);

// Authenticated liveness check; no security event or alert is created.
router.post("/heartbeat", deviceAuth, (req, res) => res.json({ ok: true }));

module.exports = router;
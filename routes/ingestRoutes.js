const express = require("express");
const router = express.Router();

const deviceAuth = require("../middleware/deviceAuth");
const { ingestLog } = require("../controllers/ingestController");

// 🔥 Devices send logs here
router.post("/", deviceAuth, ingestLog);

module.exports = router;
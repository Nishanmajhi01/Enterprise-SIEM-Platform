const express = require("express");

const router = express.Router();

const authenticate =
require("../middleware/authMiddleware");

const {

    scanHash

} = require("../controllers/threatIntelController");

router.get(

"/hash/:hash",

authenticate,

scanHash

);

module.exports = router;
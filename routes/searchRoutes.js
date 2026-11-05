const express = require("express");

const router = express.Router();


const {
    searchEvents
} = require("../controllers/searchController");


const authenticate =
require("../middleware/authMiddleware");


const workspaceAuth = require("../middleware/workspaceAuth");
const workspaceRbac = require("../middleware/workspaceRbac");



router.get(

    "/events",

    authenticate,

    workspaceAuth,
    workspaceRbac("ADMIN", "ANALYST", "VIEWER"),

    searchEvents

);



module.exports = router;

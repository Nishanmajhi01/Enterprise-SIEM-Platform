const express = require("express");

const router = express.Router();


const {
    searchEvents
} = require("../controllers/searchController");


const authenticate =
require("../middleware/authMiddleware");


const rbac =
require("../middleware/rbac");



router.get(

    "/events",

    authenticate,

    rbac([
        "ADMIN",
        "ANALYST",
        "VIEWER"
    ]),

    searchEvents

);



module.exports = router;

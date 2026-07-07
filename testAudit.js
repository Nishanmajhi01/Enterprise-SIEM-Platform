require("dotenv").config();


const createAuditLog =
require("./utils/auditLogger");



createAuditLog({

username:"admin",

action:"TEST_EVENT",

module:"SYSTEM",

severity:"LOW",

ipAddress:"127.0.0.1",

description:
"Testing enterprise audit logging"


});
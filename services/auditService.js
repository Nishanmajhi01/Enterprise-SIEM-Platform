const AuditLog = require("../models/AuditLog");

exports.logAction = async ({ user, action, description, ip }) => {

    try {
        await AuditLog.create({
            username: user?.username || "SYSTEM",
            action,
            description,
            ipAddress: ip || "UNKNOWN"
        });
    } catch (err) {
        console.log("Audit error:", err.message);
    }

};
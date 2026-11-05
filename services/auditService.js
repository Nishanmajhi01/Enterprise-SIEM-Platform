const AuditLog = require("../models/AuditLog");

exports.logAction = async ({
    workspaceId,
    user,
    action,
    description,
    ip
}) => {
    try {
        if (
            typeof workspaceId !== "string" ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
        ) {
            throw new Error(
                "Valid workspaceId required for audit logging"
            );
        }

        await AuditLog.create({
            workspaceId,
            userId: user?.id ?? null,
            username: user?.username || "SYSTEM",
            action,
            module: "SYSTEM",
            description,
            ipAddress: ip || "UNKNOWN"
        });

        return true;
    } catch (err) {
        console.error("Audit error:", err.message);
        return false;
    }
};
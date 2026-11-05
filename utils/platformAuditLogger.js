"use strict";

const PlatformAuditLog = require("../models/PlatformAuditLog");

async function createPlatformAuditLog(data) {
    if (!data || data.module !== "AUTH" || !data.action) {
        throw new Error(
            "Platform audit logging requires an AUTH module and action"
        );
    }

    try {
        await PlatformAuditLog.create({
            userId: data.userId ?? null,
            username: data.username || "SYSTEM",
            action: data.action,
            module: "AUTH",
            severity: data.severity || "LOW",
            ipAddress: data.ipAddress || "UNKNOWN",
            description: data.description || null,
            metadata: data.metadata || {}
        });

        return true;
    } catch (error) {
        console.error(
            "Platform audit logging failed:",
            error.message
        );

        return false;
    }
}

module.exports = createPlatformAuditLog;

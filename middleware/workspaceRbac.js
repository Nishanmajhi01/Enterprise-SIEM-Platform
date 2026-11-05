"use strict";

module.exports = (...roleArguments) => {
    const allowedRoles =
        roleArguments.length === 1 &&
        Array.isArray(roleArguments[0])
            ? roleArguments[0]
            : roleArguments;

    const validRoles = ["ADMIN", "ANALYST", "VIEWER"];

    if (
        allowedRoles.length === 0 ||
        allowedRoles.some(
            role =>
                typeof role !== "string" ||
                !validRoles.includes(role)
        )
    ) {
        throw new Error("Invalid workspace RBAC configuration");
    }

    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        if (!req.workspaceId || !req.workspaceMembership) {
            return res.status(403).json({
                message: "Verified workspace membership required"
            });
        }

        const role = req.workspaceRole;

        if (
            !["ADMIN", "ANALYST", "VIEWER"].includes(role) ||
            !allowedRoles.includes(role)
        ) {
            return res.status(403).json({
                message: "Insufficient workspace permissions"
            });
        }

        next();
    };
};

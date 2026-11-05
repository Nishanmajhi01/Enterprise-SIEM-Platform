const express = require("express");

const router = express.Router();

const authenticate = require("../middleware/authMiddleware");
const rbac = require("../middleware/rbac");
const { loginLimiter } = require("../middleware/rateLimiter");

const { login } = require("../controllers/authController");

/*
 * Legacy administrator account provisioning is retired.
 * Workspace members join through email invitations instead.
 */
router.post(
    "/register",
    authenticate,
    rbac(["ADMIN"]),
    (_req, res) => res.status(410).json({
        message: "Direct account registration is retired. Send a workspace invitation instead."
    })
);

/*
 * Return the caller's active workspace memberships.
 * Only membership metadata is exposed; no user secrets or API keys.
 */
router.get("/workspaces", authenticate, async (req, res) => {
    try {
        const Workspace = require("../models/Workspace");
        const WorkspaceMembership = require("../models/WorkspaceMembership");
        require("../models/associations");

        if (!Number.isSafeInteger(req.user?.id) || req.user.id <= 0) {
            return res.status(401).json({ message: "Authentication required" });
        }

        const memberships = await WorkspaceMembership.findAll({
            where: { userId: req.user.id, status: "ACTIVE" },
            include: [{
                model: Workspace,
                as: "workspace",
                required: true,
                where: { status: "ACTIVE" },
                attributes: ["id", "name", "slug", "type"]
            }],
            attributes: ["workspaceId", "role"],
            order: [["workspaceId", "ASC"]]
        });

        return res.json({
            workspaces: memberships.map((membership) => ({
                id: membership.workspaceId,
                name: membership.workspace.name,
                slug: membership.workspace.slug,
                type: membership.workspace.type,
                role: membership.role
            }))
        });
    } catch (error) {
        console.error("Unable to list user workspaces:", error);
        return res.status(500).json({ message: "Unable to load workspaces" });
    }
});

/*
 * Workspace administrator: list members without exposing passwords or tokens.
 * Access is verified against the selected active workspace, not just JWT role.
 */
router.get(
    "/workspace-members",
    authenticate,
    require("../middleware/workspaceAuth"),
    require("../middleware/workspaceRbac")("ADMIN"),
    async (req, res) => {
        try {
            const WorkspaceMembership = require("../models/WorkspaceMembership");
            const User = require("../models/User");
            require("../models/associations");

            const members = await WorkspaceMembership.findAll({
                where: { workspaceId: req.workspaceId },
                attributes: ["id", "role", "status", "createdAt"],
                include: [{
                    model: User,
                    as: "user",
                    required: true,
                    attributes: ["id", "username", "email"]
                }],
                order: [["createdAt", "ASC"]]
            });

            return res.json({
                workspaceId: req.workspaceId,
                members: members.map(member => ({
                    membershipId: member.id,
                    role: member.role,
                    status: member.status,
                    user: {
                        id: member.user.id,
                        username: member.user.username,
                        email: member.user.email
                    }
                }))
            });
        } catch (error) {
            console.error("Unable to list workspace members:", error);
            return res.status(500).json({
                message: "Unable to load workspace members"
            });
        }
    }
);

/*
 * Legacy temporary-password workspace provisioning is retired.
 * Members must join using a single-use email invitation.
 */
router.post(
    "/workspace-members",
    authenticate,
    require("../middleware/workspaceAuth"),
    require("../middleware/workspaceRbac")("ADMIN"),
    (_req, res) => res.status(410).json({
        message: "Direct workspace account creation is retired. Send a workspace invitation instead."
    })
);

/*
 * Self-service password change. Requires the current password and a valid JWT.
 * Does not permit changing another user's password.
 */
router.post("/change-password", authenticate, async (req, res) => {
    const bcrypt = require("bcrypt");
    const User = require("../models/User");
    const { currentPassword, newPassword } = req.body || {};

    if (typeof currentPassword !== "string" ||
        typeof newPassword !== "string" ||
        newPassword.length < 12 ||
        Buffer.byteLength(newPassword, "utf8") > 72 ||
        currentPassword === newPassword) {
        return res.status(400).json({
            message: "Current password and a different new password (12-72 UTF-8 bytes) required"
        });
    }

    if (!Number.isSafeInteger(req.user?.id) || req.user.id <= 0) {
        return res.status(401).json({ message: "Authentication required" });
    }

    try {
        const user = await User.findByPk(req.user.id);
        if (!user) {
            return res.status(401).json({ message: "Authentication required" });
        }
        const valid = await bcrypt.compare(currentPassword, user.password);
        if (!valid) {
            return res.status(403).json({ message: "Current password is incorrect" });
        }
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        try {
            await require("../utils/platformAuditLogger")({
                username: user.username,
                action: "PASSWORD_CHANGE",
                module: "AUTH",
                severity: "MEDIUM",
                ipAddress: req.ip,
                description: "User changed their own account password"
            });
        } catch (auditError) {
            console.error("Password change audit failed:", auditError);
        }

        return res.json({ success: true, message: "Password updated successfully" });
    } catch (error) {
        console.error("Password change failed:", error);
        return res.status(500).json({ message: "Unable to change password" });
    }
});

/*
 * Login remains publicly accessible.
 */
router.post(
    "/login",
    loginLimiter,
    login
);

module.exports = router;

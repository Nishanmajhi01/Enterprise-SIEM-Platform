const express = require("express");

const router = express.Router();

const authenticate = require("../middleware/authMiddleware");
const rbac = require("../middleware/rbac");

const {
    register,
    login
} = require("../controllers/authController");

/*
 * User registration:
 * Only authenticated administrators can create accounts.
 */
router.post(
    "/register",
    authenticate,
    rbac(["ADMIN"]),
    register
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
 * Workspace administrator: create an account in this workspace atomically.
 * Platform role is VIEWER; permissions come from verified workspace membership.
 * Existing emails must use a separate invitation workflow (not implemented).
 */
router.post(
    "/workspace-members",
    authenticate,
    require("../middleware/workspaceAuth"),
    require("../middleware/workspaceRbac")("ADMIN"),
    async (req, res) => {
        const bcrypt = require("bcrypt");
        const { randomUUID } = require("crypto");
        const { sequelize } = require("../config/database");
        const User = require("../models/User");
        const WorkspaceMembership = require("../models/WorkspaceMembership");
        const { username, email, password, role = "VIEWER" } = req.body || {};

        if (typeof username !== "string" || username.trim().length < 3 ||
            username.trim().length > 100 ||
            typeof email !== "string" || email.length > 254 ||
            !/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email.trim()) ||
            typeof password !== "string" || password.length < 12 ||
            password.length > 72 ||
            !["ADMIN", "ANALYST", "VIEWER"].includes(role)) {
            return res.status(400).json({
                message: "Valid username (3-100), email, password (12-72) and workspace role required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        try {
            const passwordHash = await bcrypt.hash(password, 10);
            const result = await sequelize.transaction(async transaction => {
                const existing = await User.findOne({
                    where: { email: normalizedEmail }, transaction
                });
                if (existing) {
                    const conflict = new Error("Email already registered");
                    conflict.statusCode = 409;
                    throw conflict;
                }
                const user = await User.create({
                    username: username.trim(),
                    email: normalizedEmail,
                    password: passwordHash,
                    role: "VIEWER"
                }, { transaction });
                await WorkspaceMembership.create({
                    id: randomUUID(),
                    userId: user.id,
                    workspaceId: req.workspaceId,
                    role,
                    status: "ACTIVE"
                }, { transaction });
                return user;
            });

            // Audit is best effort after commit, not a reason to report failure
            // for an already-created account.
            try {
                await require("../utils/platformAuditLogger")({
                    username: req.user.username,
                    action: "USER_REGISTER",
                    module: "AUTH",
                    severity: "MEDIUM",
                    ipAddress: req.ip,
                    description: `Workspace administrator created account ${result.id} in workspace ${req.workspaceId} with membership role ${role}`
                });
            } catch (auditError) {
                console.error("Workspace member creation audit failed:", auditError);
            }

            return res.status(201).json({
                success: true,
                user: { id: result.id, username: result.username, email: result.email },
                workspaceId: req.workspaceId,
                role
            });
        } catch (error) {
            if (error.statusCode === 409 ||
                error.name === "SequelizeUniqueConstraintError") {
                return res.status(409).json({ message: "Email already registered" });
            }
            console.error("Workspace member creation failed:", error);
            return res.status(500).json({ message: "Unable to create workspace member" });
        }
    }
);

/*
 * Login remains publicly accessible.
 */
router.post(
    "/login",
    login
);

module.exports = router;

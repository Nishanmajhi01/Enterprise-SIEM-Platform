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
 * Login remains publicly accessible.
 */
router.post(
    "/login",
    login
);

module.exports = router;

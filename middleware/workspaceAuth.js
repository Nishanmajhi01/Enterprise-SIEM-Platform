"use strict";

const { Op } = require("sequelize");
const Workspace = require("../models/Workspace");
const WorkspaceMembership = require("../models/WorkspaceMembership");

// Ensure Sequelize associations are registered before eager loading.
require("../models/associations");

module.exports = async (req, res, next) => {
    try {
        const userId = req.user?.id;

        if (!Number.isSafeInteger(userId) || userId <= 0) {
            return res.status(401).json({
                message: "Valid user authentication required"
            });
        }

        const requestedWorkspaceId = req.get("x-workspace-id");

        if (
            requestedWorkspaceId &&
            !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
                requestedWorkspaceId
            )
        ) {
            return res.status(400).json({
                message: "Invalid workspace ID"
            });
        }

        const memberships = await WorkspaceMembership.findAll({
            where: {
                userId,
                status: "ACTIVE",
                ...(requestedWorkspaceId
                    ? { workspaceId: requestedWorkspaceId }
                    : {})
            },
            include: [{
                model: Workspace,
                as: "workspace",
                required: true,
                where: {
                    status: "ACTIVE"
                }
            }],
            limit: requestedWorkspaceId ? 1 : 2
        });

        if (memberships.length === 0) {
            return res.status(403).json({
                message: "No active workspace access"
            });
        }

        if (!requestedWorkspaceId && memberships.length > 1) {
            return res.status(400).json({
                message: "Select a workspace using x-workspace-id"
            });
        }

        const membership = memberships[0];

        req.workspaceId = membership.workspaceId;
        req.workspaceRole = membership.role;
        req.workspace = membership.workspace;
        req.workspaceMembership = membership;

        next();
    } catch (error) {
        console.error("Workspace authentication failed:", error);

        return res.status(500).json({
            message: "Unable to verify workspace access"
        });
    }
};

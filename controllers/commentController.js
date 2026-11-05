const IncidentComment = require("../models/IncidentComment");
const Incident = require("../models/Incident");

exports.addComment = async (req, res) => {
    try {
        if (!req.user || !req.user.username) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        const incidentId = Number(req.params.id);

        if (!Number.isSafeInteger(incidentId) || incidentId <= 0) {
            return res.status(400).json({
                message: "Invalid incident ID"
            });
        }

        const { comment } = req.body || {};

        if (
            typeof comment !== "string" ||
            !comment.trim() ||
            comment.trim().length > 2000
        ) {
            return res.status(400).json({
                message: "Comment must contain 1 to 2000 characters"
            });
        }

        const incident = await Incident.findOne({
            where: {
                id: incidentId,
                workspaceId: req.workspaceId
            }
        });

        if (!incident) {
            return res.status(404).json({
                message: "Incident not found"
            });
        }

        const createdComment = await IncidentComment.create({
            workspaceId: req.workspaceId,
            incidentId: incident.id,
            username: req.user.username,
            comment: comment.trim()
        });

        return res.status(201).json({
            success: true,
            comment: createdComment
        });

    } catch (error) {
        console.error("Incident comment creation failed:", error);

        return res.status(500).json({
            message: "Unable to create incident comment"
        });
    }
};

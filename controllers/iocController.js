const IOC = require("../models/IOC");
const { Op } = require("sequelize");
const { logAction } = require("../services/auditService");

exports.createIOC = async (req, res) => {

    try {

        const ioc = await IOC.create({
            ...req.body,
            workspaceId: req.workspaceId,
            createdBy: req.user.id
        });

        await logAction({
            workspaceId: req.workspaceId,
            user: req.user,
            action: "IOC_CREATED",
            description: `IOC ${ioc.value} created`,
            ip: req.ip
        });

        res.status(201).json({
            message: "IOC Created",
            ioc
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.updateIOC = async (req, res) => {

    try {

        const {
            workspaceId,
            createdBy,
            id,
            ...allowedUpdates
        } = req.body;

        const [updatedCount] = await IOC.update(allowedUpdates, {
            where: {
                id: req.params.id,
                workspaceId: req.workspaceId
            }
        });

        if (updatedCount === 0) {
            return res.status(404).json({
                error: "IOC not found"
            });
        }

        await logAction({
            workspaceId: req.workspaceId,
            user: req.user,
            action: "IOC_UPDATED",
            description: `IOC ${req.params.id} updated`,
            ip: req.ip
        });

        res.json({ message: "IOC Updated" });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.deleteIOC = async (req, res) => {

    try {

        const deletedCount = await IOC.destroy({
            where: {
                id: req.params.id,
                workspaceId: req.workspaceId
            }
        });

        if (deletedCount === 0) {
            return res.status(404).json({
                error: "IOC not found"
            });
        }

        await logAction({
            workspaceId: req.workspaceId,
            user: req.user,
            action: "IOC_DELETED",
            description: `IOC ${req.params.id} deleted`,
            ip: req.ip
        });

        res.json({ message: "IOC Deleted" });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.getIOCs = async (req, res) => {

    try {

        const iocs = await IOC.findAll({

            where: {
                workspaceId: req.workspaceId
            },

            order: [
                ["createdAt", "DESC"]
            ]

        });


        res.json({

            count: iocs.length,

            iocs

        });


    } catch (error) {

        res.status(500).json({

            error: error.message

        });

    }

};


exports.searchIOCs = async (req, res) => {

    try {

        const { value, type } = req.query;

        const where = {
            workspaceId: req.workspaceId
        };

        if (value) {
            where.value = { [Op.iLike]: `%${value}%` };
        }

        if (type) {
            where.type = type;
        }

        const iocs = await IOC.findAll({

            where,

            order: [
                ["createdAt", "DESC"]
            ]

        });

        res.json({

            count: iocs.length,

            iocs

        });

    } catch (error) {

        res.status(500).json({

            error: error.message

        });

    }

};


exports.getIOCById = async (req, res) => {

    try {

        const ioc = await IOC.findOne({
            where: {
                id: req.params.id,
                workspaceId: req.workspaceId
            }
        });

        if (!ioc) {

            return res.status(404).json({

                error: "IOC not found"

            });

        }

        res.json({ ioc });

    } catch (error) {

        res.status(500).json({

            error: error.message

        });

    }

};
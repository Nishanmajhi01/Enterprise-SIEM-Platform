const IOC = require("../models/IOC");
const { logAction } = require("../services/auditService");

exports.createIOC = async (req, res) => {

    try {

        const ioc = await IOC.create({
            ...req.body,
            createdBy: req.user.id
        });

        await logAction({
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

        await IOC.update(req.body, {
            where: { id: req.params.id }
        });

        await logAction({
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

        await IOC.destroy({
            where: { id: req.params.id }
        });

        await logAction({
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
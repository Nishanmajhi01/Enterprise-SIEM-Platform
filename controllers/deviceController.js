"use strict";

const crypto = require("crypto");
const Device = require("../models/Device");

function generateApiKey() {
    return crypto.randomBytes(32).toString("hex");
}

function validDeviceId(value) {
    const id = Number(value);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
}

const allowedFields = [
    "name",
    "hostname",
    "type",
    "ipAddress",
    "operatingSystem",
    "location",
    "agentVersion"
];

exports.registerDevice = async (req, res) => {
    try {
        if (!req.workspaceId) {
            return res.status(403).json({
                message: "Verified workspace required"
            });
        }

        const deviceData = {};

        for (const field of allowedFields) {
            if (req.body[field] !== undefined) {
                deviceData[field] = req.body[field];
            }
        }

        const device = await Device.create({
            ...deviceData,
            workspaceId: req.workspaceId,
            apiKey: generateApiKey(),
            status: "ACTIVE"
        });

        return res.status(201).json({
            message: "Device registered",
            device: {
                id: device.id,
                name: device.name,
                hostname: device.hostname,
                type: device.type,
                ipAddress: device.ipAddress,
                status: device.status,
                workspaceId: device.workspaceId
            },
            apiKey: device.apiKey
        });

    } catch (error) {
        console.error("Device registration failed:", error);

        return res.status(500).json({
            message: "Device registration failed"
        });
    }
};

exports.getDevices = async (req, res) => {
    try {
        const devices = await Device.findAll({
            where: {
                workspaceId: req.workspaceId
            },
            attributes: {
                exclude: ["apiKey"]
            },
            order: [["createdAt", "DESC"]]
        });

        return res.json({
            count: devices.length,
            devices
        });

    } catch (error) {
        console.error("Device listing failed:", error);

        return res.status(500).json({
            message: "Unable to retrieve devices"
        });
    }
};

exports.updateDeviceStatus = async (req, res) => {
    try {
        const id = validDeviceId(req.params.id);

        if (!id) {
            return res.status(400).json({
                message: "Invalid device ID"
            });
        }

        const allowedStatuses = [
            "ACTIVE",
            "OFFLINE",
            "DISABLED"
        ];

        if (!allowedStatuses.includes(req.body.status)) {
            return res.status(400).json({
                message: "Invalid device status"
            });
        }

        const device = await Device.findOne({
            where: {
                id,
                workspaceId: req.workspaceId
            }
        });

        if (!device) {
            return res.status(404).json({
                message: "Device not found"
            });
        }

        device.status = req.body.status;
        await device.save();

        return res.json({
            message: "Device updated",
            device: {
                id: device.id,
                name: device.name,
                status: device.status,
                workspaceId: device.workspaceId
            }
        });

    } catch (error) {
        console.error("Device update failed:", error);

        return res.status(500).json({
            message: "Unable to update device"
        });
    }
};

exports.regenerateApiKey = async (req, res) => {
    try {
        const id = validDeviceId(req.params.id);

        if (!id) {
            return res.status(400).json({
                message: "Invalid device ID"
            });
        }

        const device = await Device.findOne({
            where: {
                id,
                workspaceId: req.workspaceId
            }
        });

        if (!device) {
            return res.status(404).json({
                message: "Device not found"
            });
        }

        const apiKey = generateApiKey();

        device.apiKey = apiKey;
        await device.save();

        return res.json({
            message: "API key regenerated",
            deviceId: device.id,
            apiKey
        });

    } catch (error) {
        console.error("API key regeneration failed:", error);

        return res.status(500).json({
            message: "Unable to regenerate API key"
        });
    }
};

exports.deleteDevice = async (req, res) => {
    try {
        const id = validDeviceId(req.params.id);

        if (!id) {
            return res.status(400).json({
                message: "Invalid device ID"
            });
        }

        const deleted = await Device.destroy({
            where: {
                id,
                workspaceId: req.workspaceId
            }
        });

        if (deleted !== 1) {
            return res.status(404).json({
                message: "Device not found"
            });
        }

        return res.json({
            message: "Device deleted"
        });

    } catch (error) {
        console.error("Device deletion failed:", error);

        return res.status(500).json({
            message: "Unable to delete device"
        });
    }
};

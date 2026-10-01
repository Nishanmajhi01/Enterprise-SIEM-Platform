const crypto = require("crypto");

const Device = require("../models/Device");


function generateApiKey(){

    return crypto.randomBytes(32).toString("hex");

}


exports.registerDevice = async (req, res) => {

    try {

        const apiKey = generateApiKey();

        const device = await Device.create({

            ...req.body,

            apiKey,
            status: "ACTIVE"

        });

        res.status(201).json({

            message: "Device registered",

            device

        });

    } catch (error) {

        res.status(500).json({ error: error.message });

    }

};


exports.getDevices = async (req, res) => {

    try {

        const devices = await Device.findAll({

            order: [["createdAt", "DESC"]]

        });

        res.json({

            count: devices.length,

            devices

        });

    } catch (error) {

        res.status(500).json({ error: error.message });

    }

};


exports.updateDeviceStatus = async (req, res) => {

    try {

        const device = await Device.findByPk(req.params.id);

        if (!device) {

            return res.status(404).json({ error: "Device not found" });

        }

        device.status = req.body.status || device.status;

        await device.save();

        res.json({ message: "Device updated", device });

    } catch (error) {

        res.status(500).json({ error: error.message });

    }

};


exports.regenerateApiKey = async (req, res) => {

    try {

        const device = await Device.findByPk(req.params.id);

        if (!device) {

            return res.status(404).json({ error: "Device not found" });

        }

        device.apiKey = generateApiKey();

        await device.save();

        res.json({ message: "API key regenerated", device });

    } catch (error) {

        res.status(500).json({ error: error.message });

    }

};


exports.deleteDevice = async (req, res) => {

    try {

        await Device.destroy({ where: { id: req.params.id } });

        res.json({ message: "Device deleted" });

    } catch (error) {

        res.status(500).json({ error: error.message });

    }

};

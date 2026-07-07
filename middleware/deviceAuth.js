const Device = require("../models/Device");

module.exports = async (req, res, next) => {

    try {

        const apiKey = req.headers["x-api-key"];

        if (!apiKey) {
            return res.status(401).json({ error: "Missing API Key" });
        }

        const device = await Device.findOne({
            where: { apiKey }
        });

        if (!device) {
            return res.status(403).json({ error: "Invalid Device" });
        }

        req.device = device;

        next();

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
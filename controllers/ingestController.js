const { runCorrelation } = require("../services/correlationEngine");

exports.ingestLog = async (req, res) => {

    try {

        const device = req.device;

        const log = req.body;

        // 🔥 STANDARDIZED EVENT FORMAT
        const event = {
            deviceId: device.id,
            deviceType: device.type,
            sourceIP: log.sourceIP || device.ipAddress,
            eventType: log.eventType,
            attackType: log.attackType || "UNKNOWN",
            raw: log,
            timestamp: new Date()
        };

        // 🧠 Dummy IOC + Detection (already in your system)
        const iocMatches = [];
        const detection = {
            alert: null,
            severity: "LOW",
            riskScore: 0
        };

        // 🚨 CALL CORRELATION ENGINE
        const result = await runCorrelation(
            event,
            iocMatches,
            detection
        );

        res.json({
            message: "Log processed successfully",
            result
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
const {
    processSecurityEvent
} = require("../services/eventPipeline");


/**
 * ==================================
 * DEVICE LOG INGESTION
 * Devices (Kali targets, Windows/Linux
 * hosts, pfSense) send raw logs here,
 * authenticated via x-api-key (deviceAuth).
 * Runs through the same real pipeline as
 * POST /api/events.
 * ==================================
 */

exports.ingestLog = async (req, res) => {

    try{

        const device = req.device;

        const log = req.body;

        const eventData = {

            deviceId: device.id,

            eventType: log.eventType || "UNKNOWN",

            sourceIP: log.sourceIP || device.ipAddress,

            destinationIP: log.destinationIP || null,

            username: log.username || null,

            message: log.message || null,

            severity: log.severity || "LOW",

            attackType: log.attackType || "UNKNOWN",

            raw: log,

            timestamp: new Date()

        };

        const result =
        await processSecurityEvent(eventData);

        res.json({

            message:
            "Security event processed",

            eventId:
            result.event.id,

            matchedIOCs:
            result.matchedIOCs,

            incident:
            result.incident,

            risk:
            result.risk

        });

    }
    catch(error){

        console.log(
            "Ingest Error:",
            error.message
        );

        res.status(500).json({

            error: error.message

        });

    }

};

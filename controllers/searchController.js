const SecurityEvent = require("../models/SecurityEvent");
const { Op } = require("sequelize");


exports.searchEvents = async (req, res) => {

    try {
        if (!req.workspaceId) return res.status(403).json({ message: "Verified workspace access required" });

        const {
            ip,
            severity,
            eventType,
            attackType,
            deviceId,
            from,
            to,
            page = 1,
            limit = 50
        } = req.query;


        // Scope every query to the authenticated workspace, never client input.
        const where = { workspaceId: req.workspaceId };
        const pageNumber = Number(page);
        const pageSize = Number(limit);
        if (!Number.isSafeInteger(pageNumber) || pageNumber < 1 ||
            !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 200) {
            return res.status(400).json({ message: "Page must be positive and limit must be between 1 and 200" });
        }
        if ((from && !to) || (!from && to) ||
            (from && (!Number.isFinite(Date.parse(from)) || !Number.isFinite(Date.parse(to)) ||
              new Date(from) > new Date(to)))) {
            return res.status(400).json({ message: "Valid from and to dates required" });
        }
        if (deviceId !== undefined && (!Number.isSafeInteger(Number(deviceId)) || Number(deviceId) < 1)) {
            return res.status(400).json({ message: "Invalid device ID" });
        }


        // Search by source IP
        if (ip) {

            where.sourceIP = ip;

        }


        // Search severity
        if (severity) {

            where.severity = severity;

        }


        // Search event type
        if (eventType) {

            where.eventType = eventType;

        }


        // Search attack type
        if (attackType) {

            where.attackType = attackType;

        }


        // Search device
        if (deviceId) {

            where.deviceId = deviceId;

        }


        // Date range search
        if (from && to) {

            where.timestamp = {

                [Op.between]: [
                    new Date(from),
                    new Date(to)
                ]

            };

        }


        const offset =
        (pageNumber - 1) * pageSize;



        const result =
        await SecurityEvent.findAndCountAll({

            where,

            limit: pageSize,

            offset,


            order:[
                [
                    "timestamp",
                    "DESC"
                ]
            ]

        });



        res.json({

            total: result.count,

            page: pageNumber,

            limit: Number(limit),

            totalPages:
            Math.ceil(result.count / pageSize),

            events: result.rows

        });


    }
    catch(error){

        res.status(500).json({

            error:error.message

        });

    }

};
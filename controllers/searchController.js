const SecurityEvent = require("../models/SecurityEvent");
const { Op } = require("sequelize");


exports.searchEvents = async (req, res) => {

    try {

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


        let where = {};


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
        (page - 1) * limit;



        const result =
        await SecurityEvent.findAndCountAll({

            where,

            limit: Number(limit),

            offset: Number(offset),


            order:[
                [
                    "timestamp",
                    "DESC"
                ]
            ]

        });



        res.json({

            total: result.count,

            page: Number(page),

            limit: Number(limit),

            totalPages:
            Math.ceil(result.count / limit),

            events: result.rows

        });


    }
    catch(error){

        res.status(500).json({

            error:error.message

        });

    }

};
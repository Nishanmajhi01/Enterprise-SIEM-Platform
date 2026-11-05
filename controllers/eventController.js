const SecurityEvent = require("../models/SecurityEvent");
const Device = require("../models/Device");

const { Op } = require("sequelize");

const {
    processSecurityEvent
} = require("../services/eventPipeline");


/**
 * ==================================
 * CREATE SECURITY EVENT
 * ==================================
 */

exports.createEvent = async (req, res) => {

    try {

        if (!req.workspaceId) {
            return res.status(403).json({
                message: "Verified workspace access required"
            });
        }

        if (
            !req.body ||
            typeof req.body !== "object" ||
            Array.isArray(req.body)
        ) {
            return res.status(400).json({
                message: "Invalid event payload"
            });
        }

        const requestedDeviceId = req.body.deviceId;

        if (requestedDeviceId !== undefined &&
            requestedDeviceId !== null) {

            const deviceId = Number(requestedDeviceId);

            if (!Number.isSafeInteger(deviceId) ||
                deviceId <= 0) {
                return res.status(400).json({
                    message: "Invalid device ID"
                });
            }

            const device = await Device.findOne({
                where: {
                    id: deviceId,
                    workspaceId: req.workspaceId
                }
            });

            if (!device) {
                return res.status(403).json({
                    message: "Device does not belong to this workspace"
                });
            }
        }

        const eventData = {
            ...req.body,
            workspaceId: req.workspaceId
        };

        const result =
        await processSecurityEvent(eventData);

        res.json({

            message:
            "Security event stored",

            event:
            result.event,

            incident:
            result.incident,

            matchedIOCs:
            result.matchedIOCs,

            risk:
            result.risk

        });

    }

    catch(error){

        console.log(
            "Security Event Error:",
            error.message
        );

        res.status(500).json({

            error:
            error.message

        });

    }

};


/**
 * ==================================
 * SOC INVESTIGATION SEARCH
 * ==================================
 */


exports.searchEvents = async (req, res) => {


    try {


        const {


            ip,


            attackType,


            severity,


            startDate,


            endDate,


            limit = 50,


            page = 1



        } = req.query;


        const where = {};


        if(ip){


            where.sourceIP = ip;


        }


        if(attackType){


            where.attackType =
            attackType;


        }


        if(severity){


            where.severity =
            severity;


        }


        if(startDate && endDate){



            where.timestamp = {



                [Op.between]:


                [


                    new Date(startDate),


                    new Date(endDate)


                ]


            };


        }


        const offset =


        (Number(page)-1)


        *


        Number(limit);


        const events =


        await SecurityEvent.findAndCountAll({



            where,



            order:[


                [


                    "timestamp",


                    "DESC"


                ]


            ],



            limit:
            Number(limit),



            offset



        });


        res.json({



            total:
            events.count,



            page:
            Number(page),



            limit:
            Number(limit),



            events:
            events.rows



        });


    }


    catch(error){



        res.status(500).json({


            error:
            error.message


        });


    }



};

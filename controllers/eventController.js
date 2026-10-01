const SecurityEvent = require("../models/SecurityEvent");

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

        const result =
        await processSecurityEvent(req.body);

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

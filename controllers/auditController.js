const AuditLog = require("../models/AuditLog");


// Create audit log

exports.createAuditLog = async (req, res) => {

    try {

        const audit = await AuditLog.create(req.body);


        res.json({

            message: "Audit log created",

            audit

        });


    } catch(error) {


        res.status(500).json({

            error:error.message

        });


    }

};




// Get all audit logs

exports.getAuditLogs = async(req,res)=>{


    try{


        const logs = await AuditLog.findAll({

            order:[
                ["createdAt","DESC"]
            ]

        });


        res.json(logs);


    }catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};
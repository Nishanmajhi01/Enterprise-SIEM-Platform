const AuditLog = require("../models/AuditLog");


// Create audit log

exports.createAuditLog = async (req, res) => {
    return res.status(403).json({
        error: "Direct audit log creation is disabled"
    });
};


// Get audit logs for the authenticated workspace

exports.getAuditLogs = async(req,res)=>{


    try{


        const logs = await AuditLog.findAll({
            where: {
                workspaceId: req.workspaceId
            },
            order: [
                ["createdAt", "DESC"]
            ]
        });


        res.json(logs);


    }catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};
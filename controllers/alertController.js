const Alert = require("../models/Alert");
const { logAction } = require("../services/auditService");

const {
    emitAlert
} = require("../utils/socketEmitter");



// CREATE ALERT
// Used by SIEM detection engines

exports.createAlert = async (req, res) => {

    try {


        const alert = await Alert.create({

            title: req.body.title,

            description: req.body.description,

            severity: req.body.severity || "LOW",

            sourceIP: req.body.sourceIP,

            attackType: req.body.attackType,

            mitreTechnique:
            req.body.mitreTechnique,

            tactic:
            req.body.tactic,

            riskScore:
            req.body.riskScore || 0,

            createdBy:
            req.user ? req.user.id : null

        });



        // Send real-time alert
        emitAlert(alert);



        res.status(201).json({

            message:
            "Alert created successfully",

            alert

        });



    }
    catch(error){


        res.status(500).json({

            error:error.message

        });


    }

};



// =====================================
// GET ALL ALERTS
// =====================================

exports.getAlerts = async (req, res) => {

    try {

        const alerts = await Alert.findAll({

            order: [
                ["createdAt", "DESC"]
            ]

        });


        res.json({

            count: alerts.length,

            alerts

        });


    } catch(error) {


        res.status(500).json({

            error:error.message

        });


    }

};





// =====================================
// GET SINGLE ALERT
// =====================================

exports.getAlertById = async(req,res)=>{


    try{


        const alert =
        await Alert.findByPk(
            req.params.id
        );



        if(!alert){

            return res.status(404).json({

                message:"Alert not found"

            });

        }



        res.json(alert);



    }
    catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};







// =====================================
// CREATE ALERT
// Used by SIEM detection engines
// =====================================


exports.createAlert = async(req,res)=>{


    try{


        const alert =
        await Alert.create({

            title:req.body.title,

            description:req.body.description,

            severity:req.body.severity || "LOW",

            sourceIP:req.body.sourceIP,

            attackType:req.body.attackType,

            riskScore:req.body.riskScore || 0,

            createdBy:req.user?.id || null

        });





        // Send real-time alert
        emitAlert(alert);





        res.status(201).json({

            message:"Alert created",

            alert

        });



    }
    catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};






// =====================================
// UPDATE ALERT STATUS
// =====================================


exports.updateAlertStatus = async(req,res)=>{


    try{


        const {
            status
        } = req.body;



        const alert =
        await Alert.findByPk(
            req.params.id
        );



        if(!alert){


            return res.status(404).json({

                message:"Alert not found"

            });


        }





        alert.status=status;


        await alert.save();





        await logAction({

            user:req.user,

            action:"ALERT_STATUS_UPDATED",

            description:
            `Alert ${alert.id} changed to ${status}`,

            ip:req.ip

        });





        res.json({

            message:"Alert status updated",

            alert

        });



    }
    catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};







// =====================================
// ASSIGN ALERT
// =====================================


exports.assignAlert = async(req,res)=>{


    try{


        const {
            assignedTo
        } = req.body;




        const alert =
        await Alert.findByPk(
            req.params.id
        );



        if(!alert){


            return res.status(404).json({

                message:"Alert not found"

            });


        }




        alert.assignedTo=assignedTo;

        alert.status="INVESTIGATING";



        await alert.save();




        res.json({

            message:"Alert assigned",

            alert

        });



    }
    catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};








// =====================================
// RESOLVE ALERT
// =====================================


exports.resolveAlert = async(req,res)=>{


    try{


        const {
            resolutionNote
        } = req.body;




        const alert =
        await Alert.findByPk(
            req.params.id
        );



        if(!alert){


            return res.status(404).json({

                message:"Alert not found"

            });


        }





        alert.status="RESOLVED";

        alert.resolvedBy =
        req.user.id;


        alert.resolutionNote =
        resolutionNote;



        await alert.save();





        await logAction({


            user:req.user,

            action:"ALERT_RESOLVED",

            description:
            `Alert ${alert.id} resolved`,

            ip:req.ip


        });





        res.json({

            message:"Alert resolved",

            alert

        });




    }
    catch(error){


        res.status(500).json({

            error:error.message

        });


    }


};
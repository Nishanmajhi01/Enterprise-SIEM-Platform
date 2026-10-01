const {
    checkFileHash
} = require("../services/virusTotalService");


const {
    mapThreat
} = require("../services/mitreMapper");


const {
    analyzeVirusTotal
} = require("../services/reputationEngine");


const {
    calculateRisk
} = require("../services/riskEngine");


const ThreatIntel =
require("../models/ThreatIntel");


const {
    emitAlert
} = require("../utils/socketEmitter");





/*
=================================================
GET ALL THREAT INTELLIGENCE
Used by Threat Intelligence Cards
=================================================
*/

exports.getThreatIntel = async(req,res)=>{


    try{


        const threats =
        await ThreatIntel.findAll({

            order:[
                ["createdAt","DESC"]
            ]

        });



        res.json(threats);



    }
    catch(error){


        res.status(500).json({

            message:
            "Unable to fetch threat intelligence",

            error:
            error.message

        });


    }


};








/*
=================================================
VIRUSTOTAL HASH ANALYSIS
=================================================
*/


exports.scanHash = async(req,res)=>{


    try{


        const {
            hash
        } = req.params;




        /*
        Check hash with VirusTotal
        */

        const result =
        await checkFileHash(hash);






        if(!result.data){


            return res.status(400).json({

                success:false,

                message:
                "Unable to analyse hash",

                result

            });


        }







        /*
        Reputation Analysis
        */

        const analysis =
        analyzeVirusTotal(result.data);








        /*
        MITRE Mapping
        */

        const mitre =
        mapThreat(

            result
            .data
            .data
            .attributes
            .type_description
            ||
            "malware"

        );








        /*
        Risk Calculation
        */

        const risk =
        calculateRisk({

            maliciousCount:
            analysis.detections.malicious,


            severity:
            analysis.severity,


            assetCriticality:
            "HIGH"

        });









        /*
        Normalize severity
        Because database ENUM requires uppercase
        */

        const severity =
        (
            analysis.severity
            ||
            "LOW"

        )
        .toUpperCase();









        /*
        Save Threat Intelligence
        */

        const newThreat =
        await ThreatIntel.create({



            name:

            result
            .data
            .data
            .attributes
            .meaningful_name

            ||

            "Unknown Malware",






            attackType:

            result
            .data
            .data
            .attributes
            .type_description

            ||

            "MALWARE",







            mitreTechnique:

            mitre.technique

            ||

            "UNKNOWN",







            tactic:

            mitre.tactic

            ||

            "UNKNOWN",







            severity,







            riskScore:

            risk.score

            ??

            risk,







            sourceIP:

            null



        });










        /*
        Send Real-Time SOC Alert
        */

        emitAlert({



            title:

            newThreat.name,






            description:

            "Threat intelligence analysis completed",






            severity:

            newThreat.severity,






            attackType:

            newThreat.attackType,






            riskScore:

            newThreat.riskScore,






            mitreTechnique:

            newThreat.mitreTechnique,






            tactic:

            newThreat.tactic



        });









        res.json({



            success:true,



            hash,



            threat:newThreat,



            threatIntelligence:

            analysis,



            mitre,



            risk



        });







    }
    catch(error){



        console.log(
            "Threat Intel Error:",
            error.message
        );



        res.status(500).json({



            success:false,



            message:

            "Threat analysis failed",



            error:

            error.message



        });



    }



};
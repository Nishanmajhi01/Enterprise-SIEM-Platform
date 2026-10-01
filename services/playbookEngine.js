const ResponsePlaybook =
require("../models/ResponsePlaybook");

const ResponseAction =
require("../models/ResponseAction");

const {
    executeResponse
} = require("./responseExecutor");


// ========================================================
// EXECUTE INCIDENT RESPONSE PLAYBOOK
// ========================================================

const executePlaybook = async (incident) => {

    try {

        // =================================================
        // FIND MATCHING PLAYBOOK
        // =================================================

        const playbook =
        await ResponsePlaybook.findOne({

            where: {

                triggerType:
                    incident.attackType,

                severity:
                    incident.severity,

                enabled: true

            }

        });


        if (!playbook) {

            console.log(
                `No matching playbook for ${incident.attackType} / ${incident.severity}`
            );

            return null;

        }


        console.log(
            "Executing Playbook:",
            playbook.name
        );


        console.log(
            `Playbook Action: ${playbook.action}`
        );


        console.log(
            `Response Target: ${incident.sourceIP}`
        );


        // =================================================
        // EXECUTE RESPONSE
        // =================================================

        const result =
        await executeResponse(

            playbook.action,

            incident.sourceIP

        );


        // =================================================
        // RECORD RESPONSE ACTION
        // =================================================

        const responseAction =
        await ResponseAction.create({

            incidentId:
                incident.id,

            action:
                playbook.action,

            target:
                incident.sourceIP,

            status:
                result.success
                    ? "SUCCESS"
                    : "FAILED",

            details: {

                playbook:
                    playbook.name,

                simulated:
                    result.simulated ?? false,

                message:
                    result.message || null,

                error:
                    result.error || null

            }

        });


        // =================================================
        // UPDATE INCIDENT
        // =================================================

        if (result.success) {

            incident.status =
                "CONTAINED";

        }


        incident.timeline = [

            ...(incident.timeline || []),

            {

                action:
                    result.success
                        ? "PLAYBOOK_EXECUTED"
                        : "PLAYBOOK_FAILED",

                responseAction:
                    playbook.action,

                user:
                    "AUTOMATION_ENGINE",

                playbook:
                    playbook.name,

                simulated:
                    result.simulated ?? false,

                time:
                    new Date()

            }

        ];


        await incident.save();


        // =================================================
        // LOG RESULT
        // =================================================

        if (result.success) {

            console.log(
                `PLAYBOOK SUCCESS | Incident: ${incident.id} | Action: ${playbook.action} | Target: ${incident.sourceIP} | Simulated: ${result.simulated ?? false}`
            );

        }
        else {

            console.log(
                `PLAYBOOK FAILED | Incident: ${incident.id} | Action: ${playbook.action} | Target: ${incident.sourceIP} | Error: ${result.error}`
            );

        }


        return {

            playbook,

            responseAction,

            result

        };

    }
    catch (error) {

        console.error(
            "PLAYBOOK ENGINE ERROR:",
            error.message
        );

        throw error;

    }

};


module.exports = {
    executePlaybook
};
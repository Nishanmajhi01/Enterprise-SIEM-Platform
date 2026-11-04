const ResponsePlaybook =
require("../models/ResponsePlaybook");

const ResponseAction =
require("../models/ResponseAction");

const { withIncidentLock } = require("./responseLock");

const {
    executeResponse
} = require("./responseExecutor");


// ========================================================
// EXECUTE INCIDENT RESPONSE PLAYBOOK
// ========================================================

const executePlaybookUnlocked = async (incident) => {
        // =================================================
        // DDOS V2 SAFETY GUARD
        // Monitoring and incident creation only.
        // Never execute automatic response actions for DDOS.
        // =================================================

        if (
            String(incident.attackType || "")
                .trim()
                .toUpperCase() === "DDOS"
        ) {
            console.log(
                `DDOS SAFETY: Automatic response disabled for incident ${incident.id}`
            );

            return null;
        }
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

        // Prevent repeated successful responses for the same incident.
        if (playbook.action === "BLOCK_IP") {
            const previousBlock = await ResponseAction.findOne({
                where: {
                    incidentId: incident.id,
                    action: "BLOCK_IP",
                    target: incident.sourceIP,
                    status: "SUCCESS"
                }
            });

            if (previousBlock) {
                console.log(
                    `BLOCK_IP SKIPPED: Incident ${incident.id} already has successful response ${previousBlock.id}`
                );
                return null;
            }
        }

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

        // Only real successful responses establish containment.
        // Simulated actions must not imply real containment.
        if (result.success && result.simulated !== true) {

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


const executePlaybook = async (incident) => {
    if (
        String(incident.attackType || "").trim().toUpperCase() === "BRUTE_FORCE"
    ) {
        return withIncidentLock(
            incident.id,
            () => executePlaybookUnlocked(incident)
        );
    }

    return executePlaybookUnlocked(incident);
};

module.exports = {
    executePlaybook
};

// services/responseExecutor.js

const net = require("net");

// ========================================================
// PROTECTED IPS
// Never automatically block critical infrastructure
// ========================================================

const PROTECTED_IPS = new Set([
    "127.0.0.1",
    "::1",

    // ubuntu siem
    "192.168.1.10",

    // pfSense 
    "192.168.56.2"
]);


// ========================================================
// PRIVATE IP CHECK
// ========================================================

function isValidIP(ip) {

    return net.isIP(ip) !== 0;

}


// ========================================================
// BLOCK IP - SIMULATION MODE
// Real pfSense integration comes later
// ========================================================

async function blockIP(ip) {

    if (!ip || !isValidIP(ip)) {

        throw new Error(
            `Invalid IP address: ${ip}`
        );

    }


    if (PROTECTED_IPS.has(ip)) {

        throw new Error(
            `Protected IP cannot be blocked: ${ip}`
        );

    }


    console.log(
        `RESPONSE EXECUTOR: BLOCK_IP requested for ${ip}`
    );


    // IMPORTANT:
    // We are still in simulation mode.
    // No firewall rule is changed yet.

    return {

        success: true,

        simulated: true,

        action: "BLOCK_IP",

        target: ip,

        message:
            `Simulated firewall block for ${ip}`

    };

}


// ========================================================
// MAIN RESPONSE EXECUTOR
// ========================================================

async function executeResponse(action, target) {

    try {

        switch (
            String(action || "").toUpperCase()
        ) {

            case "BLOCK_IP":

                return await blockIP(target);


            case "ISOLATE_HOST":

                console.log(
                    `RESPONSE EXECUTOR: ISOLATE_HOST requested for ${target}`
                );

                return {

                    success: true,
                    simulated: true,
                    action: "ISOLATE_HOST",
                    target

                };


            case "DISABLE_ACCOUNT":

                console.log(
                    `RESPONSE EXECUTOR: DISABLE_ACCOUNT requested for ${target}`
                );

                return {

                    success: true,
                    simulated: true,
                    action: "DISABLE_ACCOUNT",
                    target

                };


            default:

                throw new Error(
                    `Unsupported response action: ${action}`
                );

        }

    }
    catch (error) {

        console.error(
            "RESPONSE EXECUTION FAILED:",
            error.message
        );

        return {

            success: false,

            simulated: true,

            action,

            target,

            error: error.message

        };

    }

}


module.exports = {
    executeResponse
};
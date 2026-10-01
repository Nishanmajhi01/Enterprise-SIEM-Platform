const net = require("net");
const { execFile } = require("child_process");
const { promisify } = require("util");

const execFileAsync = promisify(execFile);

// ========================================================
// PFSENSE CONFIGURATION
// ========================================================

const PFSENSE_HOST = "192.168.56.2";
const PFSENSE_USER = "admin";

const SSH_KEY =
    "/home/siemadmin/.ssh/siem_pfsense";

const BLOCK_TABLE = "SIEM_BLOCKLIST";


// ========================================================
// PROTECTED IPS
// These addresses must never be automatically blocked.
// ========================================================

const PROTECTED_IPS = new Set([
    "127.0.0.1",
    "::1",

    // Ubuntu SIEM
    "192.168.1.10",

    // pfSense LAN
    "192.168.1.1",

    // pfSense OPT1 management
    "192.168.56.2",

    // Windows management host-only adapter
    "192.168.56.1"
]);


// ========================================================
// IP VALIDATION
// ========================================================

function validateTargetIP(ip) {

    if (!ip || typeof ip !== "string") {
        throw new Error("Target IP is required");
    }

    const target = ip.trim();

    if (net.isIP(target) === 0) {
        throw new Error(`Invalid IP address: ${target}`);
    }

    if (PROTECTED_IPS.has(target)) {
        throw new Error(
            `Protected IP cannot be blocked: ${target}`
        );
    }

    return target;
}


// ========================================================
// EXECUTE PFSENSE COMMAND
// ========================================================

async function executePfSenseCommand(operation, ip) {

    if (!["add", "delete"].includes(operation)) {
        throw new Error(
            `Invalid pfSense table operation: ${operation}`
        );
    }

    const remoteCommand =
        `/sbin/pfctl -t ${BLOCK_TABLE} -T ${operation} ${ip}`;

    const sshArguments = [
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=5",
        "-i", SSH_KEY,
        `${PFSENSE_USER}@${PFSENSE_HOST}`,
        remoteCommand
    ];

    const { stdout, stderr } = await execFileAsync(
        "/usr/bin/ssh",
        sshArguments,
        {
            timeout: 10000,
            maxBuffer: 1024 * 1024
        }
    );

    return {
        stdout: stdout.trim(),
        stderr: stderr.trim()
    };
}


// ========================================================
// BLOCK IP
// ========================================================

async function blockIP(ip) {

    const target = validateTargetIP(ip);

    console.log(
        `RESPONSE EXECUTOR: Blocking ${target} via pfSense`
    );

    const result = await executePfSenseCommand(
        "add",
        target
    );

    return {
        success: true,
        simulated: false,
        action: "BLOCK_IP",
        target,
        firewall: "pfSense",
        table: BLOCK_TABLE,
        output: result.stdout,
        message:
            `IP ${target} added to ${BLOCK_TABLE}`
    };
}


// ========================================================
// UNBLOCK IP
// ========================================================

async function unblockIP(ip) {

    const target = validateTargetIP(ip);

    console.log(
        `RESPONSE EXECUTOR: Unblocking ${target} via pfSense`
    );

    const result = await executePfSenseCommand(
        "delete",
        target
    );

    return {
        success: true,
        simulated: false,
        action: "UNBLOCK_IP",
        target,
        firewall: "pfSense",
        table: BLOCK_TABLE,
        output: result.stdout,
        message:
            `IP ${target} removed from ${BLOCK_TABLE}`
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

            case "UNBLOCK_IP":
                return await unblockIP(target);


            // Keep these simulated until their
            // integrations are implemented safely.

            case "ISOLATE_HOST":

                return {
                    success: true,
                    simulated: true,
                    action: "ISOLATE_HOST",
                    target
                };


            case "DISABLE_ACCOUNT":

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

    } catch (error) {

        console.error(
            "RESPONSE EXECUTION FAILED:",
            error.message
        );

        return {
            success: false,
            simulated: false,
            action,
            target,
            error: error.message
        };
    }
}


module.exports = {
    executeResponse
};
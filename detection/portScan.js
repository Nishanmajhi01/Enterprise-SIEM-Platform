/**
 * ============================================================
 * ENTERPRISE SIEM - ADVANCED PORT SCAN DETECTOR
 * ============================================================
 *
 * Detects:
 *
 * 1. Vertical Port Scan
 *    One source IP -> one destination IP -> many ports
 *
 * 2. Horizontal Port Scan
 *    One source IP -> many internal destination hosts
 *
 * 3. Mixed Port Scan
 *    Many ports + many destination hosts
 *
 * Features:
 *
 * - pfSense event support
 * - Handles nested raw.raw structure
 * - TCP / UDP support
 * - Sliding detection window
 * - Unique destination-port tracking
 * - Unique destination-host tracking
 * - Duplicate packet suppression
 * - Alert cooldown
 * - Automatic memory cleanup
 * - Evidence returned to SIEM pipeline
 * - DNS/DHCP/NTP horizontal false-positive suppression
 * - External Internet traffic horizontal suppression
 * - Broadcast/multicast horizontal suppression
 *
 * ============================================================
 */


// ============================================================
// CONFIGURATION
// ============================================================

const CONFIG = {

    /*
     * Number of milliseconds during which packets
     * belong to the same potential scan.
     */

    WINDOW_MS:
        30 * 1000,


    /*
     * LAB THRESHOLD
     *
     * Example:
     *
     * 135
     * 139
     * 445
     * 3389
     *
     * Four unique destination ports trigger
     * vertical scan detection.
     */

    VERTICAL_PORT_THRESHOLD:
        4,


    /*
     * Number of different INTERNAL destination hosts
     * contacted by the same source before horizontal
     * scanning is detected.
     */

    HORIZONTAL_HOST_THRESHOLD:
        5,


    /*
     * Prevent repeated alerts from the same
     * scan every time another packet arrives.
     */

    ALERT_COOLDOWN_MS:
        60 * 1000,


    /*
     * Remove stale tracking information.
     */

    CLEANUP_INTERVAL_MS:
        60 * 1000,


    /*
     * Basic memory protection.
     */

    MAX_TRACKERS:
        10000,


    /*
     * ========================================================
     * HORIZONTAL SCAN EXCLUDED SERVICE PORTS
     * ========================================================
     *
     * These services can legitimately communicate
     * with several hosts.
     *
     * IMPORTANT:
     *
     * These ports are excluded ONLY from horizontal
     * scan detection.
     *
     * Vertical detection still sees them.
     */

    HORIZONTAL_IGNORE_PORTS:
        new Set([

            53,     // DNS

            67,     // DHCP Server

            68,     // DHCP Client

            123     // NTP

        ])

};


// ============================================================
// STATE
// ============================================================


/*
 * Vertical tracker
 *
 * KEY:
 *
 * sourceIP -> destinationIP
 */

const verticalTracker =
    new Map();


/*
 * Horizontal tracker
 *
 * KEY:
 *
 * sourceIP
 */

const horizontalTracker =
    new Map();


/*
 * Alert cooldown tracker.
 */

const alertCooldowns =
    new Map();


// ============================================================
// NORMALISE PORT
// ============================================================

function normalisePort(value) {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }


    const port =
        Number(value);


    if (
        !Number.isInteger(port) ||
        port < 1 ||
        port > 65535
    ) {

        return null;

    }


    return port;

}


// ============================================================
// GET PROTOCOL
// ============================================================

function normaliseProtocol(event) {

    const protocol =

        event.protocol ??

        event.raw?.protocol ??

        event.raw?.raw?.protocol ??

        "";


    return String(protocol)
        .trim()
        .toUpperCase();

}


// ============================================================
// GET DESTINATION PORT
// ============================================================

function getDestinationPort(event) {

    return normalisePort(

        event.destinationPort ??

        event.destPort ??

        event.dstPort ??

        event.raw?.destinationPort ??

        event.raw?.destPort ??

        event.raw?.dstPort ??

        event.raw?.raw?.destinationPort ??

        event.raw?.raw?.destPort ??

        event.raw?.raw?.dstPort

    );

}


// ============================================================
// GET SOURCE PORT
// ============================================================

function getSourcePort(event) {

    return normalisePort(

        event.sourcePort ??

        event.srcPort ??

        event.raw?.sourcePort ??

        event.raw?.srcPort ??

        event.raw?.raw?.sourcePort ??

        event.raw?.raw?.srcPort

    );

}


// ============================================================
// GET FIREWALL ACTION
// ============================================================

function getFirewallAction(event) {

    const action =

        event.action ??

        event.raw?.action ??

        event.raw?.raw?.action ??

        "";


    return String(action)
        .trim()
        .toUpperCase();

}


// ============================================================
// VALID NETWORK PROTOCOL
// ============================================================

function isNetworkProtocol(protocol) {

    return (

        protocol === "TCP" ||

        protocol === "UDP"

    );

}


// ============================================================
// COOLDOWN CHECK
// ============================================================

function isCoolingDown(
    key,
    now
) {

    const lastAlert =
        alertCooldowns.get(key);


    if (!lastAlert) {

        return false;

    }


    return (

        now - lastAlert <

        CONFIG.ALERT_COOLDOWN_MS

    );

}


// ============================================================
// MARK ALERT
// ============================================================

function markAlert(
    key,
    now
) {

    alertCooldowns.set(
        key,
        now
    );

}


// ============================================================
// VERTICAL PORT SCAN TRACKING
// ============================================================

function trackVerticalScan(

    sourceIP,

    destinationIP,

    destinationPort,

    protocol,

    action,

    now

) {

    const key =
        `${sourceIP}->${destinationIP}`;


    let tracker =
        verticalTracker.get(key);


    if (!tracker) {

        tracker = {

            sourceIP,

            destinationIP,

            ports:
                new Map(),

            firstSeen:
                now,

            lastSeen:
                now

        };


        verticalTracker.set(
            key,
            tracker
        );

    }


    tracker.lastSeen =
        now;


    /*
     * Store each destination port only once.
     */

    tracker.ports.set(

        destinationPort,

        {

            lastSeen:
                now,

            protocol,

            action

        }

    );


    /*
     * Remove ports outside the detection window.
     */

    for (

        const [
            port,
            metadata
        ]

        of tracker.ports.entries()

    ) {

        if (

            now - metadata.lastSeen >

            CONFIG.WINDOW_MS

        ) {

            tracker.ports.delete(
                port
            );

        }

    }


    const ports =

        [...tracker.ports.keys()]

        .sort(
            (a, b) => a - b
        );


    const uniquePorts =
        ports.length;


    const detected =

        uniquePorts >=

        CONFIG.VERTICAL_PORT_THRESHOLD;


    const cooldownKey =

        `VERTICAL:${key}`;


    const shouldAlert =

        detected &&

        !isCoolingDown(

            cooldownKey,

            now

        );


    if (shouldAlert) {

        markAlert(

            cooldownKey,

            now

        );

    }


    return {

        detected,

        shouldAlert,

        uniquePorts,

        ports,

        firstSeen:
            new Date(
                tracker.firstSeen
            ),

        lastSeen:
            new Date(
                tracker.lastSeen
            )

    };

}


// ============================================================
// INTERNAL IPv4 CHECK
// ============================================================

function isPrivateIPv4(ip) {

    if (
        !ip ||
        typeof ip !== "string"
    ) {

        return false;

    }


    const parts =
        ip
            .split(".")
            .map(Number);


    if (

        parts.length !== 4 ||

        parts.some(

            part =>

                !Number.isInteger(part) ||

                part < 0 ||

                part > 255

        )

    ) {

        return false;

    }


    /*
     * 10.0.0.0/8
     */

    if (
        parts[0] === 10
    ) {

        return true;

    }


    /*
     * 172.16.0.0/12
     */

    if (

        parts[0] === 172 &&

        parts[1] >= 16 &&

        parts[1] <= 31

    ) {

        return true;

    }


    /*
     * 192.168.0.0/16
     */

    if (

        parts[0] === 192 &&

        parts[1] === 168

    ) {

        return true;

    }


    return false;

}


// ============================================================
// BROADCAST / MULTICAST CHECK
// ============================================================

function isBroadcastOrMulticast(ip) {

    if (
        !ip ||
        typeof ip !== "string"
    ) {

        return true;

    }


    const parts =
        ip
            .split(".")
            .map(Number);


    if (
        parts.length !== 4
    ) {

        return true;

    }


    /*
     * Limited broadcast.
     */

    if (
        ip === "255.255.255.255"
    ) {

        return true;

    }


    /*
     * Broadcast addresses used by the current SIEM lab.
     */

    if (

        ip === "192.168.1.255" ||

        ip === "192.168.56.255"

    ) {

        return true;

    }


    /*
     * IPv4 multicast:
     *
     * 224.0.0.0 - 239.255.255.255
     */

    if (

        parts[0] >= 224 &&

        parts[0] <= 239

    ) {

        return true;

    }


    return false;

}


// ============================================================
// HORIZONTAL PORT SCAN TRACKING
// ============================================================

function trackHorizontalScan(

    sourceIP,

    destinationIP,

    destinationPort,

    protocol,

    action,

    now

) {

    let tracker =

        horizontalTracker.get(
            sourceIP
        );


    if (!tracker) {

        tracker = {

            hosts:
                new Map(),

            firstSeen:
                now,

            lastSeen:
                now

        };


        horizontalTracker.set(

            sourceIP,

            tracker

        );

    }


    tracker.lastSeen =
        now;


    /*
     * Get destination host tracker.
     */

    let host =

        tracker.hosts.get(
            destinationIP
        );


    if (!host) {

        host = {

            lastSeen:
                now,

            ports:
                new Set(),

            protocol,

            action

        };


        tracker.hosts.set(

            destinationIP,

            host

        );

    }


    host.lastSeen =
        now;


    host.ports.add(
        destinationPort
    );


    /*
     * Remove destination hosts outside
     * the sliding time window.
     */

    for (

        const [
            ip,
            metadata
        ]

        of tracker.hosts.entries()

    ) {

        if (

            now - metadata.lastSeen >

            CONFIG.WINDOW_MS

        ) {

            tracker.hosts.delete(
                ip
            );

        }

    }


    const hosts =

        [...tracker.hosts.keys()];


    const uniqueHosts =
        hosts.length;


    const detected =

        uniqueHosts >=

        CONFIG.HORIZONTAL_HOST_THRESHOLD;


    const cooldownKey =

        `HORIZONTAL:${sourceIP}`;


    const shouldAlert =

        detected &&

        !isCoolingDown(

            cooldownKey,

            now

        );


    if (shouldAlert) {

        markAlert(

            cooldownKey,

            now

        );

    }


    return {

        detected,

        shouldAlert,

        uniqueHosts,

        hosts,

        firstSeen:
            new Date(
                tracker.firstSeen
            ),

        lastSeen:
            new Date(
                tracker.lastSeen
            )

    };

}


// ============================================================
// CLEANUP OLD STATE
// ============================================================

function cleanup() {

    const now =
        Date.now();


    /*
     * Remove stale vertical trackers.
     */

    for (

        const [
            key,
            tracker
        ]

        of verticalTracker.entries()

    ) {

        if (

            now - tracker.lastSeen >

            CONFIG.WINDOW_MS * 2

        ) {

            verticalTracker.delete(
                key
            );

        }

    }


    /*
     * Remove stale horizontal trackers.
     */

    for (

        const [
            key,
            tracker
        ]

        of horizontalTracker.entries()

    ) {

        if (

            now - tracker.lastSeen >

            CONFIG.WINDOW_MS * 2

        ) {

            horizontalTracker.delete(
                key
            );

        }

    }


    /*
     * Remove old cooldown records.
     */

    for (

        const [
            key,
            timestamp
        ]

        of alertCooldowns.entries()

    ) {

        if (

            now - timestamp >

            CONFIG.ALERT_COOLDOWN_MS * 2

        ) {

            alertCooldowns.delete(
                key
            );

        }

    }


    /*
     * Emergency memory protection.
     */

    if (

        verticalTracker.size >

        CONFIG.MAX_TRACKERS

    ) {

        console.log(
            "PORTSCAN WARNING: vertical tracker limit reached"
        );

        verticalTracker.clear();

    }


    if (

        horizontalTracker.size >

        CONFIG.MAX_TRACKERS

    ) {

        console.log(
            "PORTSCAN WARNING: horizontal tracker limit reached"
        );

        horizontalTracker.clear();

    }

}


// ============================================================
// CLEANUP TIMER
// ============================================================

const cleanupTimer =

    setInterval(

        cleanup,

        CONFIG.CLEANUP_INTERVAL_MS

    );


/*
 * Do not keep Node.js alive only because
 * this timer exists.
 */

cleanupTimer.unref();


// ============================================================
// MAIN PORT SCAN DETECTOR
// ============================================================

function detectPortScan(event) {

    const sourceIP =
        event.sourceIP;


    const destinationIP =
        event.destinationIP;


    const destinationPort =
        getDestinationPort(event);


    const sourcePort =
        getSourcePort(event);


    const protocol =
        normaliseProtocol(event);


    const action =
        getFirewallAction(event);


    // ========================================================
    // TEMPORARY DEBUG
    // ========================================================

    console.log(

        "PORTSCAN DEBUG:",

        {

            sourceIP,

            destinationIP,

            sourcePort,

            destinationPort,

            protocol,

            action

        }

    );


    /*
     * Ignore events that cannot represent
     * TCP/UDP port activity.
     */

    if (

        !sourceIP ||

        !destinationIP ||

        destinationPort === null ||

        !isNetworkProtocol(protocol)

    ) {

        return {

            detected:
                false,

            shouldAlert:
                false,

            scanType:
                null,

            sourceIP,

            destinationIP,

            sourcePort,

            destinationPort,

            protocol,

            action,

            uniquePorts:
                0,

            uniqueHosts:
                0,

            ports:
                [],

            hosts:
                [],

            windowSeconds:

                CONFIG.WINDOW_MS /
                1000,

            detectedAt:
                null

        };

    }


    const now =
        Date.now();


    // ========================================================
    // VERTICAL DETECTION
    // ========================================================

    const vertical =

        trackVerticalScan(

            sourceIP,

            destinationIP,

            destinationPort,

            protocol,

            action,

            now

        );


    // ========================================================
    // HORIZONTAL DETECTION
    // ========================================================

    let horizontal;


    /*
     * Determine whether this event is appropriate
     * for horizontal scan tracking.
     */

    const ignoredServicePort =

        CONFIG
            .HORIZONTAL_IGNORE_PORTS
            .has(
                destinationPort
            );


    const internalDestination =

        isPrivateIPv4(
            destinationIP
        );


    const broadcastOrMulticast =

        isBroadcastOrMulticast(
            destinationIP
        );


    /*
     * Horizontal reconnaissance in this SIEM means:
     *
     * source
     *   ->
     * many INTERNAL destination hosts
     *
     * Normal Internet traffic must not increase
     * the horizontal host counter.
     */

    const shouldTrackHorizontal =

        !ignoredServicePort &&

        internalDestination &&

        !broadcastOrMulticast;


    // ========================================================
    // TRACK HORIZONTAL ACTIVITY
    // ========================================================

    if (
        shouldTrackHorizontal
    ) {

        horizontal =

            trackHorizontalScan(

                sourceIP,

                destinationIP,

                destinationPort,

                protocol,

                action,

                now

            );

    }


    // ========================================================
    // SKIP HORIZONTAL ACTIVITY
    // ========================================================

    else {

        horizontal = {

            detected:
                false,

            shouldAlert:
                false,

            uniqueHosts:
                0,

            hosts:
                [],

            firstSeen:
                new Date(now),

            lastSeen:
                new Date(now)

        };


        let reason =
            "horizontal filtering";


        if (
            ignoredServicePort
        ) {

            reason =

                `normal service port ${destinationPort}`;

        }


        else if (
            broadcastOrMulticast
        ) {

            reason =

                `broadcast/multicast destination ${destinationIP}`;

        }


        else if (
            !internalDestination
        ) {

            reason =

                `external destination ${destinationIP}`;

        }


        console.log(

            `HORIZONTAL SCAN SKIPPED: ${reason}`

        );

    }


    // ========================================================
    // DETERMINE SCAN TYPE
    // ========================================================

    let scanType =
        null;


    if (

        vertical.detected &&

        horizontal.detected

    ) {

        scanType =
            "MIXED_PORT_SCAN";

    }


    else if (

        vertical.detected

    ) {

        scanType =
            "VERTICAL_PORT_SCAN";

    }


    else if (

        horizontal.detected

    ) {

        scanType =
            "HORIZONTAL_PORT_SCAN";

    }


    const detected =

        vertical.detected ||

        horizontal.detected;


    const shouldAlert =

        vertical.shouldAlert ||

        horizontal.shouldAlert;


    // ========================================================
    // DETECTION LOGGING
    // ========================================================

    if (
        shouldAlert
    ) {

        console.log(
            "\n=========================================="
        );

        console.log(
            "PORT SCAN DETECTOR TRIGGERED"
        );

        console.log(
            "Source:",
            sourceIP
        );

        console.log(
            "Destination:",
            destinationIP
        );

        console.log(
            "Protocol:",
            protocol
        );

        console.log(
            "Firewall Action:",
            action
        );

        console.log(
            "Scan Type:",
            scanType
        );

        console.log(
            "Unique Ports:",
            vertical.uniquePorts
        );

        console.log(
            "Ports:",
            vertical.ports
        );

        console.log(
            "Unique Hosts:",
            horizontal.uniqueHosts
        );

        console.log(
            "Hosts:",
            horizontal.hosts
        );

        console.log(
            "==========================================\n"
        );

    }


    // ========================================================
    // RETURN EVIDENCE TO SIEM PIPELINE
    // ========================================================

    return {

        detected,

        shouldAlert,

        scanType,

        sourceIP,

        destinationIP,

        sourcePort,

        destinationPort,

        protocol,

        action,


        // Vertical evidence

        uniquePorts:
            vertical.uniquePorts,

        ports:
            vertical.ports,


        // Horizontal evidence

        uniqueHosts:
            horizontal.uniqueHosts,

        hosts:
            horizontal.hosts,


        // Detection configuration

        threshold: {

            verticalPorts:

                CONFIG
                    .VERTICAL_PORT_THRESHOLD,

            horizontalHosts:

                CONFIG
                    .HORIZONTAL_HOST_THRESHOLD

        },


        windowSeconds:

            CONFIG.WINDOW_MS /
            1000,


        /*
         * For vertical scans use vertical timestamps.
         * For horizontal-only scans use horizontal timestamps.
         */

        firstSeen:

            horizontal.detected &&
            !vertical.detected

                ? horizontal.firstSeen

                : vertical.firstSeen,


        lastSeen:

            horizontal.detected &&
            !vertical.detected

                ? horizontal.lastSeen

                : vertical.lastSeen,


        detectedAt:

            detected

                ? new Date()

                : null

    };

}


// ============================================================
// EXPORT
// ============================================================

module.exports =
    detectPortScan;
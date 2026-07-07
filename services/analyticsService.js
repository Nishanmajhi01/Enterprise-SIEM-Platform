const Incident = require("../models/Incident");
const { Op } = require("sequelize");

/**
 * =========================================
 * 🟢 SOC ANALYTICS SERVICE (INDUSTRIAL)
 * =========================================
 */

/**
 * 📊 1. SOC OVERVIEW KPIs
 */
exports.getSOCOverview = async () => {

    const totalIncidents = await Incident.count();

    const openIncidents = await Incident.count({
        where: { status: "OPEN" }
    });

    const closedIncidents = await Incident.count({
        where: { status: "CLOSED" }
    });

    const critical = await Incident.count({
        where: { severity: "CRITICAL" }
    });

    const high = await Incident.count({
        where: { severity: "HIGH" }
    });

    const medium = await Incident.count({
        where: { severity: "MEDIUM" }
    });

    return {
        totalIncidents,
        openIncidents,
        closedIncidents,
        severityBreakdown: {
            critical,
            high,
            medium
        }
    };
};


/**
 * ⏱️ 2. ATTACK TIMELINE (HOURLY BUCKET)
 */
exports.getAttackTimeline = async () => {

    const incidents = await Incident.findAll({
        attributes: ["createdAt"]
    });

    const timeline = {};

    incidents.forEach(i => {

        const hourBucket = new Date(i.createdAt)
            .toISOString()
            .substring(0, 13); // YYYY-MM-DDTHH

        timeline[hourBucket] = (timeline[hourBucket] || 0) + 1;
    });

    return timeline;
};


/**
 * 🎯 3. TOP ATTACKING IPs
 */
exports.getTopAttackers = async () => {

    const incidents = await Incident.findAll({
        attributes: ["sourceIP"]
    });

    const map = {};

    incidents.forEach(i => {
        if (!i.sourceIP) return;

        map[i.sourceIP] = (map[i.sourceIP] || 0) + 1;
    });

    return Object.entries(map)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));
};


/**
 * 🧠 4. MITRE TECHNIQUE DISTRIBUTION
 */
exports.getMITREStats = async () => {

    const incidents = await Incident.findAll({
        attributes: ["attackType"]
    });

    const mitreMap = {};

    incidents.forEach(i => {

        const key = i.attackType || "UNKNOWN";
        mitreMap[key] = (mitreMap[key] || 0) + 1;
    });

    return Object.entries(mitreMap)
        .sort((a, b) => b[1] - a[1])
        .map(([technique, count]) => ({
            technique,
            count
        }));
};


/**
 * 🔥 5. RISK DISTRIBUTION (HEATMAP STYLE)
 */
exports.getRiskDistribution = async () => {

    const incidents = await Incident.findAll({
        attributes: ["severity"]
    });

    const risk = {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0
    };

    incidents.forEach(i => {
        if (risk[i.severity] !== undefined) {
            risk[i.severity]++;
        }
    });

    return risk;
};


/**
 * 🚀 6. FULL DASHBOARD API WRAPPER
 */
exports.getDashboardData = async () => {

    const overview = await exports.getSOCOverview();
    const timeline = await exports.getAttackTimeline();
    const attackers = await exports.getTopAttackers();
    const mitre = await exports.getMITREStats();
    const risk = await exports.getRiskDistribution();

    return {
        overview,
        timeline,
        attackers,
        mitre,
        risk,
        generatedAt: new Date()
    };
};
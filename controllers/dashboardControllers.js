const IOC = require("../models/IOC");
const Incident = require("../models/Incident");
const Event = require("../models/Event");

exports.getDashboardStats = async (req, res) => {

    try {

        const totalIOCs = await IOC.count();
        const totalIncidents = await Incident.count();

        const openIncidents = await Incident.count({
            where: { status: "OPEN" }
        });

        const criticalIncidents = await Incident.count({
            where: { severity: "CRITICAL" }
        });

        const highRiskEvents = await Event.count({
            where: { riskScore: { [require("sequelize").Op.gte]: 70 } }
        });

        res.json({
            totalIOCs,
            totalIncidents,
            openIncidents,
            criticalIncidents,
            highRiskEvents,
            systemStatus: "ACTIVE",
            riskLevel:
                criticalIncidents > 5 ? "HIGH" :
                openIncidents > 10 ? "MEDIUM" : "LOW"
        });

    } catch (error) {
        res.status(500).json({
            error: error.message
        });
    }
};
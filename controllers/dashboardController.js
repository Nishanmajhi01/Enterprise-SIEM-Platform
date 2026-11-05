const { Op, fn, col } = require("sequelize");
const IOC = require("../models/IOC");
const Incident = require("../models/Incident");
const SecurityEvent = require("../models/SecurityEvent");
const ThreatIntel = require("../models/ThreatIntel");

exports.getDashboardStats = async (req, res) => {
  try {
    const workspaceId = req.workspaceId;
    if (!workspaceId || !req.workspaceMembership) {
      return res.status(403).json({ message: "Verified workspace required" });
    }
    const scope = { workspaceId };
    const [
      totalIOCs, maliciousIOCs, totalThreats, criticalThreats, highThreats,
      totalIncidents, openIncidents, highRiskEvents, topAttackers, attackTypes
    ] = await Promise.all([
      IOC.count({ where: scope }),
      IOC.count({ where: { ...scope, reputation: "MALICIOUS" } }),
      ThreatIntel.count({ where: scope }),
      ThreatIntel.count({ where: { ...scope, severity: "CRITICAL" } }),
      ThreatIntel.count({ where: { ...scope, severity: "HIGH" } }),
      Incident.count({ where: scope }),
      Incident.count({ where: { ...scope, status: "OPEN" } }),
      SecurityEvent.count({ where: { ...scope, riskScore: { [Op.gte]: 70 } } }),
      SecurityEvent.findAll({
        where: scope,
        attributes: ["sourceIP", [fn("COUNT", col("sourceIP")), "count"]],
        group: ["sourceIP"],
        order: [[fn("COUNT", col("sourceIP")), "DESC"]],
        limit: 5
      }),
      SecurityEvent.findAll({
        where: scope,
        attributes: ["attackType", [fn("COUNT", col("attackType")), "count"]],
        group: ["attackType"]
      })
    ]);
    return res.json({
      systemStatus: "ACTIVE",
      threatIntelligence: { totalThreats, criticalThreats, highThreats },
      ioc: { totalIOCs, maliciousIOCs },
      incidents: { totalIncidents, openIncidents },
      highRiskEvents, topAttackers, attackTypes
    });
  } catch (error) {
    console.error("Dashboard metrics failed:", error);
    return res.status(500).json({ message: "Unable to load dashboard metrics" });
  }
};

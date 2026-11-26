"use strict";
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async transaction => {
      await queryInterface.addColumn("Alerts", "destinationIP", {
        type: Sequelize.STRING, allowNull: true
      }, { transaction });
      await queryInterface.sequelize.query(`
        UPDATE "Alerts" a SET "destinationIP" = i.evidence->0->>'destinationIP'
        FROM "Incidents" i
        WHERE a."incidentId" = i.id
          AND a."workspaceId" = i."workspaceId"
          AND a."attackType" = 'DDOS'
          AND i."attackType" = 'DDOS'
          AND i.evidence->0->>'type' = 'DDOS_V2_DETECTION'
          AND i.evidence->0->>'sourceIP' = a."sourceIP"
          AND NULLIF(i.evidence->0->>'destinationIP', '') IS NOT NULL
      `, { transaction });
    });
  },
  async down(queryInterface) {
    await queryInterface.removeColumn("Alerts", "destinationIP");
  }
};

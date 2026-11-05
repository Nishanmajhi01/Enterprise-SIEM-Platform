"use strict";

const TABLES = [
  "Evidence",
  "IncidentAssignments",
  "IncidentComments",
  "Investigations",
  "ResponseActions"
];

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const db = queryInterface.sequelize;

      for (const table of TABLES) {
        const [before] = await db.query(
          `SELECT COUNT(*)::integer AS total FROM "${table}"`,
          { transaction }
        );

        await queryInterface.addColumn(
          table,
          "workspaceId",
          {
            type: Sequelize.UUID,
            allowNull: true,
            references: {
              model: "Workspaces",
              key: "id"
            },
            onUpdate: "CASCADE",
            onDelete: "RESTRICT"
          },
          { transaction }
        );

        await db.query(
          `UPDATE "${table}" AS child
           SET "workspaceId" = parent."workspaceId"
           FROM "Incidents" AS parent
           WHERE child."incidentId" = parent.id`,
          { transaction }
        );

        const [after] = await db.query(
          `SELECT
             COUNT(*)::integer AS total,
             COUNT(*) FILTER (
               WHERE child."workspaceId" IS NULL
             )::integer AS unassigned,
             COUNT(*) FILTER (
               WHERE parent.id IS NULL
                  OR child."workspaceId"
                     IS DISTINCT FROM parent."workspaceId"
             )::integer AS mismatched
           FROM "${table}" AS child
           LEFT JOIN "Incidents" AS parent
             ON parent.id = child."incidentId"`,
          { transaction }
        );

        if (
          before[0].total !== after[0].total ||
          after[0].unassigned !== 0 ||
          after[0].mismatched !== 0
        ) {
          throw new Error(
            `Workspace validation failed for ${table}: ` +
            JSON.stringify(after[0])
          );
        }

        await queryInterface.changeColumn(
          table,
          "workspaceId",
          {
            type: Sequelize.UUID,
            allowNull: false,
            references: {
              model: "Workspaces",
              key: "id"
            },
            onUpdate: "CASCADE",
            onDelete: "RESTRICT"
          },
          { transaction }
        );

        await queryInterface.addIndex(
          table,
          ["workspaceId", "incidentId"],
          {
            name: `${table.toLowerCase()}_workspace_incident_idx`,
            transaction
          }
        );
      }
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      for (const table of [...TABLES].reverse()) {
        await queryInterface.removeColumn(
          table,
          "workspaceId",
          { transaction }
        );
      }
    });
  }
};

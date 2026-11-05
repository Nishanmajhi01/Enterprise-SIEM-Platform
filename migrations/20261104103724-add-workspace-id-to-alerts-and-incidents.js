"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const [workspaces] = await queryInterface.sequelize.query(
        `SELECT id FROM "Workspaces" WHERE slug = 'legacy-siem'`,
        { transaction }
      );

      if (workspaces.length !== 1) {
        throw new Error(
          "Migration stopped: exactly one legacy workspace is required"
        );
      }

      const legacyWorkspaceId = workspaces[0].id;

      for (const table of ["Alerts", "Incidents"]) {
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

        await queryInterface.sequelize.query(
          `UPDATE "${table}"
           SET "workspaceId" = :legacyWorkspaceId
           WHERE "workspaceId" IS NULL`,
          {
            replacements: { legacyWorkspaceId },
            transaction
          }
        );
      }

      const [checks] = await queryInterface.sequelize.query(
        `SELECT
          (SELECT COUNT(*) FROM "Alerts"
           WHERE "workspaceId" IS NULL)::integer
           AS unassigned_alerts,

          (SELECT COUNT(*) FROM "Incidents"
           WHERE "workspaceId" IS NULL)::integer
           AS unassigned_incidents,

          (SELECT COUNT(*)
           FROM "Alerts" a
           JOIN "Incidents" i ON i.id = a."incidentId"
           WHERE a."workspaceId" IS DISTINCT FROM i."workspaceId"
          )::integer AS mismatched_alerts,

          (SELECT COUNT(*)
           FROM "Incidents" i
           JOIN "Alerts" a ON a.id = i."alertId"
           WHERE i."workspaceId" IS DISTINCT FROM a."workspaceId"
          )::integer AS mismatched_incidents`,
        { transaction }
      );

      if (Object.values(checks[0]).some(value => value !== 0)) {
        throw new Error(
          `Workspace validation failed: ${JSON.stringify(checks[0])}`
        );
      }

      for (const table of ["Alerts", "Incidents"]) {
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
          ["workspaceId", "createdAt"],
          {
            name: `${table.toLowerCase()}_workspace_created_idx`,
            transaction
          }
        );
      }
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      for (const table of ["Alerts", "Incidents"]) {
        await queryInterface.removeColumn(
          table,
          "workspaceId",
          { transaction }
        );
      }
    });
  }
};

"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const [workspaces] = await queryInterface.sequelize.query(
        `SELECT id FROM "Workspaces" WHERE slug = 'legacy-siem'`,
        { transaction }
      );

      if (workspaces.length !== 1) {
        throw new Error("Exactly one legacy workspace is required");
      }

      const legacyWorkspaceId = workspaces[0].id;

      await queryInterface.addColumn(
        "SecurityEvents",
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

      // Assign device-linked events to their device's workspace.
      await queryInterface.sequelize.query(
        `UPDATE "SecurityEvents" AS e
         SET "workspaceId" = d."workspaceId"
         FROM "Devices" AS d
         WHERE e."deviceId" = d.id
           AND e."workspaceId" IS NULL`,
        { transaction }
      );

      // Historical exception: device-less events in the legacy backup.
      await queryInterface.sequelize.query(
        `UPDATE "SecurityEvents"
         SET "workspaceId" = :legacyWorkspaceId
         WHERE "deviceId" IS NULL
           AND "workspaceId" IS NULL`,
        {
          replacements: { legacyWorkspaceId },
          transaction
        }
      );

      const [checks] = await queryInterface.sequelize.query(
        `SELECT
           COUNT(*) FILTER (
             WHERE e."workspaceId" IS NULL
           )::integer AS unassigned,
           COUNT(*) FILTER (
             WHERE e."deviceId" IS NOT NULL
               AND (
                 d.id IS NULL
                 OR e."workspaceId" IS DISTINCT FROM d."workspaceId"
               )
           )::integer AS mismatched
         FROM "SecurityEvents" e
         LEFT JOIN "Devices" d ON d.id = e."deviceId"`,
        { transaction }
      );

      if (checks[0].unassigned !== 0 || checks[0].mismatched !== 0) {
        throw new Error(
          `Workspace backfill failed: ${JSON.stringify(checks[0])}`
        );
      }

      await queryInterface.changeColumn(
        "SecurityEvents",
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
        "SecurityEvents",
        ["workspaceId", "timestamp"],
        {
          name: "security_events_workspace_timestamp_idx",
          transaction
        }
      );

      await queryInterface.addIndex(
        "SecurityEvents",
        ["workspaceId", "deviceId"],
        {
          name: "security_events_workspace_device_idx",
          transaction
        }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.removeColumn(
        "SecurityEvents",
        "workspaceId",
        { transaction }
      );
    });
  }
};

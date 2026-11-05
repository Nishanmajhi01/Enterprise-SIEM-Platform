"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const db = queryInterface.sequelize;

      const [workspaces] = await db.query(
        `SELECT id FROM "Workspaces"
         WHERE slug = 'legacy-siem'`,
        { transaction }
      );

      if (workspaces.length !== 1) {
        throw new Error(
          "Expected exactly one legacy-siem workspace"
        );
      }

      const workspaceId = workspaces[0].id;

      const [before] = await db.query(
        `SELECT COUNT(*)::integer AS total
         FROM "ThreatIntels"`,
        { transaction }
      );

      await queryInterface.addColumn(
        "ThreatIntels",
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
        `UPDATE "ThreatIntels"
         SET "workspaceId" = :workspaceId
         WHERE "workspaceId" IS NULL`,
        {
          replacements: { workspaceId },
          transaction
        }
      );

      const [after] = await db.query(
        `SELECT
           COUNT(*)::integer AS total,
           COUNT(*) FILTER (
             WHERE "workspaceId" IS NULL
           )::integer AS unassigned,
           COUNT(*) FILTER (
             WHERE "workspaceId" <> :workspaceId
           )::integer AS incorrect_workspace
         FROM "ThreatIntels"`,
        {
          replacements: { workspaceId },
          transaction
        }
      );

      if (
        before[0].total !== after[0].total ||
        after[0].unassigned !== 0 ||
        after[0].incorrect_workspace !== 0
      ) {
        throw new Error(
          "ThreatIntels workspace validation failed: " +
          JSON.stringify(after[0])
        );
      }

      await queryInterface.changeColumn(
        "ThreatIntels",
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
        "ThreatIntels",
        ["workspaceId"],
        {
          name: "threatintels_workspace_idx",
          transaction
        }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.removeColumn(
        "ThreatIntels",
        "workspaceId",
        { transaction }
      );
    });
  }
};

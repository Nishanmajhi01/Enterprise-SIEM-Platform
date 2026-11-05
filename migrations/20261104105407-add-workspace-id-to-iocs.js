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
        `SELECT COUNT(*)::integer AS total FROM "IOCs"`,
        { transaction }
      );

      await queryInterface.addColumn(
        "IOCs",
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
        `UPDATE "IOCs"
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
         FROM "IOCs"`,
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
          "IOC workspace validation failed: " +
          JSON.stringify(after[0])
        );
      }

      await queryInterface.changeColumn(
        "IOCs",
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
        "IOCs",
        ["workspaceId"],
        {
          name: "iocs_workspace_idx",
          transaction
        }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.removeColumn(
        "IOCs",
        "workspaceId",
        { transaction }
      );
    });
  }
};

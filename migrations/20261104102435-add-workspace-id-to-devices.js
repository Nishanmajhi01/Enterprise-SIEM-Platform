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
          "Migration stopped: exactly one legacy-siem workspace is required"
        );
      }

      await queryInterface.addColumn(
        "Devices",
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
        `UPDATE "Devices"
         SET "workspaceId" = :workspaceId
         WHERE "workspaceId" IS NULL`,
        {
          replacements: {
            workspaceId: workspaces[0].id
          },
          transaction
        }
      );

      await queryInterface.changeColumn(
        "Devices",
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
        "Devices",
        ["workspaceId"],
        {
          name: "devices_workspace_id_idx",
          transaction
        }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.removeColumn(
        "Devices",
        "workspaceId",
        { transaction }
      );
    });
  }
};

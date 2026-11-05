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

      const [before] = await queryInterface.sequelize.query(
        `SELECT
          COUNT(*)::integer AS total,
          COUNT(*) FILTER (WHERE enabled = TRUE)::integer AS enabled,
          COUNT(*) FILTER (WHERE enabled = FALSE)::integer AS disabled,
          COUNT(*) FILTER (WHERE enabled IS NULL)::integer AS unknown
         FROM "ResponsePlaybooks"`,
        { transaction }
      );

      await queryInterface.addColumn(
        "ResponsePlaybooks",
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
        `UPDATE "ResponsePlaybooks"
         SET "workspaceId" = :workspaceId
         WHERE "workspaceId" IS NULL`,
        {
          replacements: { workspaceId: legacyWorkspaceId },
          transaction
        }
      );

      const [after] = await queryInterface.sequelize.query(
        `SELECT
          COUNT(*)::integer AS total,
          COUNT(*) FILTER (WHERE enabled = TRUE)::integer AS enabled,
          COUNT(*) FILTER (WHERE enabled = FALSE)::integer AS disabled,
          COUNT(*) FILTER (WHERE enabled IS NULL)::integer AS unknown,
          COUNT(*) FILTER (WHERE "workspaceId" IS NULL)::integer AS unassigned,
          COUNT(*) FILTER (
            WHERE "workspaceId" IS DISTINCT FROM :workspaceId
          )::integer AS incorrect_workspace
         FROM "ResponsePlaybooks"`,
        {
          replacements: { workspaceId: legacyWorkspaceId },
          transaction
        }
      );

      for (const field of ["total", "enabled", "disabled", "unknown"]) {
        if (before[0][field] !== after[0][field]) {
          throw new Error(
            `Playbook validation failed: ${field} changed`
          );
        }
      }

      if (
        after[0].unassigned !== 0 ||
        after[0].incorrect_workspace !== 0
      ) {
        throw new Error(
          "Playbook workspace validation failed"
        );
      }

      await queryInterface.changeColumn(
        "ResponsePlaybooks",
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
        "ResponsePlaybooks",
        ["workspaceId", "triggerType", "severity"],
        {
          name: "response_playbooks_workspace_trigger_severity_idx",
          transaction
        }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.removeColumn(
        "ResponsePlaybooks",
        "workspaceId",
        { transaction }
      );
    });
  }
};

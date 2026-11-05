"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      const db = queryInterface.sequelize;

      const [before] = await db.query(
        `SELECT COUNT(*)::integer AS total
         FROM "IOCMatches"`,
        { transaction }
      );

      await queryInterface.addColumn(
        "IOCMatches",
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
        `UPDATE "IOCMatches" AS m
         SET "workspaceId" = e."workspaceId"
         FROM "SecurityEvents" AS e
         WHERE m."securityEventId" = e.id`,
        { transaction }
      );

      const [after] = await db.query(
        `SELECT
           COUNT(*)::integer AS total,

           COUNT(*) FILTER (
             WHERE m."workspaceId" IS NULL
           )::integer AS unassigned,

           COUNT(*) FILTER (
             WHERE e.id IS NULL
                OR i.id IS NULL
                OR m."workspaceId"
                   IS DISTINCT FROM e."workspaceId"
                OR m."workspaceId"
                   IS DISTINCT FROM i."workspaceId"
           )::integer AS mismatched

         FROM "IOCMatches" AS m

         LEFT JOIN "SecurityEvents" AS e
           ON e.id = m."securityEventId"

         LEFT JOIN "IOCs" AS i
           ON i.id = m."iocId"`,
        { transaction }
      );

      if (
        before[0].total !== after[0].total ||
        after[0].unassigned !== 0 ||
        after[0].mismatched !== 0
      ) {
        throw new Error(
          "IOCMatches workspace validation failed: " +
          JSON.stringify(after[0])
        );
      }

      await queryInterface.changeColumn(
        "IOCMatches",
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
        "IOCMatches",
        ["workspaceId", "securityEventId"],
        {
          name: "iocmatches_workspace_event_idx",
          transaction
        }
      );

      await queryInterface.addIndex(
        "IOCMatches",
        ["workspaceId", "iocId"],
        {
          name: "iocmatches_workspace_ioc_idx",
          transaction
        }
      );
    });
  },

  async down(queryInterface) {
    await queryInterface.sequelize.transaction(async (transaction) => {
      await queryInterface.removeColumn(
        "IOCMatches",
        "workspaceId",
        { transaction }
      );
    });
  }
};

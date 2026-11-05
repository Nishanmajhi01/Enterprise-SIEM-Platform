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
        `SELECT
           COUNT(*)::integer AS total,
           COUNT(*) FILTER (
             WHERE "userId" IS NULL
           )::integer AS without_user
         FROM "AuditLogs"`,
        { transaction }
      );

      // Preserve platform authentication history separately.
      // Run inside the same transaction as the workspace migration.
      const [authBefore] = await db.query(
        `SELECT
           COUNT(*)::integer AS total,
           COUNT(*) FILTER (
             WHERE "userId" IS NULL
           )::integer AS without_user
         FROM "AuditLogs"
         WHERE "module" = 'AUTH'`,
        { transaction }
      );

      // Historical transfer requires an empty platform audit table.
      // Never mix migrated records with existing platform audit history.
      const [platformBefore] = await db.query(
        `SELECT COUNT(*)::integer AS total
         FROM "PlatformAuditLogs"`,
        { transaction }
      );

      if (platformBefore[0].total !== 0) {
        throw new Error(
          "PlatformAuditLogs is not empty; historical transfer blocked"
        );
      }

      await db.query(
        `INSERT INTO "PlatformAuditLogs"
         ("sourceAuditLogId", "userId", "username",
          "action", "module", "severity", "ipAddress",
          "description", "metadata", "createdAt", "updatedAt")
         SELECT
          "id", "userId", "username",
          "action", "module", COALESCE("severity", 'LOW'),
          "ipAddress", "description",
          COALESCE("metadata", '{}'::json),
          "createdAt", "updatedAt"
         FROM "AuditLogs"
         WHERE "module" = 'AUTH'`,
        { transaction }
      );

      const [authAfter] = await db.query(
        `SELECT COUNT(*)::integer AS total
         FROM "PlatformAuditLogs"`,
        { transaction }
      );

      if (authBefore[0].total !== authAfter[0].total) {
        throw new Error(
          "Platform audit transfer count mismatch"
        );
      }

      // Verify every historical authentication record before deletion.
      const [verification] = await db.query(
        `SELECT
           COUNT(*)::integer AS mismatches
         FROM "AuditLogs" a
         LEFT JOIN "PlatformAuditLogs" p
           ON p."sourceAuditLogId" = a."id"
         WHERE a."module" = 'AUTH'
           AND (
             p."id" IS NULL
             OR a."userId" IS DISTINCT FROM p."userId"
             OR a."username" IS DISTINCT FROM p."username"
             OR a."action" IS DISTINCT FROM p."action"
             OR a."module" IS DISTINCT FROM p."module"
             OR COALESCE(a."severity", 'LOW')
                IS DISTINCT FROM p."severity"
             OR a."ipAddress" IS DISTINCT FROM p."ipAddress"
             OR a."description" IS DISTINCT FROM p."description"
             OR COALESCE(a."metadata"::jsonb, '{}'::jsonb)
                IS DISTINCT FROM p."metadata"::jsonb
             OR a."createdAt" IS DISTINCT FROM p."createdAt"
             OR a."updatedAt" IS DISTINCT FROM p."updatedAt"
           )`,
        { transaction }
      );

      if (verification[0].mismatches !== 0) {
        throw new Error(
          "Platform audit record verification failed: " +
          verification[0].mismatches + " mismatches"
        );
      }

      await db.query(
        `DELETE FROM "AuditLogs"
         WHERE "module" = 'AUTH'`,
        { transaction }
      );

      await queryInterface.addColumn(
        "AuditLogs",
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
        `UPDATE "AuditLogs"
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
             WHERE "userId" IS NULL
           )::integer AS without_user,
           COUNT(*) FILTER (
             WHERE "workspaceId" IS NULL
           )::integer AS unassigned,
           COUNT(*) FILTER (
             WHERE "workspaceId" IS DISTINCT FROM :workspaceId
           )::integer AS incorrect_workspace
         FROM "AuditLogs"`,
        {
          replacements: { workspaceId },
          transaction
        }
      );

      if (
        before[0].total !==
          after[0].total + authBefore[0].total ||
        before[0].without_user !==
          after[0].without_user + authBefore[0].without_user ||
        after[0].unassigned !== 0 ||
        after[0].incorrect_workspace !== 0
      ) {
        throw new Error(
          "AuditLogs workspace validation failed: " +
          JSON.stringify(after[0])
        );
      }

      await queryInterface.changeColumn(
        "AuditLogs",
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
        "AuditLogs",
        ["workspaceId", "createdAt"],
        {
          name: "auditlogs_workspace_created_idx",
          transaction
        }
      );
    });
  },

  async down() {
    throw new Error(
      "Audit migration rollback blocked: platform audit records " +
      "must be safely restored and verified before removing workspaceId."
    );
  }
};

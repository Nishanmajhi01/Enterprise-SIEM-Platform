"use strict";

const { randomUUID } = require("crypto");

module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.sequelize.transaction(async (transaction) => {

            const [existing] = await queryInterface.sequelize.query(
                `SELECT id FROM "Workspaces"
                 WHERE slug = 'legacy-siem'`,
                { transaction }
            );

            if (existing.length !== 0) {
                throw new Error(
                    "Legacy workspace already exists. Stopping safely."
                );
            }

            const now = new Date();
            const workspaceId = randomUUID();

            await queryInterface.bulkInsert("Workspaces", [{
                id: workspaceId,
                name: "Legacy SIEM Workspace",
                slug: "legacy-siem",
                type: "ORGANIZATION",
                status: "ACTIVE",
                createdAt: now,
                updatedAt: now
            }], { transaction });

            const [users] = await queryInterface.sequelize.query(
                `SELECT id, role FROM "Users" ORDER BY id`,
                { transaction }
            );

            if (users.length === 0) {
                throw new Error("No existing users found.");
            }

            const validRoles = ["ADMIN", "ANALYST", "VIEWER"];

            const memberships = users.map(user => ({
                id: randomUUID(),
                workspaceId,
                userId: user.id,
                role: validRoles.includes(user.role)
                    ? user.role
                    : "VIEWER",
                status: "ACTIVE",
                createdAt: now,
                updatedAt: now
            }));

            await queryInterface.bulkInsert(
                "WorkspaceMemberships",
                memberships,
                { transaction }
            );

            const [verification] = await queryInterface.sequelize.query(
                `SELECT
                    COUNT(*)::integer AS total,
                    COUNT(*) FILTER (
                        WHERE status = 'ACTIVE'
                    )::integer AS active,
                    COUNT(DISTINCT "userId")::integer AS unique_users
                 FROM "WorkspaceMemberships"
                 WHERE "workspaceId" = :workspaceId`,
                {
                    replacements: { workspaceId },
                    transaction
                }
            );

            const result = verification[0];

            if (
                result.total !== users.length ||
                result.active !== users.length ||
                result.unique_users !== users.length
            ) {
                throw new Error(
                    "Workspace membership verification failed."
                );
            }

            console.log("LEGACY WORKSPACE CREATED");
            console.log("Users:", users.length);
            console.log("Active memberships:", result.active);
        });
    },

    async down(queryInterface) {
        await queryInterface.sequelize.transaction(async (transaction) => {
            const [workspaces] = await queryInterface.sequelize.query(
                `SELECT id FROM "Workspaces"
                 WHERE slug = 'legacy-siem'`,
                { transaction }
            );

            if (workspaces.length === 0) return;

            const workspaceId = workspaces[0].id;

            await queryInterface.bulkDelete(
                "WorkspaceMemberships",
                { workspaceId },
                { transaction }
            );

            await queryInterface.bulkDelete(
                "Workspaces",
                { id: workspaceId },
                { transaction }
            );
        });
    }
};

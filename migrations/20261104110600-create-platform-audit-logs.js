"use strict";

module.exports = {
    async up(queryInterface, Sequelize) {
        await queryInterface.sequelize.transaction(
            async (transaction) => {
                await queryInterface.createTable(
                    "PlatformAuditLogs",
                    {
                        id: {
                            type: Sequelize.INTEGER,
                            autoIncrement: true,
                            primaryKey: true,
                            allowNull: false
                        },
                        sourceAuditLogId: {
                            type: Sequelize.INTEGER,
                            allowNull: true,
                            unique: true
                        },

                        userId: {
                            type: Sequelize.INTEGER,
                            allowNull: true
                        },
                        username: {
                            type: Sequelize.STRING,
                            allowNull: true
                        },
                        action: {
                            type: Sequelize.STRING,
                            allowNull: false
                        },
                        module: {
                            type: Sequelize.STRING,
                            allowNull: false,
                            defaultValue: "AUTH"
                        },
                        severity: {
                            type: Sequelize.STRING,
                            allowNull: false,
                            defaultValue: "LOW"
                        },
                        ipAddress: {
                            type: Sequelize.STRING,
                            allowNull: true
                        },
                        description: {
                            type: Sequelize.TEXT,
                            allowNull: true
                        },
                        metadata: {
                            type: Sequelize.JSON,
                            allowNull: false,
                            defaultValue: {}
                        },
                        createdAt: {
                            type: Sequelize.DATE,
                            allowNull: false
                        },
                        updatedAt: {
                            type: Sequelize.DATE,
                            allowNull: false
                        }
                    },
                    { transaction }
                );

                await queryInterface.addIndex(
                    "PlatformAuditLogs",
                    ["createdAt"],
                    {
                        name: "platform_audit_created_idx",
                        transaction
                    }
                );
            }
        );
    },

    async down(queryInterface) {
        await queryInterface.sequelize.transaction(
            async (transaction) => {
                const [result] = await queryInterface.sequelize.query(
                    `SELECT COUNT(*)::integer AS total
                     FROM "PlatformAuditLogs"`,
                    { transaction }
                );

                if (result[0].total !== 0) {
                    throw new Error(
                        "PlatformAuditLogs contains records; " +
                        "rollback blocked to prevent audit history loss"
                    );
                }

                await queryInterface.dropTable(
                    "PlatformAuditLogs",
                    { transaction }
                );
            }
        );
    }
};

"use strict";
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable("EmailActionTokens", {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      tokenHash: { type: Sequelize.STRING(64), unique: true, allowNull: false },
      purpose: { type: Sequelize.ENUM("VERIFY_EMAIL", "INVITE", "RESET_PASSWORD"), allowNull: false },
      email: { type: Sequelize.STRING(254), allowNull: false },
      userId: { type: Sequelize.INTEGER, allowNull: true, references: { model: "Users", key: "id" }, onDelete: "CASCADE" },
      workspaceId: { type: Sequelize.UUID, allowNull: true, references: { model: "Workspaces", key: "id" }, onDelete: "CASCADE" },
      workspaceRole: { type: Sequelize.ENUM("ADMIN", "ANALYST", "VIEWER"), allowNull: true },
      expiresAt: { type: Sequelize.DATE, allowNull: false },
      consumedAt: { type: Sequelize.DATE, allowNull: true },
      createdAt: { type: Sequelize.DATE, allowNull: false },
      updatedAt: { type: Sequelize.DATE, allowNull: false }
    });
    await queryInterface.addIndex("EmailActionTokens", ["email", "purpose"]);
    await queryInterface.addIndex("EmailActionTokens", ["expiresAt"]);
  },
  async down(queryInterface) {
    await queryInterface.dropTable("EmailActionTokens");
    // PostgreSQL enum types are managed by Sequelize; leave shared enum cleanup to DBA.
  }
};

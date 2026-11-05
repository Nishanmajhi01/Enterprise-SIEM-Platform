"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable("Workspaces", {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false
      },

      name: {
        type: Sequelize.STRING(150),
        allowNull: false
      },

      slug: {
        type: Sequelize.STRING(150),
        allowNull: false,
        unique: true
      },

      type: {
        type: Sequelize.ENUM("PERSONAL", "ORGANIZATION"),
        allowNull: false,
        defaultValue: "ORGANIZATION"
      },

      status: {
        type: Sequelize.ENUM("ACTIVE", "SUSPENDED"),
        allowNull: false,
        defaultValue: "ACTIVE"
      },

      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW
      },

      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
        defaultValue: Sequelize.NOW
      }
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable("Workspaces");
    await queryInterface.sequelize.query(
      'DROP TYPE IF EXISTS "enum_Workspaces_type";'
    );
    await queryInterface.sequelize.query(
      'DROP TYPE IF EXISTS "enum_Workspaces_status";'
    );
  }
};

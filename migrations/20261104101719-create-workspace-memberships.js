"use strict";

module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable("WorkspaceMemberships", {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        allowNull: false,
        primaryKey: true
      },

      workspaceId: {
        type: Sequelize.UUID,
        allowNull: false,
        references: {
          model: "Workspaces",
          key: "id"
        },
        onUpdate: "CASCADE",
        onDelete: "CASCADE"
      },

      userId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: {
          model: "Users",
          key: "id"
        },
        onUpdate: "CASCADE",
        onDelete: "CASCADE"
      },

      role: {
        type: Sequelize.ENUM("ADMIN", "ANALYST", "VIEWER"),
        allowNull: false,
        defaultValue: "VIEWER"
      },

      status: {
        type: Sequelize.ENUM("ACTIVE", "INVITED", "SUSPENDED"),
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

    await queryInterface.addConstraint("WorkspaceMemberships", {
      fields: ["workspaceId", "userId"],
      type: "unique",
      name: "workspace_memberships_workspace_user_unique"
    });

    await queryInterface.addIndex("WorkspaceMemberships", ["userId"], {
      name: "workspace_memberships_user_idx"
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable("WorkspaceMemberships");

    await queryInterface.sequelize.query(
      'DROP TYPE IF EXISTS "enum_WorkspaceMemberships_role";'
    );

    await queryInterface.sequelize.query(
      'DROP TYPE IF EXISTS "enum_WorkspaceMemberships_status";'
    );
  }
};

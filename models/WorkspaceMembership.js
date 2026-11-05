"use strict";

const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

const WorkspaceMembership = sequelize.define(
  "WorkspaceMembership",
  {
    id: {
      type: DataTypes.UUID,
      primaryKey: true,
      allowNull: false
    },

    workspaceId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: "Workspaces",
        key: "id"
      }
    },

    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "Users",
        key: "id"
      }
    },

    role: {
      type: DataTypes.ENUM(
        "ADMIN",
        "ANALYST",
        "VIEWER"
      ),
      allowNull: false
    },

    status: {
      type: DataTypes.ENUM(
        "ACTIVE",
        "INVITED",
        "SUSPENDED"
      ),
      allowNull: false
    }
  },
  {
    tableName: "WorkspaceMemberships",
    timestamps: true,
    indexes: [
      {
        unique: true,
        fields: ["workspaceId", "userId"]
      }
    ]
  }
);

module.exports = WorkspaceMembership;

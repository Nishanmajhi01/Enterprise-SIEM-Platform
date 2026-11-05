"use strict";

const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

const Workspace = sequelize.define(
  "Workspace",
  {
    id: {
      type: DataTypes.UUID,
      primaryKey: true,
      allowNull: false
    },

    name: {
      type: DataTypes.STRING,
      allowNull: false
    },

    slug: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true
    },

    type: {
      type: DataTypes.ENUM(
        "PERSONAL",
        "ORGANIZATION"
      ),
      allowNull: false
    },

    status: {
      type: DataTypes.ENUM(
        "ACTIVE",
        "SUSPENDED"
      ),
      allowNull: false
    }
  },
  {
    tableName: "Workspaces",
    timestamps: true
  }
);

module.exports = Workspace;

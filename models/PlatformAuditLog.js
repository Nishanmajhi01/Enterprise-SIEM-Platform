"use strict";

const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

const PlatformAuditLog = sequelize.define(
    "PlatformAuditLog",
    {
        id: {
            type: DataTypes.INTEGER,
            autoIncrement: true,
            primaryKey: true
        },

        sourceAuditLogId: {
            type: DataTypes.INTEGER,
            allowNull: true,
            unique: true
        },

        userId: {
            type: DataTypes.INTEGER,
            allowNull: true
        },

        username: {
            type: DataTypes.STRING,
            allowNull: true
        },

        action: {
            type: DataTypes.STRING,
            allowNull: false
        },

        module: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: "AUTH"
        },

        severity: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: "LOW"
        },

        ipAddress: {
            type: DataTypes.STRING,
            allowNull: true
        },

        description: {
            type: DataTypes.TEXT,
            allowNull: true
        },

        metadata: {
            type: DataTypes.JSON,
            allowNull: false,
            defaultValue: {}
        }
    },
    {
        tableName: "PlatformAuditLogs",
        timestamps: true
    }
);

module.exports = PlatformAuditLog;

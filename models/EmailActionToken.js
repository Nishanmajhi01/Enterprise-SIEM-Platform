"use strict";
const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

// Raw email action tokens are never persisted. Only their SHA-256 digests.
const EmailActionToken = sequelize.define("EmailActionToken", {
  id: { type: DataTypes.UUID, primaryKey: true, allowNull: false },
  tokenHash: { type: DataTypes.STRING(64), unique: true, allowNull: false },
  purpose: { type: DataTypes.ENUM("VERIFY_EMAIL", "INVITE", "RESET_PASSWORD"), allowNull: false },
  email: { type: DataTypes.STRING(254), allowNull: false },
  userId: { type: DataTypes.INTEGER, allowNull: true },
  workspaceId: { type: DataTypes.UUID, allowNull: true },
  workspaceRole: { type: DataTypes.ENUM("ADMIN", "ANALYST", "VIEWER"), allowNull: true },
  expiresAt: { type: DataTypes.DATE, allowNull: false },
  consumedAt: { type: DataTypes.DATE, allowNull: true }
}, {
  tableName: "EmailActionTokens",
  timestamps: true,
  indexes: [{ fields: ["email", "purpose"] }, { fields: ["expiresAt"] }]
});
module.exports = EmailActionToken;

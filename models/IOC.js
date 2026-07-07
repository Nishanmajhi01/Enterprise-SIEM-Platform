const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

const IOC = sequelize.define("IOC", {

    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },

    type: {
        type: DataTypes.ENUM(
            "IP",
            "DOMAIN",
            "URL",
            "HASH",
            "EMAIL"
        ),
        allowNull: false
    },

    value: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },

    confidence: {
        type: DataTypes.ENUM(
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ),
        defaultValue: "MEDIUM"
    },

    source: {
        type: DataTypes.STRING,
        defaultValue: "Manual"
    },

    reputation: {
        type: DataTypes.STRING
    },

    firstSeen: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
    },

    lastSeen: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
    },

    isActive: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }

}, {

    timestamps: true

});

module.exports = IOC;
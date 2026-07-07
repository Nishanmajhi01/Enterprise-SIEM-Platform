const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

const Device = sequelize.define("Device", {

    id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },

    name: {
        type: DataTypes.STRING,
        allowNull: false
    },

    type: {
        type: DataTypes.ENUM("WINDOWS", "LINUX", "FIREWALL", "SERVER"),
        allowNull: false
    },

    ipAddress: {
        type: DataTypes.STRING,
        allowNull: false
    },

    apiKey: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },

    status: {
        type: DataTypes.ENUM("ACTIVE", "OFFLINE"),
        defaultValue: "ACTIVE"
    }

}, {
    timestamps: true
});

module.exports = Device;
const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");


const Alert = sequelize.define("Alert", {


    id: {

        type: DataTypes.INTEGER,

        autoIncrement: true,

        primaryKey: true

    },



    title: {

        type: DataTypes.STRING,

        allowNull: false

    },



    description: {

        type: DataTypes.TEXT

    },



    severity: {

        type: DataTypes.ENUM(
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ),

        defaultValue: "LOW"

    },



    status: {

        type: DataTypes.ENUM(
            "NEW",
            "ACKNOWLEDGED",
            "INVESTIGATING",
            "RESOLVED",
            "FALSE_POSITIVE",
            "CLOSED"
        ),

        defaultValue: "NEW"

    },



    sourceIP: {

        type: DataTypes.STRING,

        allowNull:true

    },



    attackType: {

        type: DataTypes.STRING

    },


    incidentId: {

    type: DataTypes.INTEGER,

    allowNull:true

},



    // MITRE ATT&CK mapping

    mitreTechnique: {

        type: DataTypes.STRING,

        allowNull:true

    },



    tactic: {

        type: DataTypes.STRING,

        allowNull:true

    },



    riskScore: {

        type: DataTypes.INTEGER,

        defaultValue:0

    },



    assignedTo: {

        type: DataTypes.INTEGER,

        allowNull:true

    },



    createdBy: {

        type: DataTypes.INTEGER,

        allowNull:true

    },



    resolvedBy: {

        type: DataTypes.INTEGER,

        allowNull:true

    },



    resolutionNote: {

        type: DataTypes.TEXT,

        allowNull:true

    },



    notes: {

        type: DataTypes.TEXT,

        allowNull:true

    }



}, {

    timestamps:true

});


module.exports = Alert;
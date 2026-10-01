const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");


const Incident = sequelize.define(
"Incident",
{

id:{
    type:DataTypes.INTEGER,
    autoIncrement:true,
    primaryKey:true
},



title:{
    type:DataTypes.STRING,
    allowNull:false
},



attackType:{
    type:DataTypes.STRING,
    allowNull:false
},

scanType: {
    type: DataTypes.STRING,
    allowNull: true
},



mitreTechnique:{
    type:DataTypes.STRING,
    allowNull:true
},



tactic:{
    type:DataTypes.STRING,
    allowNull:true
},



severity:{
    type:DataTypes.ENUM(
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ),
    defaultValue:"LOW"
},



riskScore:{
    type:DataTypes.INTEGER,
    defaultValue:0
},


relatedAlerts:{
    type:DataTypes.INTEGER,
    defaultValue:1
},



alertId:{
    type:DataTypes.INTEGER,
    allowNull:true
},



sourceIP:{
    type:DataTypes.STRING,
    allowNull:true
},



description:{
    type:DataTypes.TEXT,
    allowNull:true
},



evidence:{
    type:DataTypes.JSONB,
    defaultValue:[]
},



recommendation:{
    type:DataTypes.TEXT,
    allowNull:true
},




status:{
    type:DataTypes.ENUM(
        "OPEN",
        "ACKNOWLEDGED",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "CLOSED"
    ),
    defaultValue:"OPEN"
},



assignedTo:{
    type:DataTypes.INTEGER,
    allowNull:true
},



resolvedBy:{
    type:DataTypes.INTEGER,
    allowNull:true
},



resolutionNote:{
    type:DataTypes.TEXT,
    allowNull:true
},
closedBy:{
    type:DataTypes.INTEGER,
    allowNull:true
},


closedAt:{
    type:DataTypes.DATE,
    allowNull:true
},


closureNote:{
    type:DataTypes.TEXT,
    allowNull:true
},



timeline:{
    type:DataTypes.JSONB,
    defaultValue:[]
}



},
{

timestamps:true,

indexes:[

{
fields:["severity"]
},

{
fields:["status"]
},

{
fields:["attackType"]
}

]

});


module.exports = Incident;
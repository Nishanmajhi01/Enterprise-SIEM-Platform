const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");


const SecurityEvent = sequelize.define("SecurityEvent", {


id:{
type:DataTypes.INTEGER,
autoIncrement:true,
primaryKey:true
},


deviceId:{
type:DataTypes.INTEGER,
allowNull:true
},

incidentId:{
    type:DataTypes.INTEGER,
    allowNull:true
},


eventType:{
type:DataTypes.STRING,
allowNull:false
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


sourceIP:{
type:DataTypes.STRING
},


destinationIP:{
type:DataTypes.STRING
},


username:{
type:DataTypes.STRING
},


message:{
type:DataTypes.TEXT
},


attackType:{
type:DataTypes.STRING
},


raw:{
type:DataTypes.JSONB
},


timestamp:{
type:DataTypes.DATE,
defaultValue:DataTypes.NOW
}


},{
timestamps:true
});


module.exports = SecurityEvent;
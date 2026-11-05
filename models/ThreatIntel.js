const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");


const ThreatIntel = sequelize.define("ThreatIntel", {


id: {

type: DataTypes.INTEGER,

autoIncrement:true,

primaryKey:true

},

workspaceId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
        model: "Workspaces",
        key: "id"
    },
    onUpdate: "CASCADE",
    onDelete: "RESTRICT"
},





name: {

type:DataTypes.STRING,

allowNull:false

},



description: {

type:DataTypes.TEXT,

allowNull:true

},



attackType: {

type:DataTypes.STRING,

allowNull:true

},



mitreTechnique: {

type:DataTypes.STRING,

allowNull:true

},



tactic: {

type:DataTypes.STRING,

allowNull:true

},



severity: {

type:DataTypes.ENUM(
"LOW",
"MEDIUM",
"HIGH",
"CRITICAL"
),

defaultValue:"LOW"

},



riskScore: {

type:DataTypes.INTEGER,

defaultValue:0

},



confidence: {

type:DataTypes.ENUM(
"LOW",
"MEDIUM",
"HIGH",
"CRITICAL"
),

defaultValue:"MEDIUM"

},



source: {

type:DataTypes.STRING,

defaultValue:"Manual"

},



status: {

type:DataTypes.ENUM(
"NEW",
"INVESTIGATING",
"RESOLVED"
),

defaultValue:"NEW"

},



sourceIP: {

type:DataTypes.STRING,

allowNull:true

}



},{

timestamps:true

});


module.exports = ThreatIntel;
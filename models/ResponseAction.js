const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");


const ResponseAction = sequelize.define(
"ResponseAction",
{

id:{
type:DataTypes.INTEGER,
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

incidentId:{
type:DataTypes.INTEGER,
allowNull:false
},


action:{
type:DataTypes.STRING,
allowNull:false
},


target:{
type:DataTypes.STRING,
allowNull:true
},


performedBy:{
type:DataTypes.INTEGER,
allowNull:true
},


status:{
type:DataTypes.STRING,
defaultValue:"PENDING"
},


details:{
type:DataTypes.JSON,
defaultValue:{}
}


},
{
timestamps:true
});


module.exports = ResponseAction;
const {DataTypes}=require("sequelize");
const {sequelize}=require("../config/database");


const IncidentAssignment = sequelize.define(
"IncidentAssignment",
{

id:{
type:DataTypes.INTEGER,
autoIncrement:true,
primaryKey:true
},


incidentId:{
type:DataTypes.INTEGER,
allowNull:false
},


userId:{
type:DataTypes.INTEGER,
allowNull:false
},


username:{
type:DataTypes.STRING
},


role:{
type:DataTypes.STRING,
defaultValue:"SOC_ANALYST"
},


assignedAt:{
type:DataTypes.DATE,
defaultValue:DataTypes.NOW
}


},
{
timestamps:true
});


module.exports=IncidentAssignment;
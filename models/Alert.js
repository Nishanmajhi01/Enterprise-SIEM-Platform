const {DataTypes}=require("sequelize");

const {sequelize}=require("../config/database");


const Alert = sequelize.define(
"Alert",
{

id:{
type:DataTypes.INTEGER,
autoIncrement:true,
primaryKey:true
},


attackType:{
type:DataTypes.STRING,
allowNull:false
},


sourceIP:{
type:DataTypes.STRING
},


riskLevel:{
type:DataTypes.STRING
},


message:{
type:DataTypes.TEXT
},


status:{
type:DataTypes.STRING,
defaultValue:"OPEN"
}


},

{
timestamps:true
}

);


module.exports=Alert;
const {DataTypes}=require("sequelize");

const {sequelize}=require("../config/database");


const SecurityEvent = sequelize.define(
"SecurityEvent",
{

id:{
type:DataTypes.INTEGER,
autoIncrement:true,
primaryKey:true
},


eventType:{
type:DataTypes.STRING,
allowNull:false
},


sourceIP:{
type:DataTypes.STRING,
allowNull:false
},


username:{
type:DataTypes.STRING
},


description:{
type:DataTypes.TEXT
},


severity:{
type:DataTypes.STRING,
defaultValue:"LOW"
},


status:{
type:DataTypes.STRING,
defaultValue:"NEW"
}


},

{
timestamps:true
}

);


module.exports=SecurityEvent;
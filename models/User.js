const {DataTypes}=require("sequelize");

const {sequelize}=require("../config/database");


const User = sequelize.define(
"User",

{

id:{
type:DataTypes.INTEGER,
autoIncrement:true,
primaryKey:true
},


username:{
type:DataTypes.STRING,
allowNull:false
},


email:{
type:DataTypes.STRING,
unique:true,
allowNull:false
},


password:{
type:DataTypes.STRING,
allowNull:false
},


role:{
type:DataTypes.STRING,
defaultValue:"ANALYST"
}

},

{
timestamps:true
}

);


module.exports=User;
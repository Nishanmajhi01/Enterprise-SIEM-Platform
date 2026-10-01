const {
DataTypes
}=require("sequelize");


const {
sequelize
}=require("../config/database");



const Investigation =
sequelize.define(
"Investigation",
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


analystId:{
type:DataTypes.INTEGER,
allowNull:false
},


action:{
type:DataTypes.STRING,
allowNull:false
},


description:{
type:DataTypes.TEXT
},


result:{
type:DataTypes.TEXT
}


},
{

timestamps:true

});


module.exports=Investigation;
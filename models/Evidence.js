const {DataTypes}=require("sequelize");
const {sequelize}=require("../config/database");


const Evidence = sequelize.define(
"Evidence",
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


type:{
    type:DataTypes.STRING,
    allowNull:false
},


description:{
    type:DataTypes.TEXT,
    allowNull:true
},


source:{
    type:DataTypes.STRING,
    allowNull:true
},


data:{
    type:DataTypes.JSONB,
    defaultValue:{}
}


},
{

timestamps:true

});


module.exports = Evidence;
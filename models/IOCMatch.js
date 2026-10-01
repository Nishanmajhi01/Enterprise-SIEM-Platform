const {DataTypes}=require("sequelize");
const {sequelize}=require("../config/database");


const IOCMatch = sequelize.define("IOCMatch",{

id:{
type:DataTypes.INTEGER,
autoIncrement:true,
primaryKey:true
},


securityEventId:{
type:DataTypes.INTEGER,
allowNull:false
},


iocId:{
type:DataTypes.INTEGER,
allowNull:false
},


matchType:{
type:DataTypes.STRING,
defaultValue:"AUTOMATIC"
},


confidence:{
type:DataTypes.STRING,
defaultValue:"MEDIUM"
}


},{

timestamps:true

});


module.exports=IOCMatch;
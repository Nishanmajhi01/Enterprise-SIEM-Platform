const {DataTypes}=require("sequelize");

const {sequelize}=require("../config/database");


const AuditLog = sequelize.define(

"AuditLog",

{

id:{

type:DataTypes.INTEGER,

autoIncrement:true,

primaryKey:true

},


userId:{

type:DataTypes.INTEGER

},


username:{

type:DataTypes.STRING

},


action:{

type:DataTypes.STRING,

allowNull:false

},


module:{

type:DataTypes.STRING

},


severity:{

type:DataTypes.STRING,

defaultValue:"LOW"

},


ipAddress:{

type:DataTypes.STRING

},


description:{

type:DataTypes.TEXT

},


metadata:{

type:DataTypes.JSON

}


},


{

timestamps:true

}


);


module.exports=AuditLog;
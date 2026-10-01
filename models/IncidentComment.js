const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");


const IncidentComment = sequelize.define(
"IncidentComment",
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



username:{

type:DataTypes.STRING,

allowNull:false

},



comment:{

type:DataTypes.TEXT,

allowNull:false

}



},
{

timestamps:true

});


module.exports = IncidentComment;
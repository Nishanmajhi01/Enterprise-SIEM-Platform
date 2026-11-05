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
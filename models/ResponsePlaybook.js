const {DataTypes} = require("sequelize");
const {sequelize} = require("../config/database");


const ResponsePlaybook = sequelize.define("ResponsePlaybook",{


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




name:{
type:DataTypes.STRING,
allowNull:false
},


triggerType:{
type:DataTypes.STRING,
allowNull:false
},

incidentId:{
type:DataTypes.INTEGER,
allowNull:true
},


severity:{
type:DataTypes.STRING,
allowNull:false
},


action:{
type:DataTypes.STRING,
allowNull:false
},


enabled:{
type:DataTypes.BOOLEAN,
defaultValue:true
}


});


module.exports = ResponsePlaybook;
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
const {DataTypes}=require("sequelize");
const {sequelize}=require("../config/database");


const IOCMatch = sequelize.define("IOCMatch",{

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

securityEventId: {
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
const {DataTypes}=require("sequelize");

const {sequelize}=require("../config/database");


const Incident = sequelize.define(

"Incident",

{


id:{

type:DataTypes.INTEGER,

autoIncrement:true,

primaryKey:true

},



title:{

type:DataTypes.STRING,

allowNull:false

},



attackType:{

type:DataTypes.STRING,

allowNull:false

},



// MITRE ATT&CK Information

mitreTechnique:{

type:DataTypes.STRING

},



tactic:{

type:DataTypes.STRING

},



// Risk Management

severity:{

type:DataTypes.STRING,

defaultValue:"LOW"

},



riskScore:{

type:DataTypes.INTEGER,

defaultValue:0

},



// Investigation Information

sourceIP:{

type:DataTypes.STRING

},



evidence:{

type:DataTypes.JSON

},



description:{

type:DataTypes.TEXT

},



recommendation:{

type:DataTypes.TEXT

},



// SOC Workflow

status:{

type:DataTypes.STRING,

defaultValue:"OPEN"

},



assignedTo:{

type:DataTypes.STRING

}



},


{

timestamps:true

}


);



module.exports=Incident;
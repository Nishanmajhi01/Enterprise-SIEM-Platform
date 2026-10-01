const { DataTypes } = require("sequelize");
const { sequelize } = require("../config/database");

const Device = sequelize.define("Device", {

    id:{
        type:DataTypes.INTEGER,
        autoIncrement:true,
        primaryKey:true
    },

    name:{
        type:DataTypes.STRING,
        allowNull:false
    },

    hostname:{
        type:DataTypes.STRING
    },


    type:{
        type:DataTypes.ENUM(
            "WINDOWS",
            "LINUX",
            "FIREWALL",
            "SERVER",
            "ROUTER",
            "APPLICATION"
        ),
        allowNull:false
    },


    ipAddress:{
        type:DataTypes.STRING,
        allowNull:false
    },


    operatingSystem:{
        type:DataTypes.STRING
    },


    location:{
        type:DataTypes.STRING
    },


    apiKey:{
        type:DataTypes.STRING,
        allowNull:false,
        unique:true
    },


    agentVersion:{
        type:DataTypes.STRING,
        defaultValue:"1.0"
    },


    lastHeartbeat:{
        type:DataTypes.DATE
    },


    status:{
        type:DataTypes.ENUM(
            "ACTIVE",
            "OFFLINE",
            "DISABLED"
        ),
        defaultValue:"ACTIVE"
    }


},{
timestamps:true
});


module.exports = Device;
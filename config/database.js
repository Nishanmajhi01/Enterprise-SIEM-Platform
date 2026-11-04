const { Sequelize } = require("sequelize");


const sequelize = new Sequelize(

process.env.DB_NAME,

process.env.DB_USER,

process.env.DB_PASSWORD,

{

host: process.env.DB_HOST,

dialect:"postgres",

port:process.env.DB_PORT,

logging:false

}

);



const connectDatabase = async()=>{

try{


await sequelize.authenticate();


console.log(
"PostgreSQL Connected Successfully"
);







}

catch(error){


console.error("Database Connection Failed", error);
throw error;


}


};



module.exports={

sequelize,

connectDatabase

};
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



await sequelize.sync({

alter:true

});


console.log(
"Database Tables Updated"
);



}

catch(error){


console.log(

"Database Connection Failed",

error

);


}


};



module.exports={

sequelize,

connectDatabase

};
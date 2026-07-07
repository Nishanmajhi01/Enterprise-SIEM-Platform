const axios=require("axios");



async function checkIP(ip){


try{


const response =
await axios.get(

"https://api.abuseipdb.com/api/v2/check",

{

params:{
ipAddress:ip
},


headers:{

Key:
process.env.ABUSEIPDB_API_KEY,

Accept:
"application/json"

}

}

);



return response.data;


}

catch(error){


return {

error:
"IP check failed"

};


}


}



module.exports=checkIP;
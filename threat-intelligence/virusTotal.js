const axios=require("axios");


async function checkVirusTotal(hash){


try{


const response =
await axios.get(

`https://www.virustotal.com/api/v3/files/${hash}`,

{

headers:{
"x-apikey":
process.env.VIRUSTOTAL_API_KEY
}

}

);



return {

detected:true,

data:
response.data

};


}

catch(error){


return {

detected:false,

message:
"No malware detected"

};


}


}


module.exports=checkVirusTotal;
const axios = require("axios");


exports.checkIPReputation = async(ip)=>{


try{


const response =
await axios.get(

"https://api.abuseipdb.com/api/v2/check",

{

params:{

ipAddress:ip,

maxAgeInDays:90

},


headers:{

Key:
process.env.ABUSEIPDB_API_KEY,

Accept:
"application/json"

}

}

);



return {

source:"AbuseIPDB",

score:
response.data.data.abuseConfidenceScore,


country:
response.data.data.countryCode,


reports:
response.data.data.totalReports

};


}
catch(error){


return {

source:"AbuseIPDB",

score:0

};


}


};
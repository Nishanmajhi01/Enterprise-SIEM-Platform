const axios = require("axios");
const cache = require("./cacheService");

const BASE_URL =
"https://www.virustotal.com/api/v3";


async function checkFileHash(hash){

    const cached = cache.get(hash);

    if(cached){

        return cached;

    }

    try{

        const response = await axios.get(

            `${BASE_URL}/files/${hash}`,

            {

                headers:{

                    "x-apikey":
                    process.env.VIRUSTOTAL_API_KEY

                }

            }

        );

        cache.set(hash,response.data);

        return response.data;

    }

    catch(error){

        return{

            success:false,

            error:error.message

        };

    }

}

module.exports={

    checkFileHash

};
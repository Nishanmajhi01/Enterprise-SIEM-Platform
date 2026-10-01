const { Op } = require("sequelize");
const IOC = require("../models/IOC");


function extractRawValues(raw){

    if(!raw || typeof raw !== "object"){
        return [];
    }

    return Object.values(raw)
        .filter(v => typeof v === "string");

}


async function matchIOC(event){

    const matches = [];

    const ips = [
        event.sourceIP,
        event.destinationIP
    ].filter(Boolean);


    if(ips.length > 0){

        const ipMatches = await IOC.findAll({

            where:{
                type:"IP",
                value:{ [Op.in]: ips },
                isActive:true
            }

        });

        matches.push(...ipMatches);

    }


    // DOMAIN / URL / HASH / EMAIL: scan raw log fields for a matching IOC value

    const rawValues = extractRawValues(event.raw);

    if(rawValues.length > 0){

        const otherIOCs = await IOC.findAll({

            where:{
                type:{ [Op.in]:["DOMAIN","URL","HASH","EMAIL"] },
                isActive:true
            }

        });

        for(const ioc of otherIOCs){

            const hit = rawValues.some(
                value => value.includes(ioc.value)
            );

            if(hit){
                matches.push(ioc);
            }

        }

    }


    return matches;

}



module.exports = matchIOC;

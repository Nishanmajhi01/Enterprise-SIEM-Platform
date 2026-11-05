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

    const workspaceId = event?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error(
            "Valid workspace ID required for IOC matching"
        );
    }

    const matches = [];

    const ips = [
        event.sourceIP,
        event.destinationIP
    ].filter(Boolean);


    if(ips.length > 0){

        const ipMatches = await IOC.findAll({

            where:{
                workspaceId,
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
                workspaceId,
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

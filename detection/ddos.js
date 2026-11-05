const {
    createSecurityAlert
} = require("../services/alertService");



let traffic = {};





async function detectDDoS(ip, workspaceId){

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error("Valid workspace ID required for DDoS detection");
    }

    const trafficKey = `${workspaceId}:${ip}`;



    if(!ip){

        return;

    }




    if(!traffic[trafficKey]){

        traffic[trafficKey]=[];

    }





    traffic[trafficKey].push(
        Date.now()
    );






    const requests =
    traffic[trafficKey].filter(

        time =>
        Date.now() - time < 60000

    );





    traffic[trafficKey] =
    requests;






    if(requests.length > 100){



        await createSecurityAlert({
              workspaceId,



            title:
            "DDoS Attack Detected",




            description:
            `High volume traffic detected from ${ip}. Possible denial of service attack.`,




            severity:
            "CRITICAL",




            sourceIP:
            ip,




            attackType:
            "DDOS",




            mitreTechnique:
            "T1498",




            tactic:
            "Impact",




            riskScore:
            95



        });






        console.log(

            "DDOS ATTACK DETECTED:",
            ip

        );






        traffic[trafficKey]=[];

    }



}





module.exports = detectDDoS;
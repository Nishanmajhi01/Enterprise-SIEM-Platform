const {
    createSecurityAlert
} = require("../services/alertService");



let traffic = {};





async function detectDDoS(ip){



    if(!ip){

        return;

    }




    if(!traffic[ip]){

        traffic[ip]=[];

    }





    traffic[ip].push(
        Date.now()
    );






    const requests =
    traffic[ip].filter(

        time =>
        Date.now() - time < 60000

    );





    traffic[ip] =
    requests;






    if(requests.length > 100){



        await createSecurityAlert({



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






        traffic[ip]=[];

    }



}





module.exports = detectDDoS;
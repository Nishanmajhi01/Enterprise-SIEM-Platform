const {
    createSecurityAlert
} = require("../services/alertService");



async function detectPhishing(url){



    const suspiciousWords = [

        "login",

        "verify",

        "update",

        "password",

        "bank"

    ];




    let found = false;

    let matchedWord = "";





    for(let word of suspiciousWords){


        if(url.toLowerCase().includes(word)){


            found = true;

            matchedWord = word;

            break;

        }


    }





    if(found){



        await createSecurityAlert({



            title:
            "Phishing URL Detected",




            description:
            `Suspicious phishing URL detected containing keyword "${matchedWord}": ${url}`,




            severity:
            "HIGH",




            sourceIP:
            null,




            attackType:
            "PHISHING",




            mitreTechnique:
            "T1566",




            tactic:
            "Initial Access",




            riskScore:
            80



        });






        console.log(

            "PHISHING DETECTED:",
            url

        );





        return true;



    }





    return false;



}





module.exports = detectPhishing;
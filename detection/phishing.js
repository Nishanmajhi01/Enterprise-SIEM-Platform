const {
    createSecurityAlert
} = require("../services/alertService");



async function detectPhishing(url, workspaceId){

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        throw new Error("Valid workspace ID required for phishing detection");
    }




    // Ignore non-web schemes and malformed inputs; never alert on arbitrary text.
    if (typeof url !== "string" || url.length > 2048) return false;
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        return false;
    }
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) return false;

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


        // Search URL path and query, not benign hostname substrings.
        if((parsed.pathname + parsed.search).toLowerCase().includes(word)){


            found = true;

            matchedWord = word;

            break;

        }


    }





    if(found){



        await createSecurityAlert({



            workspaceId,
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
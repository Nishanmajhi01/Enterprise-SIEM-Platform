const mitreDatabase = {


    powershell:{


        technique:"T1059.001",

        tactic:"Execution",

        name:"PowerShell",

        description:
        "Adversaries may abuse PowerShell to execute malicious commands"

    },


    brute_force:{


        technique:"T1110",

        tactic:"Credential Access",

        name:"Brute Force",

        description:
        "Attackers attempt multiple credentials to gain access"

    },


    phishing:{


        technique:"T1566",

        tactic:"Initial Access",

        name:"Phishing",

        description:
        "Attackers use phishing techniques to gain initial access"

    },


    malware:{


        technique:"T1204",

        tactic:"Execution",

        name:"User Execution",

        description:
        "Malware execution through user interaction"

    }


};



function mapThreat(type){


const key =
type.toLowerCase();



return (

mitreDatabase[key]

||

{

technique:"Unknown",

tactic:"Unknown",

name:type,

description:
"No MITRE mapping available"

}

);


}



module.exports={

mapThreat

};
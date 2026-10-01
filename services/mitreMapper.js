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

    },


    ddos:{


        technique:"T1498",

        tactic:"Impact",

        name:"Network Denial of Service",

        description:
        "Attackers overload services with excessive traffic"

    },


    data_exfiltration:{


        technique:"T1041",

        tactic:"Exfiltration",

        name:"Exfiltration Over C2 Channel",

        description:
        "Adversaries steal data by exfiltrating it over an existing command and control channel"

    },


    port_scan:{


        technique:"T1046",

        tactic:"Discovery",

        name:"Network Service Discovery",

        description:
        "Attackers scan for open ports and services to identify attack surface"

    },


    ioc_reputation:{


        technique:"T1071",

        tactic:"Command and Control",

        name:"Application Layer Protocol",

        description:
        "Communication with infrastructure known to be malicious"

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
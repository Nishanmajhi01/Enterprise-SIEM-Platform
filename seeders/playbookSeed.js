require("dotenv").config();

const { sequelize, connectDatabase } = require("../config/database");
const ResponsePlaybook = require("../models/ResponsePlaybook");


const baselinePlaybooks = [

    {
        name: "Block Brute Force Source IP",
        triggerType: "BRUTE_FORCE",
        severity: "HIGH",
        action: "BLOCK_IP",
        enabled: true
    },

    {
        name: "Isolate Host on Malware (High)",
        triggerType: "MALWARE",
        severity: "HIGH",
        action: "ISOLATE_HOST",
        enabled: true
    },

    {
        name: "Isolate Host on Malware (Critical)",
        triggerType: "MALWARE",
        severity: "CRITICAL",
        action: "ISOLATE_HOST",
        enabled: true
    },

    {
        name: "Disable Account on Phishing",
        triggerType: "PHISHING",
        severity: "HIGH",
        action: "DISABLE_ACCOUNT",
        enabled: true
    },

    {
        name: "Block Source IP on DDoS",
        triggerType: "DDOS",
        severity: "HIGH",
        action: "BLOCK_IP",
        enabled: true
    },

    {
        name: "Isolate Host on Data Exfiltration",
        triggerType: "DATA_EXFILTRATION",
        severity: "CRITICAL",
        action: "ISOLATE_HOST",
        enabled: true
    }

];


async function seedPlaybooks(){

    await connectDatabase();

    for(const playbook of baselinePlaybooks){

        const [row, created] = await ResponsePlaybook.findOrCreate({

            where: { name: playbook.name },

            defaults: playbook

        });

        console.log(
            created ? `Created: ${row.name}` : `Already exists: ${row.name}`
        );

    }

    console.log("Playbook seeding complete.");

    await sequelize.close();

}


seedPlaybooks().catch(error => {

    console.log("Playbook seeding failed:", error.message);

    process.exit(1);

});

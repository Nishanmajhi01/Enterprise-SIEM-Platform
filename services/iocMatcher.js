const IOC = require("../models/IOC");

exports.matchIOC = async (event) => {

    const iocs = await IOC.findAll({ where: { isActive: true } });

    let matches = [];

    for (let ioc of iocs) {

        if (
            event.sourceIP === ioc.value ||
            event.hash === ioc.value ||
            event.domain === ioc.value
        ) {
            matches.push({
                type: ioc.type,
                value: ioc.value,
                reputation: ioc.reputation
            });
        }
    }

    return matches;
};
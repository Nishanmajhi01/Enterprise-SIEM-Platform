const validator = require("validator");

exports.validateIOC = (req, res, next) => {

    const { type, value } = req.body;

    if (!type || !value) {
        return res.status(400).json({
            message: "IOC type and value are required"
        });
    }

    // IP validation
    if (type === "IP" && !validator.isIP(value)) {
        return res.status(400).json({
            message: "Invalid IP address"
        });
    }

    // DOMAIN validation
    if (type === "DOMAIN") {
        const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

        if (!domainRegex.test(value)) {
            return res.status(400).json({
                message: "Invalid domain format"
            });
        }
    }

    // URL validation
    if (type === "URL") {
        if (!validator.isURL(value)) {
            return res.status(400).json({
                message: "Invalid URL format"
            });
        }
    }

    // HASH validation
    if (type === "HASH") {

        const len = value.length;

        if (![32, 40, 64].includes(len)) {
            return res.status(400).json({
                message: "Invalid hash format (MD5/SHA1/SHA256 required)"
            });
        }
    }

    next();
};
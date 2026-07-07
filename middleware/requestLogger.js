const logger = require("../utils/logger");

module.exports = (req, res, next) => {

    logger.info({
        method: req.method,
        url: req.url,
        ip: req.ip,
        user: req.user?.id || "anonymous",
        time: new Date().toISOString()
    });

    next();
};
const rateLimit = require("express-rate-limit");

// General API traffic includes polling, dashboards and investigation requests.
// Keep a broad safety ceiling without locking users out during normal SOC use.
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 2000,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { message: "API request limit reached. Try again later." }
});

// Login attempts have a separate, much tighter IP-based limit.
// Successful logins do not consume the quota.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 15,
    skipSuccessfulRequests: true,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { message: "Too many login attempts. Please try again later." }
});

module.exports = limiter;
module.exports.loginLimiter = loginLimiter;

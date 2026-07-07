require("dotenv").config();
require("./models/IOC");

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const http = require("http");

const { connectDatabase, sequelize } = require("./config/database");

const app = express();

/**
 * =========================
 * SECURITY CORE MIDDLEWARE
 * =========================
 */
app.use(cors());
app.use(helmet());
app.use(express.json());

/**
 * =========================
 * CUSTOM MIDDLEWARE IMPORTS
 * =========================
 */
const limiter = require("./middleware/rateLimiter");
const errorHandler = require("./middleware/errorHandler");
const requestLogger = require("./middleware/requestLogger");
const logger = require("./utils/logger");

/**
 * =========================
 * ROUTES IMPORTS
 * =========================
 */
const authRoutes = require("./routes/authRoutes");
const eventRoutes = require("./routes/eventRoutes");
const alertRoutes = require("./routes/alertRoutes");
const threatRoutes = require("./routes/threatRoutes");
const incidentRoutes = require("./routes/incidentRoutes");
const auditRoutes = require("./routes/auditRoutes");
const simulatorRoutes = require("./routes/simulatorRoutes");
const threatIntelRoutes = require("./routes/threatIntelRoutes");
const iocRoutes = require("./routes/iocRoutes");
const correlationRoutes = require("./routes/correlationRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const ingestRoutes = require("./routes/ingestRoutes");

/**
 * =========================
 * APPLY MIDDLEWARE (IMPORTANT ORDER)
 * =========================
 */

// 1. Request Logger (logs every request)
app.use(requestLogger);

// 2. Rate Limiter (protect API)
app.use(limiter);

/**
 * =========================
 * API ROUTES
 * =========================
 */

app.use("/api/auth", authRoutes);
app.use("/api/events", eventRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/threat", threatRoutes);
app.use("/api/incidents", incidentRoutes);
app.use("/api/audit", auditRoutes);
app.use("/api/simulator", simulatorRoutes);
app.use("/api/threat-intel", threatIntelRoutes);
app.use("/api/iocs", iocRoutes);
app.use("/api/correlation", correlationRoutes);
app.use("/api/dashboard", dashboardRoutes);
app.use("/api/ingest", ingestRoutes);


/**
 * =========================
 * HEALTH CHECK ROUTE
 * =========================
 */
app.get("/", (req, res) => {
    res.json({
        system: "Enterprise SIEM Platform",
        status: "Running",
        timestamp: new Date().toISOString()
    });
});

/**
 * =========================
 * ERROR HANDLER (MUST BE LAST)
 * =========================
 */
app.use(errorHandler);

/**
 * =========================
 * SERVER STARTUP
 * =========================
 */
const PORT = process.env.PORT || 5000;

const startServer = async () => {

    try {

        // Connect DB
        await connectDatabase();
        await sequelize.sync();

        logger.info("Database Connected Successfully");

        // Create HTTP server
        const server = http.createServer(app);

        /**
         * =========================
         * SOCKET.IO INIT (REAL-TIME SIEM ALERTS)
         * =========================
         */
        const { initSocket } = require("./websocket/socket");
        initSocket(server);

        /**
         * =========================
         * START SERVER
         * =========================
         */
        server.listen(PORT, () => {
            console.log(`SIEM Server running on port ${PORT}`);
            logger.info({ message: "SIEM Server Started", port: PORT });
        });

    } catch (error) {

        console.log("Server Startup Failed", error);
        logger.error({ message: "Startup Failed", error: error.message });

    }
};

startServer();
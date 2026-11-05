const { Server } = require("socket.io");
const { setIO } = require("../utils/socketEmitter");
const jwt = require("jsonwebtoken");
const Workspace = require("../models/Workspace");
const WorkspaceMembership = require("../models/WorkspaceMembership");
require("../models/associations");

let io = null;


/*
========================================
INITIALIZE SOCKET.IO SERVER
========================================
*/

const initSocket = (server) => {

    io = new Server(server, {

        cors: {

            origin: "http://localhost:5173",

            methods: [
                "GET",
                "POST"
            ],

            credentials: true

        },

        transports: [
            "polling",
            "websocket"
        ]

    });


    io.use(async (socket, next) => {
        try {
            const auth = socket.handshake.auth || {};
            const token = auth.token;
            const workspaceId = auth.workspaceId;

            if (typeof token !== "string" || !token) {
                return next(new Error("Authentication required"));
            }

            if (
                typeof workspaceId !== "string" ||
                !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
            ) {
                return next(new Error("Valid workspace ID required"));
            }

            const decoded = jwt.verify(
                token,
                process.env.JWT_SECRET
            );

            if (!Number.isSafeInteger(decoded.id) || decoded.id <= 0) {
                return next(new Error("Invalid authenticated user"));
            }

            const membership = await WorkspaceMembership.findOne({
                where: {
                    userId: decoded.id,
                    workspaceId,
                    status: "ACTIVE"
                },
                include: [{
                    model: Workspace,
                    as: "workspace",
                    required: true,
                    where: {
                        status: "ACTIVE"
                    }
                }]
            });

            if (!membership) {
                return next(new Error("Workspace access denied"));
            }

            socket.data.userId = decoded.id;
            socket.data.workspaceId = membership.workspaceId;
            socket.data.workspaceRole = membership.role;

            next();
        } catch (error) {
            next(new Error("Socket authentication failed"));
        }
    });

    io.on("connection", (socket) => {
        socket.join(`workspace:${socket.data.workspaceId}`);

        console.log(
            "SOC Dashboard Connected:",
            socket.id
        );


        socket.on("disconnect", () => {

            console.log(
                "SOC Dashboard Disconnected:",
                socket.id
            );

        });

    });


    // Used by socketEmitter.js
    setIO(io);

};



/*
========================================
SEND REAL-TIME ALERTS
========================================
*/

const sendAlert = (data) => {

    if (!io) {

        console.log(
            "Socket.IO not initialized."
        );

        return;

    }

    const workspaceId = data?.workspaceId;

    if (
        typeof workspaceId !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(workspaceId)
    ) {
        console.error(
            "Socket alert rejected: invalid workspaceId"
        );
        return;
    }

    io.to(`workspace:${workspaceId}`).emit(
        "security-alert",
        data
    );

};



/*
========================================
EXPORTS
========================================
*/

module.exports = {

    initSocket,
    sendAlert

};
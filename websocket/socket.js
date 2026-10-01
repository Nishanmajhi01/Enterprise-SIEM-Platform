const { Server } = require("socket.io");
const { setIO } = require("../utils/socketEmitter");

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


    io.on("connection", (socket) => {

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

    io.emit("security-alert", data);

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
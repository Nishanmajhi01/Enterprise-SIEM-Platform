const { Server } = require("socket.io");
const { setIO } = require("../utils/socketEmitter");

let io;

const initSocket = (server) => {

    io = new Server(server, {
        cors: {
            origin: "*"
        }
    });

    io.on("connection", (socket) => {

        console.log("Client connected:", socket.id);

        socket.on("disconnect", () => {
            console.log("Client disconnected");
        });

    });

    setIO(io); // 🔥 IMPORTANT

};

module.exports = { initSocket };
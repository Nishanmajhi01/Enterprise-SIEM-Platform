const { io } = require("socket.io-client");

const socket = io("http://localhost:5000");

socket.on("connect", () => {
    console.log("Connected:", socket.id);
});

socket.on("security-alert", (data) => {
    console.log("🚨 ALERT RECEIVED:");
    console.log(JSON.stringify(data, null, 2));
});
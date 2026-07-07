let io = null;

const setIO = (socketIO) => {
    io = socketIO;
};

const emitAlert = (data) => {
    if (io) {
        io.emit("security-alert", data);
    }
};

module.exports = {
    setIO,
    emitAlert
};
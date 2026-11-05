const path = require("path");

require("dotenv").config({
  path: path.resolve(__dirname, "..", ".env")
});

const { sequelize } = require("./database");

module.exports = {
  development: {
    ...sequelize.config,
    dialect: "postgres",
    logging: false
  }
};

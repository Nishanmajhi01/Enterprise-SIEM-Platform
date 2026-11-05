"use strict";

// Existing users remain verified to preserve legacy and already-created workspaces.
// New users are explicitly created with emailVerifiedAt = null by the signup flow.
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.addColumn("Users", "emailVerifiedAt", {
      type: Sequelize.DATE,
      allowNull: true,
      defaultValue: null
    });
    await queryInterface.sequelize.query(
      'UPDATE "Users" SET "emailVerifiedAt" = NOW() WHERE "emailVerifiedAt" IS NULL'
    );
  },
  async down(queryInterface) {
    await queryInterface.removeColumn("Users", "emailVerifiedAt");
  }
};

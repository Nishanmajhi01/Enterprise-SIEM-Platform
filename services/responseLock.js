const { sequelize } = require("../config/database");

async function withIncidentLock(incidentId, callback) {
    const id = Number(incidentId);

    if (!Number.isSafeInteger(id) || id <= 0) {
        throw new Error("A valid incident ID is required for response locking");
    }

    const connection = await sequelize.connectionManager.getConnection();
    let acquired = false;
    let reusable = true;

    try {
        await connection.query(
            "SELECT pg_advisory_lock($1::bigint)",
            [id]
        );
        acquired = true;

        return await callback();
    } finally {
        try {
            if (acquired) {
                const result = await connection.query(
                    "SELECT pg_advisory_unlock($1::bigint) AS unlocked",
                    [id]
                );

                if (result.rows?.[0]?.unlocked !== true) {
                    reusable = false;
                    throw new Error("PostgreSQL advisory lock was not confirmed released");
                }
            }
        } catch (error) {
            reusable = false;
            throw error;
        } finally {
            if (reusable) {
                await sequelize.connectionManager.releaseConnection(connection);
            } else {
                await sequelize.connectionManager.destroyConnection(connection);
            }
        }
    }
}

module.exports = { withIncidentLock };

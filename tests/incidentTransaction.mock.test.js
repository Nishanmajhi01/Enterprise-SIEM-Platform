
const assert = require("node:assert/strict");
const Module = require("node:module");
const path = require("node:path");

const creatorPath = path.resolve(
    __dirname,
    "../services/incidentCreator.js"
);

const workspaceId =
    "11111111-1111-4111-8111-111111111111";

const events = [];
let existingIncident = null;
let failAlertUpdate = false;
let failEvidenceCreate = false;

const mockSequelize = {
    query: async (sql, options) => {
        assert.match(sql, /pg_advisory_xact_lock/);
        assert.ok(options.transaction);
        events.push("LOCK");
    },

    transaction: async callback => {
        const transaction = {
            finished: false,
            LOCK: {
                UPDATE: "UPDATE"
            }
        };

        events.push("BEGIN");

        try {
            const result = await callback(transaction);
            events.push("COMMIT");
            transaction.finished = "commit";
            return result;
        } catch (error) {
            events.push("ROLLBACK");
            transaction.finished = "rollback";
            throw error;
        }
    }
};

const mocks = {
    "../models/Incident": {
        findOne: async options => {
            assert.equal(
                options.where.workspaceId,
                workspaceId
            );
            assert.ok(options.transaction);
            events.push("FIND");
            return existingIncident;
        },

        create: async (data, options) => {
            assert.equal(data.workspaceId, workspaceId);
            assert.ok(options.transaction);
            events.push("CREATE");

            return {
                id: 2001,
                ...data
            };
        }
    },

    "../models/Evidence": {
        create: async (data, options) => {
            assert.equal(data.workspaceId, workspaceId);
            assert.ok(options.transaction);
            events.push("EVIDENCE");

            if (failEvidenceCreate) {
                throw new Error("SIMULATED_EVIDENCE_FAILURE");
            }

            return data;
        }
    },

    "../models/Alert": {
        findOne: async options => {
            assert.equal(options.where.id, 1001);
            assert.equal(options.where.workspaceId, workspaceId);
            assert.equal(options.lock, "UPDATE");
            assert.ok(options.transaction);

            events.push("ALERT_LOCK");

            return {
                id: 1001,
                workspaceId,
                incidentId: null
            };
        },

        update: async (data, options) => {
            assert.equal(
                options.where.workspaceId,
                workspaceId
            );
            assert.equal(options.where.incidentId, null);
            assert.ok(options.transaction);
            events.push("LINK");

            return [failAlertUpdate ? 0 : 1];
        }
    },

    "sequelize": {
        Op: {
            in: Symbol("in"),
            gte: Symbol("gte")
        }
    },

    "../config/database": {
        sequelize: mockSequelize
    },

    "../utils/socketEmitter": {
        emitIncident: () => {
            events.push("EMIT");
        }
    },

    "./playbookEngine": {
        executePlaybook: async () => {
            events.push("PLAYBOOK");
        }
    }
};

const originalLoad = Module._load;

let createIncidentFromAlert;

try {
    Module._load = function(request, parent, isMain) {
        if (
            parent &&
            path.resolve(parent.filename) === creatorPath &&
            Object.prototype.hasOwnProperty.call(mocks, request)
        ) {
            return mocks[request];
        }

        return originalLoad.apply(this, arguments);
    };

    createIncidentFromAlert = require(creatorPath);
} finally {
    Module._load = originalLoad;
}

const makeAlert = () => ({
    id: 1001,
    workspaceId,
    sourceIP: "192.0.2.10",
    attackType: "BRUTE_FORCE",
    riskScore: 80,
    severity: "HIGH",
    alertInstance: {
        id: 1001
    }
});

async function main() {
    events.length = 0;

    const created = await createIncidentFromAlert(
        makeAlert()
    );

    assert.equal(created.id, 2001);

    assert.deepEqual(events, [
        "BEGIN",
        "LOCK",
        "ALERT_LOCK",
        "FIND",
        "CREATE",
        "LINK",
        "EVIDENCE",
        "COMMIT",
        "PLAYBOOK",
        "EMIT"
    ]);

    console.log(
        "PASS: New incident commits before external actions"
    );

    events.length = 0;
    failAlertUpdate = true;

    await assert.rejects(
        createIncidentFromAlert(makeAlert()),
        /Alert missing, already linked, or outside workspace/
    );

    assert.deepEqual(events, [
        "BEGIN",
        "LOCK",
        "ALERT_LOCK",
        "FIND",
        "CREATE",
        "LINK",
        "ROLLBACK"
    ]);

    console.log(
        "PASS: Failed alert linking triggers rollback"
    );

    console.log(
        "PASS: No playbook or WebSocket action after rollback"
    );

    events.length = 0;
    failAlertUpdate = false;

    existingIncident = {
        id: 2002,
        relatedAlerts: 2,
        riskScore: 70,
        timeline: [],
        changed: () => {},
        save: async options => {
            assert.ok(options.transaction);
            events.push("SAVE");
        }
    };

    const correlated = await createIncidentFromAlert(
        makeAlert()
    );

    assert.equal(correlated.id, 2002);
    assert.equal(correlated.relatedAlerts, 3);
    assert.equal(correlated.riskScore, 100);

    assert.deepEqual(events, [
        "BEGIN",
        "LOCK",
        "ALERT_LOCK",
        "FIND",
        "SAVE",
        "LINK",
        "COMMIT"
    ]);

    console.log(
        "PASS: Existing incident updated inside transaction"
    );

    console.log(
        "PASS: No duplicate incident or evidence created"
    );

    console.log(
        "PASS: No playbook or WebSocket emission for correlation"
    );

    events.length = 0;
    existingIncident = null;
    failAlertUpdate = false;
    failEvidenceCreate = true;

    await assert.rejects(
        createIncidentFromAlert(makeAlert()),
        /SIMULATED_EVIDENCE_FAILURE/
    );

    assert.deepEqual(events, [
        "BEGIN",
        "LOCK",
        "ALERT_LOCK",
        "FIND",
        "CREATE",
        "LINK",
        "EVIDENCE",
        "ROLLBACK"
    ]);

    console.log(
        "PASS: Evidence creation failure triggers rollback"
    );

    console.log(
        "PASS: No playbook or WebSocket emission after evidence failure"
    );

    failEvidenceCreate = false;

    events.length = 0;
    failEvidenceCreate = false;
    failAlertUpdate = true;

    existingIncident = {
        id: 2003,
        relatedAlerts: 2,
        riskScore: 70,
        timeline: [],
        changed: () => {},
        save: async options => {
            assert.ok(options.transaction);
            events.push("SAVE");
        }
    };

    await assert.rejects(
        createIncidentFromAlert(makeAlert()),
        /Alert missing, already linked, or outside workspace/
    );

    assert.deepEqual(events, [
        "BEGIN",
        "LOCK",
        "ALERT_LOCK",
        "FIND",
        "SAVE",
        "LINK",
        "ROLLBACK"
    ]);

    console.log(
        "PASS: Existing-incident alert-link failure triggers rollback"
    );

    console.log(
        "PASS: No playbook or WebSocket emission after correlation failure"
    );

    failAlertUpdate = false;
    existingIncident = null;

    console.log(
        "PASS: Isolated incident workflow tests completed"
    );
}

main().catch(error => {
    console.error("FAIL:", error);
    process.exitCode = 1;
});

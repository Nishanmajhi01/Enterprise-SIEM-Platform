const test = require("node:test");
const assert = require("node:assert/strict");
const { setIO, emitAlert, emitIncident } = require("../utils/socketEmitter");

const workspaceId = "bf763ca9-113f-40c4-b5cf-ed412a6e0474";

test("realtime alerts and incidents are scoped to their workspace and include its ID", () => {
  const messages = [];
  setIO({
    to(room) {
      return {
        emit(event, payload) {
          messages.push({ room, event, payload });
        }
      };
    }
  });

  emitAlert({ id: 129, workspaceId, title: "Brute Force Attack Detected", severity: "HIGH" });
  emitIncident({ id: 145, workspaceId, title: "Brute Force Attack Detected", status: "OPEN" });

  assert.equal(messages.length, 2);
  assert.deepEqual(messages.map(({ room }) => room), [
    `workspace:${workspaceId}`,
    `workspace:${workspaceId}`
  ]);
  assert.deepEqual(messages.map(({ event }) => event), ["security-alert", "security-incident"]);
  for (const message of messages) assert.equal(message.payload.workspaceId, workspaceId);

  setIO(null);
});

test("realtime emissions reject missing and invalid workspace IDs", () => {
  const messages = [];
  setIO({ to(room) { return { emit(event, payload) { messages.push({ room, event, payload }); } }; } });
  emitAlert({ id: 1 });
  emitIncident({ id: 2, workspaceId: "invalid" });
  assert.equal(messages.length, 0);
  setIO(null);
});

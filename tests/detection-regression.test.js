const test = require("node:test");
const assert = require("node:assert/strict");
const {detectDDoSV2} = require("../detection/ddosV2");
const {detectPhishingV2} = require("../detection/phishingV2");
test("distributed synthetic firewall telemetry", () => {
  let result;
  for (let i=0;i<150;i++) result=detectDDoSV2({workspaceId:"regression-a",eventType:"PFSENSE_FIREWALL",sourceIP:"192.0.2."+ (1+i%3),destinationIP:"198.51.100.10"});
  assert.equal(result.detectionType,"DISTRIBUTED_FLOOD");
  assert.equal(result.shouldAlert,true);
  assert.equal(result.uniqueSources,3);
});
test("workspace counters remain separate", () => {
  for(let i=0;i<60;i++) for(const workspaceId of ["regression-b","regression-c"]) {
    const result=detectDDoSV2({workspaceId,eventType:"PFSENSE_FIREWALL",sourceIP:"192.0.2.4",destinationIP:"198.51.100.11"});
    assert.equal(result.detected,false);
  }
});
test("routine traffic and benign URLs do not trigger detectors", async () => {
  for(let i=0;i<150;i++) assert.equal(detectDDoSV2({workspaceId:"regression-d",eventType:"PFSENSE_FIREWALL",sourceIP:"192.0.2.5",destinationIP:"198.51.100.12",raw:{protocol:"UDP",destinationPort:123}}).detected,false);
  assert.equal((await detectPhishingV2({message:"https://example.com/"})).detected,false);
  assert.equal((await detectPhishingV2({message:"http://192.0.2.50/verify-account?token=test"})).riskScore,85);
});

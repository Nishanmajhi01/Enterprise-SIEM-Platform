
function simulateDDoS(mode = "single") {
  const events = [];
  const timestamp = new Date().toISOString();

  if (mode === "distributed") {
    const sources = [
      "172.16.0.10",
      "172.16.0.11",
      "172.16.0.12",
      "172.16.0.13"
    ];

    for (let i = 0; i < 120; i++) {
      events.push({
        requests: true,
        sourceIP: sources[i % sources.length],
        destinationIP: "192.168.1.40",
        timestamp
      });
    }
  } else {
    for (let i = 0; i < 120; i++) {
      events.push({
        requests: true,
        sourceIP: "172.16.0.5",
        destinationIP: "192.168.1.40",
        timestamp
      });
    }
  }

  return events;
}

module.exports = simulateDDoS;

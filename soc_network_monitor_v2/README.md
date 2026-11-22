# SOC Network Monitor V2

Defensive network-monitoring dashboard for a Linux/Kali lab or authorized environment.

## V2 features

- Interface inventory
- Interface selection workflow
- CSV/JSON export for packets and alerts
- Alert clearing
- Packet/alert SQLite history
- Live flows and top talkers
- Protocol dashboard
- Host CPU/RAM telemetry
- Capture-drop counter
- TCP port-scan heuristic
- Cleartext protocol observation
- Long DNS query heuristic
- Large packet heuristic
- REST API
- Responsive SOC-style UI

## Install

```bash
chmod +x install.sh
./install.sh
sudo soc-monitor
```

Choose an interface before launching:

```bash
ip -br link
sudo SOC_INTERFACE=eth0 soc-monitor
```

or:

```bash
sudo SOC_INTERFACE=wlan0 soc-monitor
```

Open:

`http://127.0.0.1:5000`

## Exports

Dashboard buttons export:

- alerts.csv
- alerts.json
- packets.csv
- packets.json

API endpoints:

- GET /api/interfaces
- GET /api/overview
- GET /api/alerts
- GET /api/packets
- GET /api/health
- GET /export/alerts/csv
- GET /export/alerts/json
- GET /export/packets/csv
- GET /export/packets/json

## Important

Interface selection cannot safely change a live Scapy sniffer from the browser in this V2 architecture. The UI enumerates interfaces and gives the exact restart command. This avoids running privileged capture control directly from the web application.

For a production SOC, add Suricata/Zeek, centralized log collection, asset/identity context, threat-intelligence enrichment, SIEM correlation, RBAC, HTTPS, durable queues, PCAP retention, incident/case management and detection-rule lifecycle management.

Only monitor systems and traffic you are authorized to monitor.

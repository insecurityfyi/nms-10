# NSM-10

Read-only monitoring dashboard for a small network:

- **SNMP** devices (v2c and v3): subnet discovery, reachability, uptime, CPU load, traffic, LLDP neighbours
- **Ubiquiti UniFi** via the UniFi Network Integration API (API key), with a topology map
- **Proxmox VE** via API token: nodes, guests, storage
- **Firewalla** via the MSP API: boxes, device counts, active alarms
- **Zscaler** via OneAPI: ZIA, ZPA, ZDX and AI Security (AI Guard)

All credentials are entered in the app under **Settings & credentials**. They are
encrypted on disk in the `nsm_data` Docker volume and never returned to the browser.

## Deploy to the Ubuntu server (192.168.7.10)

From Windows PowerShell, in this folder:

    .\deploy.ps1 -User <your-ssh-user>

Or on the server itself:

    git clone https://github.com/insecurityfyi/nms-10 nsm-10 && cd nsm-10 && sudo bash install.sh

To update later, one command on the server:

    sudo nsm-update

(The first time, install that command with
`curl -fsSL https://raw.githubusercontent.com/insecurityfyi/nms-10/main/update.sh | sudo bash`.)

Then open `http://192.168.7.10:8080`. The first visit asks you to create the admin
password. Re-run the same command to update.

## What each source needs

| Source | In Settings | Minimum permission |
|---|---|---|
| SNMP | range to scan (or a single host), community string or v3 user | read-only |
| UniFi | console URL, API key | key from Settings > Control Plane > Integrations |
| Proxmox | API URL (port 8006), token ID, token secret | `PVEAuditor` on `/` |
| Firewalla | MSP domain, personal access token | Read Only token from MSP Settings > MSP API |
| Zscaler | vanity domain, client ID and secret, ZPA customer ID | read-only API roles in ZIdentity |

## Notes

- The app serves plain HTTP on port 8080. Keep it on the internal network, or put a
  TLS reverse proxy in front of it.
- Every source page opens with a topology map (SNMP links come from LLDP).
- Monitoring only: nothing in this version changes configuration on any device.
- Run locally: `pip install -r requirements.txt && NSM_DATA=./data uvicorn app.main:app --port 8080`
  (SNMP polling needs the net-snmp tools: `apt install snmp`).

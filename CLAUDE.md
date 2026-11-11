# NSM-10

Read-only monitoring dashboard for a small network. GitHub: insecurityfyi/nms-10
(the repo is named `nms-10`; the app is called NSM-10).

## Layout

- `app/main.py` - FastAPI app: auth, API routes, poll loop, alert rules (`build_alerts`),
  endpoint merge (`build_endpoints`: UniFi clients + Firewalla devices by MAC)
- `app/collectors.py` - one collector per source; each returns `{"configured", "ok", "error", ...}`
  - SNMP: shells out to net-snmp (`snmpget`/`snmpwalk`); `discover()` scans a range
  - UniFi: Network Integration API, `X-API-KEY`, `/proxy/network/integration/v1`
  - Proxmox VE: API token, `/api2/json/cluster/resources`
  - Firewalla MSP API: `Authorization: Token <token>`, `https://<msp domain>/v2/{boxes,devices,alarms}`
  - Zscaler OneAPI: token from `https://<vanity>.zslogin<cloud>.net/oauth2/v1/token`,
    then `/zia/api/v1`, `/zpa/mgmtconfig/v1/admin/customers/<id>`, `/zdx/v1`, `/aiguard/v1`, `/ztw/api/v1/ecgroup`
- `app/store.py` - SQLite + Fernet-encrypted settings, admin password, sessions
- `app/static/index.html` - whole UI in one file, vanilla JS, no build step
- `Dockerfile`, `docker-compose.yml`, `install.sh`, `deploy.ps1` - packaging and deploy

ZDX user data (`collectors.zdx_users`) is fetched by a separate slow loop in `main.py`
(`zdx_users_loop`, windows of 2/24/168 hours) because it costs many API calls and ZDX rate
limits are tight. Keep it capped.

## Run and test

    pip install -r requirements.txt
    NSM_DATA=./data uvicorn app.main:app --port 8080

SNMP needs `apt install snmp`; a local `snmpd` on loopback is enough to test polling
and discovery. There is no automated test suite yet.

## Deploy

Target is the Ubuntu server at 192.168.7.10, Docker Compose, port 8080:

    ssh <user>@192.168.7.10 'sudo nsm-update'     # update.sh: pull + rebuild

Settings and secrets live in the `nsm_data` volume and survive redeploys.

## Rules

- Monitoring only: do not add calls that change device or Zscaler configuration
  without the owner asking for it.
- Secrets are entered in the Settings page only. Never commit credentials, and never
  return stored secrets to the browser (see `store.masked` / `merge_secrets`).
- Render remote data with DOM text nodes (the `$()` helper), never `innerHTML`.

## Status

Tested against stand-ins only: local snmpd, a mock Proxmox/UniFi server. Not yet
verified against real Zscaler, UniFi or Proxmox responses; expect field-name fixes.

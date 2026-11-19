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
  - ZPA detail (`_zpa`, page `vZpa`): connectors every poll; app segments, segment/server/connector groups,
    access rules (`/policySet/rules/policyType/ACCESS_POLICY`), IdPs (`v2/idp`), SCIM groups
    (`/zpa/userconfig/v1/customers/<id>/scimgroup/idpId/<idp>`), log receivers (`v2/lssConfig`) and Client
    Connector devices (`/zcc/papi/public/v1/getDevices`, the only source of ZPA users) are cached for
    `ZPA_DETAIL_TTL` (5 min) because of rate limits. `zpa_diagnose` is a pure function over that config:
    shadowed rules, rules matching anyone, stale references, segments no rule allows or no connected
    connector serves. ZPA's API has no sessions or per-user app usage; that is only in log streaming (LSS).
  - ZDX detail (`_zdx`, page `vZdx`): app scores every poll; ongoing and 24-hour alerts, and score history plus
    metrics (`/apps/<id>/score`, `/apps/<id>/metrics`, since=24) for the `ZDX_MAX_APPS` lowest-scoring apps are
    cached for `ZDX_DETAIL_TTL` (10 min). `zdx_diagnose` flags poor or dropping scores and ongoing alerts. The page
    reuses `state.zdx_users` for the poorest-experience users.
  - AI Security (`_aiguard`, page `vAi`): policies, match rules with their criteria, providers, applications and
    credential names/expiry (key material is never copied out of the reply). `ai_diagnose` flags unreachable
    rules, missing or disabled policies, unused or detector-less policies, expiring credentials. The AI Guard API
    has no usage statistics; "AI applications in use" comes from Z-Insights apps matched by category and name.
  - Zscaler Zero Trust Branch (former Airgap; not in OneAPI): `collect_ztb`, API key login at
    `https://<tenant>.goairgap.com/api/v3/api-key-auth/login` -> `result.delegate_token` (Bearer), then GET
    `/api/v2/Site/`, `/api/v2/Site/siteByID/<id>/overview`, `/api/v2/devices/active`, `/api/v2/alarm`.
    With tenant and key blank it sends the same paths through OneAPI (`https://api.zsapi.net/ztb/api/v2/...`,
    the SDK's `ZTBService` route) with the Zscaler client; unverified, so a refusal is reported with a hint.
    The Zscaler console itself calls `api.zsapi.net/private/ztds/api/v2/{Site/names,Gateway/,alarm,dashboard/tiles-info}`
    (seen in a HAR from a real tenant, 8.3.0); the collector uses those paths and response shapes, joining gateways
    to sites by `cluster_id`. The API address field takes a full https address or a `goairgap.com` tenant label.
    Device-list paths and field names still come from Zscaler's Python SDK (`zscaler/ztb`). It reports no bandwidth, so the
    Zero Trust Branch page (`vZtb`) joins each gateway to an SNMP device by IP or name for throughput and
    utilization (`ifHighSpeed`). The older `ztw` source is Cloud & Branch Connector, a different product.
- `app/store.py` - SQLite + Fernet-encrypted settings, admin password, sessions
- `app/static/index.html` - whole UI in one file, vanilla JS, no build step
- `Dockerfile`, `docker-compose.yml`, `install.sh`, `deploy.ps1` - packaging and deploy

Z-Insights analytics (`collectors.zs_insights`, GraphQL at `/zins/graphql`) runs in the same
slow loop. URL categories are not a documented grouping; the collector introspects the
schema and uses a category grouping only if the tenant offers one.

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
verified against real Zscaler (including Zero Trust Branch), UniFi or Proxmox responses; expect field-name fixes.

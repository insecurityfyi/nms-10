"""Read-only collectors for SNMP, UniFi, Proxmox VE and Zscaler (OneAPI)."""
import asyncio
import hashlib
import ipaddress
import re
import shutil
import time

import httpx

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]*$")
LABEL_RE = re.compile(r"^[A-Za-z0-9-]*$")
AUTH_PROTOS = {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
PRIV_PROTOS = {"DES", "AES", "AES-192", "AES-256"}
TIMEOUT = httpx.Timeout(15.0, connect=6.0)


def _err(e):
    if isinstance(e, httpx.HTTPStatusError):
        return f"HTTP {e.response.status_code} from {e.request.url.host}{e.request.url.path}"
    if isinstance(e, httpx.HTTPError):
        return f"{type(e).__name__}: {e}"[:200] or type(e).__name__
    return f"{type(e).__name__}: {e}"[:200]


# ---- SNMP (net-snmp command line tools) ------------------------------------

async def _run(args, timeout=10):
    try:
        p = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return 127, "", "net-snmp tools are not installed"
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill()
        await p.wait()
        return 1, "", "Timeout: no response"
    return p.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def _snmp_args(dev, timeout="2", retries="1", fmt="-Oqvt"):
    if dev.get("version") == "3":
        a = ["-v3", "-u", dev.get("v3_user") or "nsm"]
        ap, pp = dev.get("v3_auth_pass"), dev.get("v3_priv_pass")
        a += ["-l", "authPriv" if ap and pp else "authNoPriv" if ap else "noAuthNoPriv"]
        if ap:
            proto = dev.get("v3_auth_proto", "SHA").upper()
            a += ["-a", proto if proto in AUTH_PROTOS else "SHA", "-A", ap]
        if ap and pp:
            proto = dev.get("v3_priv_proto", "AES").upper()
            a += ["-x", proto if proto in PRIV_PROTOS else "AES", "-X", pp]
    else:
        a = ["-v2c", "-c", dev.get("community") or "public"]
    return a + ["-t", timeout, "-r", retries, fmt]


def _num(s):
    try:
        return int(s.strip().strip('"'))
    except (ValueError, AttributeError):
        return None


async def snmp_device(dev, prev):
    res = {"id": dev["id"], "name": dev["name"], "host": dev["host"], "up": False, "sys_name": "",
           "uptime_s": None, "cpu": None, "in_bps": None, "out_bps": None,
           "uplink_name": "", "uplink_auto": False, "interfaces": [], "neighbors": [], "error": ""}
    host = dev["host"]
    if not HOST_RE.match(host):
        res["error"] = "Invalid host"
        return res
    auth = _snmp_args(dev)
    rc, out, err = await _run(["snmpget", *auth, host, "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"])
    lines = out.strip().splitlines()
    if rc != 0 or len(lines) < 2:
        msg = (err.strip().splitlines() or ["No response"])[-1]
        res["error"] = "No response" if "Timeout" in msg else msg[:160]
        return res
    res["up"] = True
    res["sys_name"] = lines[0].strip().strip('"')
    ticks = _num(lines[1])
    res["uptime_s"] = ticks // 100 if ticks is not None else None

    rc, out, _ = await _run(["snmpwalk", *auth, host, "1.3.6.1.2.1.25.3.3.1.2"])
    loads = [n for n in (_num(x) for x in out.splitlines()) if n is not None] if rc == 0 else []
    if loads:
        res["cpu"] = round(sum(loads) / len(loads))

    await _traffic(dev, host, prev, res)
    res["neighbors"] = await _lldp(dev, host)
    return res


async def _lldp(dev, host):
    """LLDP neighbours: what is plugged into which local port."""
    names = await _walk(dev, host, "1.0.8802.1.1.2.1.4.1.1.9")      # lldpRemSysName
    if not names:
        return []
    rports = await _walk(dev, host, "1.0.8802.1.1.2.1.4.1.1.8")     # lldpRemPortDesc
    rids = await _walk(dev, host, "1.0.8802.1.1.2.1.4.1.1.7")       # lldpRemPortId
    lports = await _walk(dev, host, "1.0.8802.1.1.2.1.3.7.1.4")     # lldpLocPortDesc
    lids = await _walk(dev, host, "1.0.8802.1.1.2.1.3.7.1.3")       # lldpLocPortId
    out = []
    for idx, name in names.items():
        parts = idx.split(".")
        local = parts[1] if len(parts) >= 3 else ""
        out.append({"name": name[:80], "port": (rports.get(idx) or rids.get(idx) or "")[:60],
                    "local_port": (lports.get(local) or lids.get(local) or (f"port {local}" if local else ""))[:60]})
    return out[:128]


async def _walk(dev, host, oid):
    """Walk one table column; return {row index: value}."""
    rc, out, _ = await _run(["snmpwalk", *_snmp_args(dev, fmt="-Oqn"), host, oid], timeout=25)
    rows = {}
    if rc != 0:
        return rows
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].startswith("." + oid + "."):
            rows[parts[0][len(oid) + 2:]] = parts[1].strip().strip('"')
    return rows


async def _traffic(dev, host, prev, res):
    """Per-interface rates from octet counters. Uses the configured ifIndex,
    otherwise the busiest non-loopback interface."""
    ins = await _walk(dev, host, "1.3.6.1.2.1.31.1.1.1.6")
    outs = await _walk(dev, host, "1.3.6.1.2.1.31.1.1.1.10") if ins else {}
    if not ins or not outs:  # no 64-bit counters: fall back to the 32-bit ones
        ins = await _walk(dev, host, "1.3.6.1.2.1.2.2.1.10")
        outs = await _walk(dev, host, "1.3.6.1.2.1.2.2.1.16") if ins else {}
    counters = {}
    for i, v in ins.items():
        a, b = _num(v), _num(outs.get(i, ""))
        if a is not None and b is not None:
            counters[i] = (a, b)
    if not counters:
        return
    now = time.time()
    p = prev.get(dev["id"]) or {}
    names = p.get("names") or {}
    if not names:
        names = await _walk(dev, host, "1.3.6.1.2.1.31.1.1.1.1") or await _walk(dev, host, "1.3.6.1.2.1.2.2.1.2")
    prev[dev["id"]] = {"t": now, "counters": counters, "names": names}
    old, dt = p.get("counters") or {}, now - p.get("t", now)
    if dt <= 0:
        return
    rates = {}
    for i, (a, b) in counters.items():
        if i in old and a >= old[i][0] and b >= old[i][1]:
            rates[i] = ((a - old[i][0]) * 8 / dt, (b - old[i][1]) * 8 / dt)
    want = str(dev.get("uplink_ifindex") or "").strip()
    if want in rates:
        pick, auto = want, False
    else:
        cands = {i: r for i, r in rates.items() if not names.get(i, "").lower().startswith(("lo", "null"))} or rates
        if not cands:
            return
        pick, auto = max(cands, key=lambda i: sum(cands[i])), True
    top = sorted(rates, key=lambda i: sum(rates[i]), reverse=True)[:32]
    res["interfaces"] = [{"idx": i, "name": names.get(i) or ("ifIndex " + i),
                          "in_bps": round(rates[i][0]), "out_bps": round(rates[i][1])} for i in top]
    res["in_bps"], res["out_bps"] = round(rates[pick][0]), round(rates[pick][1])
    res["uplink_name"], res["uplink_auto"] = names.get(pick) or ("ifIndex " + pick), auto


async def collect_snmp(cfg, prev):
    devs = cfg["snmp"]["devices"]
    if not devs:
        return {"configured": False, "devices": []}
    sem = asyncio.Semaphore(20)

    async def one(d):
        async with sem:
            return await snmp_device(d, prev)
    return {"configured": True, "devices": list(await asyncio.gather(*(one(d) for d in devs)))}


MAX_SCAN = 1024


async def discover(cidr, cred):
    """Probe every address in an IPv4 range with one SNMP GET; return the ones that answer."""
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        raise ValueError("Enter a range like 192.168.7.0/24")
    if net.version != 4:
        raise ValueError("Only IPv4 ranges are supported")
    if net.num_addresses > MAX_SCAN:
        raise ValueError(f"Range too large: scan at most {MAX_SCAN} addresses (a /22) at a time")
    if not shutil.which("snmpget"):
        raise ValueError("net-snmp tools are not installed")
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    auth = _snmp_args(cred, timeout="1", retries="0")
    sem = asyncio.Semaphore(64)

    async def probe(host):
        async with sem:
            rc, out, _ = await _run(["snmpget", *auth, host, "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"], timeout=4)
        lines = out.strip().splitlines()
        if rc != 0 or not lines:
            return None
        return {"host": host, "sys_name": lines[0].strip().strip('"'),
                "descr": " ".join(x.strip() for x in lines[1:]).strip('"')[:160]}
    found = [r for r in await asyncio.gather(*(probe(h) for h in hosts)) if r]
    return {"scanned": len(hosts), "found": found}


# ---- UniFi Network (official Integration API, X-API-KEY) -------------------

async def _paged(client, url, headers):
    items, offset = [], 0
    while True:
        r = await client.get(url, headers=headers, params={"offset": offset, "limit": 200})
        r.raise_for_status()
        body = r.json()
        data = body.get("data", [])
        items += data
        offset += len(data)
        if not data or offset >= body.get("totalCount", 0) or offset > 20000:
            return items


def _unifi_kind(d):
    feats = d.get("features") or []
    feats = " ".join(feats.keys() if isinstance(feats, dict) else [str(f) for f in feats]).lower()
    if "accesspoint" in feats:
        return "ap"
    if "gateway" in feats:
        return "gateway"
    if "switching" in feats:
        return "switch"
    return "other"


async def collect_unifi(cfg):
    u = cfg["unifi"]
    if not (u["enabled"] and u["url"] and u["api_key"]):
        return {"configured": False}
    if not u["url"].startswith(("https://", "http://")):
        return {"configured": True, "ok": False, "error": "URL must start with https://"}
    base = u["url"].rstrip("/") + "/proxy/network/integration/v1"
    headers = {"X-API-KEY": u["api_key"], "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(verify=u["verify_tls"], timeout=TIMEOUT) as c:
            sites = await _paged(c, base + "/sites", headers)
            devices, clients = [], {"wired": 0, "wireless": 0, "other": 0}
            client_list, sem = [], asyncio.Semaphore(8)

            async def extra(sid, d):
                """Detail (uplink) and latest statistics for one device; both optional."""
                out = {}
                for key, path in (("detail", ""), ("stats", "/statistics/latest")):
                    try:
                        async with sem:
                            r = await c.get(f"{base}/sites/{sid}/devices/{d.get('id')}{path}", headers=headers)
                        if r.status_code == 200:
                            out[key] = r.json()
                    except httpx.HTTPError:
                        pass
                return out

            for s in sites:
                sid, sname = s.get("id"), s.get("name") or s.get("internalReference") or ""
                listed = await _paged(c, f"{base}/sites/{sid}/devices", headers)
                extras = await asyncio.gather(*(extra(sid, d) for d in listed))
                for d, x in zip(listed, extras):
                    d = {**d, **(x.get("detail") or {})}
                    st = x.get("stats") or {}
                    up = d.get("uplink") if isinstance(d.get("uplink"), dict) else {}
                    devices.append({
                        "id": str(d.get("id") or ""), "uplink": str(up.get("deviceId") or d.get("uplinkDeviceId") or ""),
                        "name": d.get("name") or d.get("model") or "", "model": d.get("model") or "",
                        "ip": d.get("ipAddress") or "", "state": str(d.get("state") or "").upper(),
                        "site": sname, "kind": _unifi_kind(d),
                        "update": bool(d.get("firmwareUpdatable")),
                        "uptime_s": st.get("uptimeSec"), "cpu": st.get("cpuUtilizationPct"),
                        "mem": st.get("memoryUtilizationPct"), "clients": 0,
                    })
                for cl in await _paged(c, f"{base}/sites/{sid}/clients", headers):
                    t = str(cl.get("type") or "").upper()
                    kind = "wired" if t == "WIRED" else "wireless" if t == "WIRELESS" else "other"
                    clients[kind] += 1
                    if len(client_list) < 3000:
                        client_list.append({"name": cl.get("name") or cl.get("macAddress") or "", "ip": cl.get("ipAddress") or "",
                                            "type": kind, "uplink": str(cl.get("uplinkDeviceId") or ""),
                                            "mac": cl.get("macAddress") or "", "connected_at": cl.get("connectedAt"),
                                            "site": sname})
        by_id = {d["id"]: d for d in devices if d["id"]}
        for cl in client_list:
            if cl["uplink"] in by_id:
                by_id[cl["uplink"]]["clients"] += 1
        counts = {k: sum(1 for d in devices if d["kind"] == k) for k in ("ap", "switch", "gateway", "other")}
        counts["total"] = len(devices)
        counts["online"] = sum(1 for d in devices if d["state"] == "ONLINE")
        counts["updates"] = sum(1 for d in devices if d["update"])
        clients["total"] = sum(clients.values())
        return {"configured": True, "ok": True, "error": "", "sites": len(sites),
                "devices": devices, "counts": counts, "clients": clients, "client_list": client_list}
    except Exception as e:  # noqa: BLE001 - report any failure on the card
        return {"configured": True, "ok": False, "error": _err(e)}


# ---- Proxmox VE (API token) -------------------------------------------------

async def collect_proxmox(cfg):
    p = cfg["proxmox"]
    if not (p["enabled"] and p["url"] and p["token_id"] and p["token_secret"]):
        return {"configured": False}
    if not p["url"].startswith(("https://", "http://")):
        return {"configured": True, "ok": False, "error": "URL must start with https://"}
    base = p["url"].rstrip("/") + "/api2/json"
    headers = {"Authorization": f"PVEAPIToken={p['token_id']}={p['token_secret']}"}
    try:
        async with httpx.AsyncClient(verify=p["verify_tls"], timeout=TIMEOUT) as c:
            r = await c.get(base + "/cluster/resources", headers=headers)
            r.raise_for_status()
            resources = r.json().get("data", [])
            r = await c.get(base + "/cluster/status", headers=headers)
            # Needs Sys.Audit; without it, carry on with quorum unknown.
            status = r.json().get("data", []) if r.status_code == 200 else []
            denied = r.status_code in (401, 403)
        if denied and not resources:
            return {"configured": True, "ok": False, "error":
                    "The API token signed in but has no permissions. In Proxmox, add an API Token "
                    "Permission for it: path /, role PVEAuditor."}
        cluster = next((s for s in status if s.get("type") == "cluster"), None)
        nodes, guests, storage = [], [], []
        for x in resources:
            t = x.get("type")
            if t == "node":
                nodes.append({"name": x.get("node"), "online": x.get("status") == "online",
                              "cpu": x.get("cpu"), "mem": x.get("mem"), "maxmem": x.get("maxmem"),
                              "disk": x.get("disk"), "maxdisk": x.get("maxdisk"), "uptime": x.get("uptime")})
            elif t in ("qemu", "lxc") and not x.get("template"):
                guests.append({"vmid": x.get("vmid"), "name": x.get("name") or str(x.get("vmid")),
                               "type": "VM" if t == "qemu" else "CT", "node": x.get("node"),
                               "status": x.get("status"), "cpu": x.get("cpu"),
                               "mem": x.get("mem"), "maxmem": x.get("maxmem")})
            elif t == "storage":
                storage.append({"name": x.get("storage"), "node": x.get("node"),
                                "used": x.get("disk"), "total": x.get("maxdisk"),
                                "shared": bool(x.get("shared"))})
        nodes.sort(key=lambda n: n["name"] or "")
        guests.sort(key=lambda g: g["vmid"] or 0)
        return {"configured": True, "ok": True, "error": "",
                "cluster": cluster.get("name") if cluster else "",
                "quorate": bool(cluster.get("quorate")) if cluster else None,
                "nodes": nodes, "guests": guests, "storage": storage}
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "ok": False, "error": _err(e)}


# ---- Firewalla MSP API (personal access token) ------------------------------

def _fw_base(domain):
    # Dedicated MSP domains serve the API at the root; the shared firewalla.net portal under /api.
    return f"https://{domain}/api/v2" if domain in ("firewalla.net", "www.firewalla.net") else f"https://{domain}/v2"


async def collect_firewalla(cfg):
    f = cfg["firewalla"]
    if not (f["enabled"] and f["domain"] and f["token"]):
        return {"configured": False}
    if not HOST_RE.match(f["domain"]):
        return {"configured": True, "ok": False, "error": "MSP domain should look like mydomain.firewalla.net"}
    base, headers = _fw_base(f["domain"]), {"Authorization": f"Token {f['token']}", "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            r = await c.get(base + "/boxes", headers=headers)
            r.raise_for_status()
            boxes = [{"gid": b.get("gid") or "", "name": b.get("name") or b.get("model") or "", "model": b.get("model") or "",
                      "mode": b.get("mode") or "", "online": bool(b.get("online")), "version": b.get("version") or "",
                      "public_ip": b.get("publicIP") or "", "last_seen": b.get("lastSeen"),
                      "devices": b.get("deviceCount"), "rules": b.get("ruleCount"), "alarms": b.get("alarmCount"),
                      "down_bps": None, "up_bps": None}
                     for b in _as_list(r.json(), "results") if isinstance(b, dict)]
            out = {"configured": True, "ok": True, "error": "", "boxes": boxes,
                   "devices_total": None, "devices_online": None, "device_list": [],
                   "alarm_count": None, "alarm_list": []}
            try:  # optional: device counts
                r = await c.get(base + "/devices", headers=headers)
                r.raise_for_status()
                devs = [d for d in _as_list(r.json(), "results") if isinstance(d, dict)]
                out["devices_total"] = len(devs)
                out["devices_online"] = sum(1 for d in devs if d.get("online"))
                out["device_list"] = [{
                    "name": d.get("name") or d.get("ip") or "", "ip": d.get("ip") or "", "online": bool(d.get("online")),
                    "gid": d.get("gid") or "",
                    "network": (d.get("network") or {}).get("name") or "" if isinstance(d.get("network"), dict) else "",
                    "group": (d.get("group") or {}).get("name") or "" if isinstance(d.get("group"), dict) else "",
                    "mac": d.get("id") or "", "vendor": d.get("macVendor") or "", "last_seen": d.get("lastSeen"),
                    "download": d.get("totalDownload"), "upload": d.get("totalUpload"),
                    "ip_reserved": bool(d.get("ipReserved"))}
                    for d in devs[:3000]]
            except httpx.HTTPError:
                pass
            try:  # optional: recent internet traffic per box, estimated from the newest flows
                r = await c.get(base + "/flows", headers=headers, params={"limit": 500})
                r.raise_for_status()
                now = time.time()
                flows = [x for x in _as_list(r.json(), "results")
                         if isinstance(x, dict) and isinstance(x.get("ts"), (int, float))]
                if flows:
                    # The API has no interface counters. Average the flows that ended in the last
                    # five minutes, or over the span returned if a busy site fills the page sooner.
                    window = min(300.0, max(30.0, now - min(x["ts"] for x in flows))) if len(flows) >= 500 else 300.0
                    sums = {}
                    for x in flows:
                        if now - x["ts"] > window or x.get("block") or x.get("direction") == "local":
                            continue
                        t = sums.setdefault(x.get("gid"), [0, 0])
                        t[0] += x.get("download") or 0
                        t[1] += x.get("upload") or 0
                    for b in boxes:
                        d, u = sums.get(b["gid"], (0, 0))
                        b["down_bps"], b["up_bps"] = round(d * 8 / window), round(u * 8 / window)
                    out["traffic_window_s"] = round(window)
            except httpx.HTTPError:
                pass
            try:  # optional: active alarms, newest first
                r = await c.get(base + "/alarms", headers=headers,
                                params={"query": "status:active", "limit": 50, "sortBy": "ts:desc"})
                r.raise_for_status()
                body = r.json()
                rows = [a for a in _as_list(body, "results") if isinstance(a, dict)]
                names = {b["gid"]: b["name"] for b in boxes}
                out["alarm_count"] = body.get("count") if isinstance(body, dict) and isinstance(body.get("count"), int) else len(rows)
                out["alarm_list"] = [{
                    "ts": a.get("ts"), "message": str(a.get("message") or "")[:240],
                    "device": (a.get("device") or {}).get("name") or "" if isinstance(a.get("device"), dict) else "",
                    "box": names.get(a.get("gid"), "")} for a in rows[:50]]
            except httpx.HTTPError:
                pass
        return out
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "ok": False, "error": _err(e)}


# ---- Zscaler OneAPI (ZIdentity client credentials) --------------------------

_tokens = {}


async def _zs_token(client, z):
    cloud = z["cloud"]
    key = (z["vanity"], cloud, z["client_id"], hashlib.sha256(z["client_secret"].encode()).hexdigest())
    tok = _tokens.get(key)
    if tok and tok[1] > time.time() + 60:
        return tok[0]
    r = await client.post(
        f"https://{z['vanity']}.zslogin{cloud}.net/oauth2/v1/token",
        data={"grant_type": "client_credentials", "client_id": z["client_id"],
              "client_secret": z["client_secret"], "audience": "https://api.zscaler.com"})
    r.raise_for_status()
    body = r.json()
    _tokens.clear()
    _tokens[key] = (body["access_token"], time.time() + int(body.get("expires_in", 3600)))
    return body["access_token"]


async def _zs_get(client, url, token, params=None):
    r = await client.get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                         params=params)
    r.raise_for_status()
    return r.json()


def _as_list(body, *keys):
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for k in keys + ("list", "data", "items", "results"):
            if isinstance(body.get(k), list):
                return body[k]
    return []


async def _zia(c, base, tok):
    status = await _zs_get(c, f"{base}/zia/api/v1/status", tok)
    out = {"status": str(status.get("status", "")).upper(), "url_rules": None, "fw_rules": None, "locations": None}
    for key, path in (("url_rules", "urlFilteringRules"), ("fw_rules", "firewallFilteringRules"),
                      ("locations", "locations")):
        try:
            out[key] = len(_as_list(await _zs_get(c, f"{base}/zia/api/v1/{path}", tok)))
        except httpx.HTTPError:
            pass  # the API role may not include this resource
    return out


async def _zpa(c, base, tok, customer):
    if not customer:
        raise ValueError("ZPA customer ID is not set")
    root = f"{base}/zpa/mgmtconfig/v1/admin/customers/{customer}"
    conns = _as_list(await _zs_get(c, f"{root}/connector", tok, {"page": 1, "pagesize": 500}))
    out = {"connectors": [], "segments": None}
    for x in conns:
        st = str(x.get("controlChannelStatus") or "")
        out["connectors"].append({
            "name": x.get("name") or "", "enabled": bool(x.get("enabled", True)),
            "status": st.replace("ZPN_STATUS_", "").replace("_", " ").title() or "Unknown",
            "healthy": bool(x.get("enabled", True)) and st.endswith("AUTHENTICATED"),
            "version": x.get("currentVersion") or "",
            "group": x.get("appConnectorGroupName") or "",
            # the ZPA broker (Zscaler data center) holding this connector's control connection
            "broker": x.get("ctrlBrokerName") or "", "location": x.get("location") or "",
            "public_ip": x.get("publicIp") or ""})
    try:
        body = await _zs_get(c, f"{root}/application", tok, {"page": 1, "pagesize": 500})
        total = body.get("totalCount") if isinstance(body, dict) else None
        out["segments"] = int(total) if str(total or "").isdigit() else len(_as_list(body))
    except httpx.HTTPError:
        pass
    return out


def _nm(v):
    """Name of a referenced object that may arrive as a string or as {"name": ...}."""
    if isinstance(v, dict):
        return str(v.get("name") or v.get("id") or "")
    return str(v or "")


async def _ztw(c, base, tok):
    """Zero Trust Branch / Cloud & Branch Connector groups and the gateways their VMs use."""
    groups = []
    for g in _as_list(await _zs_get(c, f"{base}/ztw/api/v1/ecgroup", tok)):
        if not isinstance(g, dict):
            continue
        vms = []
        for v in g.get("ecVMs") or []:
            if not isinstance(v, dict):
                continue
            st = str(v.get("operationalStatus") or v.get("status") or "")
            vms.append({"name": v.get("name") or "", "status": st.replace("_", " ").title() or "Unknown",
                        "healthy": st.upper() in ("ACTIVE", "ENABLED", "HEALTHY", "UP"),
                        "zia_gateway": _nm(v.get("ziaGateway") or g.get("ziaGateway")),
                        "zpa_broker": _nm(v.get("zpaBroker") or g.get("zpaBroker")),
                        "nat_ip": v.get("natIp") or "", "version": v.get("buildVersion") or ""})
        groups.append({"name": g.get("name") or "", "platform": str(g.get("platform") or ""),
                       "location": _nm(g.get("location")), "tunnel_mode": str(g.get("tunnelMode") or ""), "vms": vms})
    return {"groups": groups}


async def _zdx(c, base, tok):
    apps = []
    for a in _as_list(await _zs_get(c, f"{base}/zdx/v1/apps", tok), "apps"):
        score = a.get("score")
        apps.append({"name": a.get("name") or "", "users": a.get("total_users"),
                     "score": round(score) if isinstance(score, (int, float)) and score >= 0 else None})
    scored = [a["score"] for a in apps if a["score"] is not None]
    out = {"apps": apps, "score": round(sum(scored) / len(scored)) if scored else None, "alerts": None}
    try:
        out["alerts"] = len(_as_list(await _zs_get(c, f"{base}/zdx/v1/alerts/ongoing", tok), "alerts"))
    except httpx.HTTPError:
        pass
    return out


async def _aiguard(c, base, tok):
    root = f"{base}/aiguard/v1"
    out = {"policies": None, "providers": None, "applications": None, "policy_names": []}
    pols = _as_list(await _zs_get(c, f"{root}/detections/policies", tok), "policies")
    out["policies"] = len(pols)
    out["policy_names"] = [str(p.get("name") or "") for p in pols if isinstance(p, dict)][:50]
    for key, path in (("providers", "llm-providers"), ("applications", "llm-applications")):
        try:
            out[key] = len(_as_list(await _zs_get(c, f"{root}/{path}", tok)))
        except httpx.HTTPError:
            pass
    return out


async def collect_zscaler(cfg):
    z = cfg["zscaler"]
    products = ("zia", "zpa", "zdx", "aiguard", "ztw")
    ready = z["enabled"] and z["vanity"] and z["client_id"] and z["client_secret"]
    if not ready:
        return {p: {"configured": False} for p in products}
    if not (LABEL_RE.match(z["vanity"]) and LABEL_RE.match(z["cloud"])):
        bad = {"configured": True, "ok": False, "error": "Vanity domain and cloud may only contain letters, digits and hyphens"}
        return {p: dict(bad) for p in products}
    base = f"https://api.{z['cloud']}.zsapi.net" if z["cloud"] else "https://api.zsapi.net"
    out = {}
    async with httpx.AsyncClient(timeout=TIMEOUT) as c:
        try:
            tok = await _zs_token(c, z)
        except httpx.ConnectError as e:
            host = f"{z['vanity']}.zslogin{z['cloud']}.net"
            msg = (f"Sign-in failed: cannot reach {host} ({str(e)[:80]}). Check the vanity domain: it is the part "
                   "before .zslogin.net in your ZIdentity admin URL. Leave Cloud blank unless you are on beta.")
        except httpx.HTTPStatusError as e:
            hint = " Check the client ID and secret." if e.response.status_code in (400, 401) else ""
            msg = "Sign-in failed: " + _err(e) + "." + hint
        except Exception as e:  # noqa: BLE001
            msg = "Sign-in failed: " + _err(e)
            return {p: ({"configured": True, "ok": False, "error": msg} if z[p] else {"configured": False})
                    for p in products}
        calls = {"zia": lambda: _zia(c, base, tok), "zpa": lambda: _zpa(c, base, tok, z["zpa_customer_id"]),
                 "zdx": lambda: _zdx(c, base, tok), "aiguard": lambda: _aiguard(c, base, tok),
                 "ztw": lambda: _ztw(c, base, tok)}

        async def one(p):
            if not z[p]:
                return p, {"configured": False}
            try:
                return p, {"configured": True, "ok": True, "error": "", **(await calls[p]())}
            except Exception as e:  # noqa: BLE001
                return p, {"configured": True, "ok": False, "error": _err(e)}
        for p, res in await asyncio.gather(*(one(p) for p in products)):
            out[p] = res
    return out


async def collect_all(cfg, prev):
    snmp, unifi, proxmox, firewalla, zs = await asyncio.gather(
        collect_snmp(cfg, prev), collect_unifi(cfg), collect_proxmox(cfg), collect_firewalla(cfg),
        collect_zscaler(cfg))
    return {"snmp": snmp, "unifi": unifi, "proxmox": proxmox, "firewalla": firewalla, **zs}

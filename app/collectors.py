"""Read-only collectors for SNMP, UniFi, Proxmox VE, Firewalla and Zscaler (OneAPI and Zero Trust Branch)."""
import asyncio
import copy
import hashlib
import ipaddress
import re
import shutil
import time
from datetime import datetime

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
           "uplink_name": "", "uplink_auto": False, "uplink_speed_bps": None, "interfaces": [], "neighbors": [], "error": ""}
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
    # ifHighSpeed (Mbps), read once per device and cached; empty if the agent has no ifXTable speeds
    speeds = p["speeds"] if "speeds" in p else await _walk(dev, host, "1.3.6.1.2.1.31.1.1.1.15")
    prev[dev["id"]] = {"t": now, "counters": counters, "names": names, "speeds": speeds}

    def speed(i):
        n = _num(speeds.get(i, ""))
        return n * 1_000_000 if n else None
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
                          "in_bps": round(rates[i][0]), "out_bps": round(rates[i][1]), "speed_bps": speed(i)} for i in top]
    res["in_bps"], res["out_bps"] = round(rates[pick][0]), round(rates[pick][1])
    res["uplink_speed_bps"] = speed(pick)
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
                      "down_bps": None, "up_bps": None, "wans": []}
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
                flows = []
                for x in _as_list(r.json(), "results"):
                    if isinstance(x, dict):
                        try:
                            x["ts"] = float(x.get("ts"))
                            flows.append(x)
                        except (TypeError, ValueError):
                            pass
                if flows:
                    # The API has no interface counters, and flows reach the MSP some minutes after
                    # they end. So measure back from the newest flow received, not from the clock:
                    # average the five minutes before it (or the span returned, if a busy site
                    # fills the page sooner).
                    newest, oldest = max(x["ts"] for x in flows), min(x["ts"] for x in flows)
                    window = min(300.0, max(30.0, newest - oldest)) if len(flows) >= 500 else 300.0
                    sums = {}
                    for x in flows:
                        if newest - x["ts"] > window or x.get("block") or x.get("direction") == "local":
                            continue
                        t = sums.setdefault(x.get("gid"), [0, 0])
                        t[0] += x.get("download") or 0
                        t[1] += x.get("upload") or 0
                    for b in boxes:
                        d, u = sums.get(b["gid"], (0, 0))
                        b["down_bps"], b["up_bps"] = round(d * 8 / window), round(u * 8 / window)
                    out["traffic_window_s"] = round(window)
                    out["traffic_age_s"] = max(0, round(now - newest))
                else:
                    out["traffic_note"] = "Firewalla returned no flows, so link speed cannot be estimated."
            except httpx.HTTPStatusError as e:
                out["traffic_note"] = f"Link speed unavailable: the flows request returned HTTP {e.response.status_code}."
            except httpx.HTTPError as e:
                out["traffic_note"] = f"Link speed unavailable: {type(e).__name__}."
            # WAN connections per box. The API has no interface list, but traffic that arrives at a
            # WAN interface itself is recorded against an "if:<id>" pseudo-device, one id per WAN.
            try:
                extra = []
                try:
                    r = await c.get(base + "/flows", headers=headers, params={"query": "direction:inbound", "limit": 500})
                    if r.status_code == 200:
                        extra = [x for x in _as_list(r.json(), "results") if isinstance(x, dict)]
                except httpx.HTTPError:
                    pass
                wans = {}
                for x in (flows if "flows" in locals() else []) + extra:
                    for part in (x.get("device"), x.get("source"), x.get("destination")):
                        if not isinstance(part, dict) or not str(part.get("id") or "").startswith("if:"):
                            continue
                        w = wans.setdefault(x.get("gid"), {}).setdefault(part["id"], {"id": part["id"], "names": set(), "ips": set()})
                        if part.get("name"):
                            w["names"].add(str(part["name"]))
                        if part.get("ip"):
                            w["ips"].add(str(part["ip"]))
                for b in boxes:
                    found = sorted(wans.get(b["gid"], {}).values(), key=lambda w: w["id"])
                    b["wans"] = [{"id": w["id"], "name": sorted(w["names"])[0] if w["names"] else f"WAN {i + 1}",
                                  # one stable address means it is the WAN's own; many means remote peers
                                  "ip": next(iter(w["ips"])) if len(w["ips"]) == 1 else ""}
                                 for i, w in enumerate(found)]
            except Exception:  # noqa: BLE001 - best effort; never fail the source over this
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
    out["gre"], out["vpn"] = None, None
    try:  # GRE tunnels and the data centers they terminate in
        out["gre"] = [{
            "source_ip": t.get("sourceIp") or "", "comment": str(t.get("comment") or "")[:120],
            "internal_range": t.get("internalIpRange") or "",
            "primary_dc": _nm((t.get("primaryDestVip") or {}).get("datacenter")),
            "primary_vip": (t.get("primaryDestVip") or {}).get("virtualIp") or "",
            "secondary_dc": _nm((t.get("secondaryDestVip") or {}).get("datacenter")),
            "secondary_vip": (t.get("secondaryDestVip") or {}).get("virtualIp") or "",
        } for t in _as_list(await _zs_get(c, f"{base}/zia/api/v1/greTunnels", tok)) if isinstance(t, dict)]
    except httpx.HTTPError:
        pass
    try:  # IPSec VPN credentials (identity only; the pre-shared key is never read into state)
        out["vpn"] = [{
            "identity": v.get("fqdn") or v.get("ipAddress") or str(v.get("id") or ""), "type": str(v.get("type") or ""),
            "location": _nm(v.get("location")), "comment": str(v.get("comments") or "")[:120],
            "disabled": bool(v.get("disabled")),
        } for v in _as_list(await _zs_get(c, f"{base}/zia/api/v1/vpnCredentials", tok)) if isinstance(v, dict)]
    except httpx.HTTPError:
        pass
    return out


_zpa_cache = {}
ZPA_DETAIL_TTL = 300   # config and Client Connector detail is re-read at most this often (rate limits)
ZPA_MAX_PAGES = 6      # x 500 rows per list


async def _zpa_list(c, url, tok, params=None, pages=ZPA_MAX_PAGES):
    """All rows of a paged ZPA list ({"totalPages", "list"}); stops at `pages` pages."""
    rows, page = [], 1
    while page <= pages:
        body = await _zs_get(c, url, tok, {**(params or {}), "page": page, "pagesize": 500})
        got = _as_list(body)
        rows += [x for x in got if isinstance(x, dict)]
        total = body.get("totalPages") if isinstance(body, dict) else None
        if not got or not str(total or "").isdigit() or page >= int(total):
            break
        page += 1
    return rows


def _zpa_ports(seg, proto):
    """'443, 8000-8100' from either tcpPortRange [{from,to}] or tcpPortRanges ['443','443',...]."""
    out = []
    for r in seg.get(proto + "PortRange") or []:
        if isinstance(r, dict) and r.get("from"):
            out.append(str(r["from"]) if str(r.get("to") or r["from"]) == str(r["from"]) else f"{r['from']}-{r['to']}")
    flat = seg.get(proto + "PortRanges") or []
    if not out and isinstance(flat, list):
        for lo, hi in zip(flat[0::2], flat[1::2]):
            out.append(str(lo) if str(lo) == str(hi) else f"{lo}-{hi}")
    return ", ".join(out[:12]) + (f" +{len(out) - 12}" if len(out) > 12 else "")


def _truthy(v):
    return v is True or str(v).strip().lower() in ("1", "true", "yes")


# What each access-rule criterion is about, for the "who" / "what" split and the diagnostics.
ZPA_WHO = {"SCIM_GROUP": "Group", "SCIM": "User attribute", "SAML": "SAML attribute", "IDP": "Identity provider"}
ZPA_WHAT = {"APP": "App segment", "APP_GROUP": "Segment group"}
ZPA_OTHER = {"POSTURE": "Posture", "TRUSTED_NETWORK": "Trusted network", "CLIENT_TYPE": "Client type",
             "PLATFORM": "Platform", "COUNTRY_CODE": "Country", "MACHINE_GRP": "Machine group", "LOCATION": "Location",
             "BRANCH_CONNECTOR_GROUP": "Branch connector group", "EDGE_CONNECTOR_GROUP": "Cloud connector group",
             "RISK_FACTOR_TYPE": "Risk", "CHROME_ENTERPRISE": "Chrome Enterprise"}


def _zpa_rule(r, seg_names, grp_names, scim_names):
    who, what, other, apps, groups, negated = [], [], [], [], [], False
    for cond in r.get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        negated = negated or _truthy(cond.get("negated"))
        for o in cond.get("operands") or []:
            if not isinstance(o, dict):
                continue
            kind, rhs, lhs = str(o.get("objectType") or "").upper(), str(o.get("rhs") or ""), str(o.get("lhs") or "")
            label = str(o.get("name") or "")
            if kind == "APP":
                apps.append(rhs)
                what.append(label or seg_names.get(rhs) or f"segment {rhs} (deleted?)")
            elif kind == "APP_GROUP":
                groups.append(rhs)
                what.append("Group: " + (label or grp_names.get(rhs) or f"{rhs} (deleted?)"))
            elif kind in ZPA_WHO:
                if kind == "SCIM_GROUP":
                    label = label or scim_names.get(rhs) or f"group {rhs}"
                elif kind == "IDP":
                    label = label or str(o.get("idpName") or rhs)
                else:
                    label = (label or lhs) + (" = " + rhs if rhs else "")
                who.append(f"{ZPA_WHO[kind]}: {label}"[:120])
            else:
                val = {"true": "pass", "false": "fail"}.get(rhs.lower(), rhs) if kind in ("POSTURE", "TRUSTED_NETWORK") else rhs
                other.append(f"{ZPA_OTHER.get(kind, kind.replace('_', ' ').title())}: {label or lhs}{' = ' + val if val and label else ''}"[:120]
                             if kind != "CLIENT_TYPE" else "Client type: " + rhs.replace("zpn_client_type_", "").replace("_", " "))
    order = r.get("ruleOrder")
    return {"id": str(r.get("id") or ""), "name": str(r.get("name") or "")[:160], "order": int(order) if str(order or "").isdigit() else 0,
            "action": str(r.get("action") or "").upper(), "disabled": _truthy(r.get("disabled")),
            "default": _truthy(r.get("defaultRule")), "description": str(r.get("description") or "")[:200],
            "who": who[:40], "what": what[:60], "other": other[:30], "apps": apps, "groups": groups,
            "negated": negated, "modified": _ts(r.get("modifiedTime")), "findings": []}


def zpa_diagnose(d):
    """Static checks over the ZPA configuration. Adds `findings` to rules and segments and returns the
    full list, worst first. Nothing here calls ZPA; it reasons over what was already read."""
    found = []

    def add(level, kind, subject, text, target):
        f = {"level": level, "kind": kind, "subject": subject, "text": text}
        found.append(f)
        if target is not None:
            target["findings"].append({"level": level, "text": text})

    segs, rules = d["segments"], sorted(d["rules"], key=lambda r: r["order"])
    seg_by_id = {s["id"]: s for s in segs}
    group_members = {}
    for s in segs:
        group_members.setdefault(s["group_id"], set()).add(s["id"])
    all_ids, group_ids = set(seg_by_id), {g["id"] for g in d["segment_groups"]}

    def covers(r):
        """Segment ids a rule applies to; None means every application."""
        if not r["apps"] and not r["groups"]:
            return None
        out = set(r["apps"])
        for g in r["groups"]:
            out |= group_members.get(g, set())
        return out

    live = [r for r in rules if not r["disabled"]]
    for r in rules:
        cov = covers(r)
        r["segments"] = None if cov is None else len(cov & all_ids)
        if r["disabled"]:
            add("info", "rule", r["name"], "Rule is disabled, so it is never evaluated.", r)
            continue
        stale = [a for a in r["apps"] if a not in all_ids] + [g for g in r["groups"] if g not in group_ids]
        if stale and (segs or d["segment_groups"]):
            add("warn", "rule", r["name"], f"Refers to {len(stale)} app segment or segment group that no longer exists.", r)
        if cov is not None and cov and not any(seg_by_id[i]["enabled"] for i in cov if i in seg_by_id) and (cov & all_ids):
            add("info", "rule", r["name"], "Every app segment this rule names is disabled.", r)
        if r["action"] == "ALLOW" and not r["who"] and not r["negated"]:
            scope = "every application" if cov is None else f"{len(cov & all_ids)} app segment(s)"
            add("warn" if cov is None else "info", "rule", r["name"],
                f"Allows {scope} without naming a user, group or identity provider"
                + (" (other conditions still apply)." if r["other"] else ": anyone who can sign in matches."), r)
        elif cov is None and not r["negated"]:
            add("info", "rule", r["name"], "Has no application condition, so it applies to every application.", r)
    # Shadowing: ZPA takes the first matching rule. An earlier rule with only application conditions
    # (or none) matches everything a later rule could match for those applications.
    for i, r in enumerate(live):
        cov = covers(r)
        for e in live[:i]:
            if e["who"] or e["other"] or e["negated"]:
                continue
            ecov = covers(e)
            if ecov is None or (cov is not None and cov and cov <= ecov):
                clash = "" if e["action"] == r["action"] else f", which gives {e['action'].lower()} where this rule says {r['action'].lower()}"
                add("warn", "rule", r["name"], f"Never reached: rule {e['order']} “{e['name']}” matches the same traffic first{clash}.", r)
                break

    healthy_by_group, total_by_group = {}, {}
    for c in d["connectors"]:
        total_by_group[c["group_id"]] = total_by_group.get(c["group_id"], 0) + 1
        if c["healthy"]:
            healthy_by_group[c["group_id"]] = healthy_by_group.get(c["group_id"], 0) + 1
    sg_by_id = {g["id"]: g for g in d["server_groups"]}
    have_rules = bool(rules)
    for s in segs:
        cg = []
        for g in s["server_group_ids"]:
            cg += sg_by_id.get(g, {}).get("connector_group_ids", [])
        cg = list(dict.fromkeys(cg))
        s["connector_group_ids"] = cg
        s["connectors"] = sum(total_by_group.get(g, 0) for g in cg)
        s["connectors_healthy"] = sum(healthy_by_group.get(g, 0) for g in cg)
        matching = [r for r in live if (lambda cov: cov is None or s["id"] in cov)(covers(r))]
        s["rules"] = [{"order": r["order"], "name": r["name"], "action": r["action"]} for r in matching][:12]
        if not s["enabled"]:
            add("info", "segment", s["name"], "App segment is disabled.", s)
            continue
        if not s["server_group_ids"]:
            add("crit", "segment", s["name"], "No server group is attached, so no App Connector can serve it.", s)
        elif d["server_groups"] and not cg:
            add("crit", "segment", s["name"], "Its server groups have no App Connector group.", s)
        elif d["connectors_known"] and cg and not s["connectors"]:
            add("crit", "segment", s["name"], "Its App Connector groups contain no connectors.", s)
        elif d["connectors_known"] and cg and not s["connectors_healthy"]:
            add("crit", "segment", s["name"], f"None of its {s['connectors']} App Connectors is connected.", s)
        elif d["connectors_known"] and cg and s["connectors_healthy"] == 1:
            add("info", "segment", s["name"], "Served by a single connected App Connector (no redundancy).", s)
        if have_rules and not any(r["action"] == "ALLOW" for r in matching):
            add("warn", "segment", s["name"], "No enabled access rule allows it, so users are blocked by default.", s)
        elif have_rules and matching and matching[0]["action"] != "ALLOW" and not (matching[0]["who"] or matching[0]["other"]):
            add("warn", "segment", s["name"], f"The first rule that matches it (rule {matching[0]['order']}) denies everyone.", s)
    for g in d["connector_groups"]:
        if d["connectors_known"] and g["enabled"] and not total_by_group.get(g["id"]):
            add("warn", "connector group", g["name"], "Enabled App Connector group with no connectors.", None)
    for c in d["connectors"]:
        if c["enabled"] and c["expected"] and c["version"] and c["expected"] != c["version"]:
            add("info", "connector", c["name"], f"Running {c['version']}; {c['expected']} is expected (upgrade pending).", None)
    if d["lss"] is not None and not any(x["enabled"] for x in d["lss"]):
        add("info", "logging", "Log streaming", "No log receiver is enabled. ZPA exposes user sessions and app usage only through "
            "log streaming, so that activity is not available to any outside tool.", None)
    rank = {"crit": 0, "warn": 1, "info": 2}
    found.sort(key=lambda f: rank[f["level"]])
    return found


async def _zpa(c, base, tok, customer):
    if not customer:
        raise ValueError("ZPA customer ID is not set")
    root = f"{base}/zpa/mgmtconfig/v1/admin/customers/{customer}"
    root2 = f"{base}/zpa/mgmtconfig/v2/admin/customers/{customer}"
    conns = _as_list(await _zs_get(c, f"{root}/connector", tok, {"page": 1, "pagesize": 500}))
    out = {"connectors": [], "segments": None}
    for x in conns:
        st = str(x.get("controlChannelStatus") or "")
        out["connectors"].append({
            "name": x.get("name") or "", "enabled": bool(x.get("enabled", True)),
            "status": st.replace("ZPN_STATUS_", "").replace("_", " ").title() or "Unknown",
            "healthy": bool(x.get("enabled", True)) and st.endswith("AUTHENTICATED"),
            "version": x.get("currentVersion") or "", "expected": x.get("expectedVersion") or "",
            "upgrade": str(x.get("upgradeStatus") or "").replace("_", " ").title(),
            "group": x.get("appConnectorGroupName") or "", "group_id": str(x.get("appConnectorGroupId") or ""),
            # the ZPA broker (Zscaler data center) holding this connector's control connection
            "broker": x.get("ctrlBrokerName") or "", "location": x.get("location") or "",
            "public_ip": x.get("publicIp") or "", "private_ip": x.get("privateIp") or "",
            "platform": " ".join(str(x.get(k) or "") for k in ("platform", "runtimeOS")).strip(),
            "connected_since": _ts(x.get("lastBrokerConnectTime")), "last_disconnect": _ts(x.get("lastBrokerDisconnectTime")),
            "started": _ts(x.get("applicationStartTime"))})

    # Everything below is configuration that changes rarely: read it at most every ZPA_DETAIL_TTL seconds.
    hit = _zpa_cache.get(customer)
    if hit and hit["t"] > time.time() - ZPA_DETAIL_TTL:
        d = hit["d"]
    else:
        d = {"notes": [], "read_at": time.time()}

        async def opt(label, coro, default):
            try:
                return await coro
            except httpx.HTTPStatusError as e:
                d["notes"].append(f"{label}: HTTP {e.response.status_code}")
            except (httpx.HTTPError, ValueError) as e:
                d["notes"].append(f"{label}: {type(e).__name__}")
            return default

        seg_rows, grp_rows, sg_rows, cg_rows, rule_rows, idp_rows, lss_rows, edge_rows = await asyncio.gather(
            opt("app segments", _zpa_list(c, f"{root}/application", tok), None),
            opt("segment groups", _zpa_list(c, f"{root}/segmentGroup", tok), []),
            opt("server groups", _zpa_list(c, f"{root}/serverGroup", tok), []),
            opt("App Connector groups", _zpa_list(c, f"{root}/appConnectorGroup", tok), []),
            opt("access policy", _zpa_list(c, f"{root}/policySet/rules/policyType/ACCESS_POLICY", tok), None),
            opt("identity providers", _zpa_list(c, f"{root2}/idp", tok, pages=1), None),
            opt("log receivers", _zpa_list(c, f"{root2}/lssConfig", tok, pages=1), None),
            opt("service edges", _zpa_list(c, f"{root}/serviceEdge", tok, pages=1), []))
        ids = lambda rows: [str(x.get("id")) for x in rows or [] if isinstance(x, dict) and x.get("id")]  # noqa: E731
        d["segments"] = [{
            "id": str(x.get("id") or ""), "name": str(x.get("name") or "")[:160], "enabled": bool(x.get("enabled", True)),
            "domains": [str(v)[:120] for v in (x.get("domainNames") or [])[:40]], "domain_count": len(x.get("domainNames") or []),
            "tcp": _zpa_ports(x, "tcp"), "udp": _zpa_ports(x, "udp"),
            "group_id": str(x.get("segmentGroupId") or ""), "group": str(x.get("segmentGroupName") or ""),
            "server_group_ids": ids(x.get("serverGroups")), "server_groups": [_nm(g) for g in (x.get("serverGroups") or [])][:12],
            "bypass": str(x.get("bypassType") or "").replace("_", " ").title(), "health": str(x.get("healthReporting") or "").replace("_", " ").title(),
            "double_encrypt": _truthy(x.get("doubleEncrypt")), "inspect": _truthy(x.get("inspectTrafficWithZia")),
            "modified": _ts(x.get("modifiedTime")), "findings": []} for x in seg_rows or []]
        d["segments_known"] = seg_rows is not None
        d["segment_groups"] = [{"id": str(x.get("id") or ""), "name": str(x.get("name") or ""), "enabled": bool(x.get("enabled", True)),
                                "segments": len(x.get("applications") or [])} for x in grp_rows]
        d["server_groups"] = [{"id": str(x.get("id") or ""), "name": str(x.get("name") or ""), "enabled": bool(x.get("enabled", True)),
                               "dynamic": _truthy(x.get("dynamicDiscovery")), "connector_group_ids": ids(x.get("appConnectorGroups"))} for x in sg_rows]
        d["connector_groups"] = [{
            "id": str(x.get("id") or ""), "name": str(x.get("name") or ""), "enabled": bool(x.get("enabled", True)),
            "location": str(x.get("location") or x.get("cityCountry") or ""), "profile": str(x.get("versionProfileName") or ""),
            "upgrade_day": str(x.get("upgradeDay") or "").title(), "upgrade_secs": int(x["upgradeTimeInSecs"]) if str(x.get("upgradeTimeInSecs") or "").isdigit() else None,
            "server_groups": len(x.get("serverGroups") or [])} for x in cg_rows]
        d["idps"] = None if idp_rows is None else [{
            "id": str(x.get("id") or ""), "name": str(x.get("name") or ""), "enabled": bool(x.get("enabled", True)),
            "sso": ", ".join(str(v).title() for v in x.get("ssoType") or []), "scim": _truthy(x.get("scimEnabled")),
            "domains": [str(v) for v in (x.get("domainList") or [])[:8]], "groups": None} for x in idp_rows]
        # Groups synced from each identity provider (who rules can be written against).
        scim_names, d["groups"] = {}, []
        for idp in [i for i in d["idps"] or [] if i["scim"]][:4]:
            rows = await opt(f"groups for {idp['name']}", _zpa_list(c, f"{base}/zpa/userconfig/v1/customers/{customer}/scimgroup/idpId/{idp['id']}", tok, pages=4), None)
            if rows is not None:
                idp["groups"] = len(rows)
                for g in rows:
                    scim_names[str(g.get("id"))] = str(g.get("name") or "")
                    d["groups"].append({"id": str(g.get("id") or ""), "name": str(g.get("name") or "")[:120], "idp": idp["name"], "rules": 0})
        seg_names = {s["id"]: s["name"] for s in d["segments"]}
        grp_names = {g["id"]: g["name"] for g in d["segment_groups"]}
        d["rules"] = [_zpa_rule(r, seg_names, grp_names, scim_names) for r in rule_rows or []]
        d["rules_known"] = rule_rows is not None
        used = {}
        for r, raw in zip(d["rules"], rule_rows or []):
            for cond in raw.get("conditions") or []:
                for o in (cond.get("operands") or []) if isinstance(cond, dict) else []:
                    if isinstance(o, dict) and str(o.get("objectType") or "").upper() == "SCIM_GROUP":
                        used[str(o.get("rhs"))] = used.get(str(o.get("rhs")), 0) + 1
        for g in d["groups"]:
            g["rules"] = used.get(g["id"], 0)
        d["groups"].sort(key=lambda g: (-g["rules"], g["name"].lower()))
        d["groups_total"], d["groups"] = len(d["groups"]), d["groups"][:400]
        d["lss"] = None if lss_rows is None else [{
            "name": str((x.get("config") or x).get("name") or ""), "enabled": bool((x.get("config") or x).get("enabled", True)),
            "type": str((x.get("config") or x).get("sourceLogType") or "").replace("zpn_", "").replace("_", " "),
            "host": str((x.get("config") or x).get("lssHost") or ""), "port": str((x.get("config") or x).get("lssPort") or ""),
            "tls": _truthy((x.get("config") or x).get("useTls"))} for x in lss_rows]
        d["edges"] = [{"name": str(x.get("name") or ""), "enabled": bool(x.get("enabled", True)),
                       "status": str(x.get("controlChannelStatus") or "").replace("ZPN_STATUS_", "").replace("_", " ").title(),
                       "healthy": str(x.get("controlChannelStatus") or "").endswith("AUTHENTICATED"),
                       "group": str(x.get("serviceEdgeGroupName") or ""), "version": str(x.get("currentVersion") or ""),
                       "public_ip": str(x.get("publicIp") or "")} for x in edge_rows]
        # Users: ZPA's own API has no list of users or sessions. Client Connector does know which enrolled
        # devices have Private Access switched on, who is signed in on them and when they were last seen.
        dev_rows = await opt("Client Connector devices", _zs_get(c, f"{base}/zcc/papi/public/v1/getDevices", tok, {"page": 1, "pageSize": 1000}), None)
        d["users"] = None
        if dev_rows is not None:
            users = {}
            for x in _as_list(dev_rows, "devices"):
                if not isinstance(x, dict):
                    continue
                name = str(x.get("user") or x.get("username") or "").strip()
                u = users.setdefault(name.lower() or "(no user)", {"name": name or "(no user)", "devices": [], "zpa": 0, "last_seen": None})
                seen = _ts(x.get("zpaLastSeenTime")) or _ts(x.get("last_seen_time"))
                on = _truthy(x.get("zpaEnabled"))
                u["devices"].append({"name": str(x.get("machineHostname") or "")[:80], "os": str(x.get("osVersion") or "")[:80],
                                     "version": str(x.get("agentVersion") or ""), "state": str(x.get("registrationState") or x.get("state") or ""),
                                     "zpa": on, "zpa_health": str(x.get("zpaHealth") or ""), "policy": str(x.get("policyName") or "")[:80],
                                     "last_seen": seen})
                u["zpa"] += 1 if on else 0
                if seen and (u["last_seen"] or 0) < seen:
                    u["last_seen"] = seen
            d["users"] = sorted(users.values(), key=lambda u: u["name"].lower())[:1000]
        _zpa_cache.clear()
        _zpa_cache[customer] = {"t": time.time(), "d": d}

    view = {k: (copy.deepcopy(v) if k in ("segments", "rules") else v) for k, v in d.items()}
    view["connectors"], view["connectors_known"] = out["connectors"], True
    view["findings"] = zpa_diagnose(view) if (view["segments_known"] or view["rules_known"]) else []
    out["segments"] = len(view["segments"]) if view["segments_known"] else None
    out["detail"] = {k: v for k, v in view.items() if k not in ("connectors", "connectors_known")}
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


_zdx_cache = {}
ZDX_DETAIL_TTL = 600   # per-app history and alert detail are re-read at most this often (tight rate limits)
ZDX_MAX_APPS = 10      # apps that get score history and metrics, worst score first


def _zdx_series(body):
    """[(metric, unit, [(ts, value), ...])] from a ZDX time-series reply (a list or one object)."""
    out = []
    for m in (body if isinstance(body, list) else [body] if isinstance(body, dict) else []):
        if not isinstance(m, dict):
            continue
        pts = [(d.get("timestamp"), d.get("value")) for d in m.get("datapoints") or [] if isinstance(d, dict)
               and isinstance(d.get("value"), (int, float)) and d["value"] >= 0]
        out.append((str(m.get("metric") or ""), str(m.get("unit") or ""), pts))
    return out


def _zdx_place(v):
    if not isinstance(v, dict):
        return ""
    return ", ".join(str(v[k]) for k in ("city", "state", "region", "country") if v.get(k))[:80] or str(v.get("name") or "")


def _zdx_groups(items):
    """'New York (12), Lab (3)' from an alert's locations / departments / geolocations."""
    out = []
    for it in items if isinstance(items, list) else []:
        if isinstance(it, dict) and it.get("name"):
            out.append({"name": str(it["name"])[:80], "devices": it.get("num_devices") if isinstance(it.get("num_devices"), int) else None})
    return out[:12]


def zdx_diagnose(apps, alerts):
    """What stands out in the ZDX data already read; worst first."""
    found = []
    add = lambda level, kind, subject, text: found.append({"level": level, "kind": kind, "subject": subject, "text": text})  # noqa: E731
    for a in alerts or []:
        where = ", ".join(g["name"] for g in (a["locations"] or a["geo"])[:3])
        since = f"Ongoing since {time.strftime('%d %b %H:%M', time.gmtime(a['started']))} UTC" if a["started"] else "Ongoing"
        add("crit" if str(a["severity"]).lower() in ("critical", "high") else "warn", "alert", a["rule"] or "Alert",
            since + (f" for {a['app']}" if a["app"] else "") + (f", {a['devices']} devices affected" if a["devices"] else "")
            + (f" ({where})" if where else "") + ".")
    for a in apps:
        sc = a["score"]
        if sc is None:
            if not a["users"]:
                add("info", "application", a["name"], "No score: no users are being measured for this application.")
            continue
        if sc < 34:
            add("crit", "application", a["name"], f"Poor experience: score {sc}.")
        elif sc < 66:
            add("warn", "application", a["name"], f"Fair experience: score {sc}.")
        if a.get("avg") is not None and a["avg"] - sc >= 15:
            add("warn", "application", a["name"], f"Score dropped to {sc} from a 24-hour average of {a['avg']}.")
        elif a.get("low") is not None and a["low"] < 34 <= sc:
            add("info", "application", a["name"], f"Recovered: score fell as low as {a['low']} in the last 24 hours.")
        total = (a["poor"] or 0) + (a["okay"] or 0) + (a["good"] or 0)
        if total >= 4 and (a["poor"] or 0) * 4 >= total and sc >= 34:
            add("warn", "application", a["name"], f"{a['poor']} of {total} measured users have a poor experience even though the overall score is {sc}.")
        if a["region"] and sc < 66:
            add("info", "application", a["name"], f"Most affected region: {a['region']}.")
    rank = {"crit": 0, "warn": 1, "info": 2}
    found.sort(key=lambda f: rank[f["level"]])
    return found


async def _zdx(c, base, tok):
    root = f"{base}/zdx/v1"
    apps = []
    for a in _as_list(await _zs_get(c, f"{root}/apps", tok), "apps"):
        if not isinstance(a, dict):
            continue
        score, st = a.get("score"), a.get("stats") if isinstance(a.get("stats"), dict) else {}
        n = lambda k: st.get(k) if isinstance(st.get(k), int) else None  # noqa: E731
        apps.append({"id": str(a.get("id") or ""), "name": a.get("name") or "", "users": a.get("total_users"),
                     "score": round(score) if isinstance(score, (int, float)) and score >= 0 else None,
                     "active_users": n("active_users"), "active_devices": n("active_devices"),
                     "poor": n("num_poor"), "okay": n("num_okay"), "good": n("num_good"),
                     "region": _zdx_place(a.get("most_impacted_region")), "avg": None, "low": None, "metrics": []})
    scored = [a["score"] for a in apps if a["score"] is not None]
    out = {"apps": apps, "score": round(sum(scored) / len(scored)) if scored else None, "alerts": None}

    hit = _zdx_cache.get(base)
    if hit and hit["t"] > time.time() - ZDX_DETAIL_TTL:
        d = hit["d"]
    else:
        d = {"notes": [], "read_at": time.time(), "history": {}, "ongoing": None, "recent": None}
        limited = []

        async def opt(label, url, params=None):
            if limited:
                return None
            try:
                return await _zs_get(c, url, tok, params)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    limited.append(1)
                    d["notes"].append("Zscaler rate limit reached; some history was skipped")
                elif label:
                    d["notes"].append(f"{label}: HTTP {e.response.status_code}")
            except (httpx.HTTPError, ValueError) as e:
                if label:
                    d["notes"].append(f"{label}: {type(e).__name__}")
            return None

        def alert(a, ongoing):
            app = a.get("application") if isinstance(a.get("application"), dict) else {}
            groups = {k: _zdx_groups(a.get(k)) for k in ("locations", "departments", "geolocations")}
            dev = [g["devices"] for g in groups["locations"] or groups["geolocations"] if g["devices"] is not None]
            return {"id": str(a.get("id") or ""), "rule": str(a.get("rule_name") or "")[:160], "severity": str(a.get("severity") or ""),
                    "type": str(a.get("alert_type") or "").replace("_", " ").title(), "status": str(a.get("alert_status") or ("ONGOING" if ongoing else "")).title(),
                    "app": str(app.get("name") or ""), "started": _ts(a.get("started_on")), "ended": _ts(a.get("ended_on")),
                    "locations": groups["locations"], "departments": groups["departments"], "geo": groups["geolocations"],
                    "devices": sum(dev) if dev else None}

        body = await opt("ongoing alerts", f"{root}/alerts/ongoing")
        if body is not None:
            d["ongoing"] = [alert(a, True) for a in _as_list(body, "alerts")[:100] if isinstance(a, dict)]
        body = await opt("recent alerts", f"{root}/alerts/historical", {"since": 24})
        if body is not None:
            d["recent"] = [alert(a, False) for a in _as_list(body, "alerts")[:50] if isinstance(a, dict)]
        # Score history and metrics for the apps that most need a look (two calls each).
        worst = sorted([a for a in apps if a["id"] and a["score"] is not None], key=lambda a: a["score"])[:ZDX_MAX_APPS]
        for a in worst:
            h = {"avg": None, "low": None, "metrics": []}
            body = await opt("", f"{root}/apps/{a['id']}/score", {"since": 24})
            pts = [v for _, _, series in _zdx_series(body) for _, v in series]
            if pts:
                h["avg"], h["low"] = round(sum(pts) / len(pts)), round(min(pts))
            body = await opt("", f"{root}/apps/{a['id']}/metrics", {"since": 24})
            for metric, unit, series in _zdx_series(body):
                vals = [v for _, v in series]
                if metric and vals:
                    h["metrics"].append({"name": metric, "unit": unit, "last": round(vals[-1], 1), "avg": round(sum(vals) / len(vals), 1),
                                         "max": round(max(vals), 1)})
            d["history"][a["id"]] = h
        _zdx_cache.clear()
        _zdx_cache[base] = {"t": time.time(), "d": d}

    for a in apps:
        a.update(d["history"].get(a["id"], {}))
    out["alerts"] = None if d["ongoing"] is None else len(d["ongoing"])
    out["detail"] = {"ongoing": d["ongoing"], "recent": d["recent"], "notes": d["notes"], "read_at": d["read_at"],
                     "findings": zdx_diagnose(apps, d["ongoing"])}
    return out


def _detectors(items):
    out = []
    for d in items if isinstance(items, list) else []:
        if isinstance(d, dict):
            out.append({"detector": str(d.get("detector") or d.get("name") or ""), "action": str(d.get("action") or ""),
                        "enabled": d.get("enabled") is not False, "severity": str(d.get("severity") or "")})
    return out


def ai_diagnose(d):
    """Static checks over the AI Guard configuration; worst first. Makes no calls."""
    found = []
    add = lambda level, kind, subject, text: found.append({"level": level, "kind": kind, "subject": subject, "text": text})  # noqa: E731
    pols = {p["id"]: p for p in d["policy_list"]}
    rules = sorted(d["rules"] or [], key=lambda r: r["order"] if isinstance(r["order"], int) else 1e9)
    used, blocker = set(), None
    for i, r in enumerate(rules):
        if not r["enabled"]:
            add("info", "rule", r["name"], "Match rule is disabled, so it is never evaluated.")
            continue
        pol = pols.get(r["policy_id"])
        if pol is None and d["policy_list"]:
            add("crit", "rule", r["name"], "Points at a policy that no longer exists.")
        elif pol is not None and not pol["enabled"]:
            add("warn", "rule", r["name"], f"Applies policy “{pol['name']}”, which is disabled.")
        if blocker:
            add("warn", "rule", r["name"], f"Never reached: rule “{blocker}” has no match conditions and matches everything first.")
            continue
        if pol is not None:
            used.add(pol["id"])
        if not r["scope"] and any(x["enabled"] for x in rules[i + 1:]):
            blocker = r["name"]
    for p in d["policy_list"]:
        dets = p["input"] + p["output"]
        on = [x for x in dets if x["enabled"]]
        if not p["enabled"]:
            add("info", "policy", p["name"], "Policy is disabled.")
            continue
        if d["rules"] is not None and p["id"] not in used:
            add("warn", "policy", p["name"], "No enabled match rule applies this policy, so it is never used.")
        if not on:
            add("warn", "policy", p["name"], "Has no enabled detector: prompts and responses pass unchecked.")
        elif not any("block" in x["action"].lower() for x in on) and "block" not in p["default_action"].lower():
            add("info", "policy", p["name"], "Detect-only: no enabled detector blocks, and the default action is not block.")
        if p["input"] and not any(x["enabled"] for x in p["input"]):
            add("info", "policy", p["name"], "Every prompt detector is switched off.")
        if p["output"] and not any(x["enabled"] for x in p["output"]):
            add("info", "policy", p["name"], "Every response detector is switched off.")
        off = [x["detector"] for x in dets if not x["enabled"]]
        if on and off:
            add("info", "policy", p["name"], f"{len(off)} detector(s) switched off: {', '.join(off[:4])}{'…' if len(off) > 4 else ''}.")
    now = time.time()
    for cr in d["provider_credentials"] or []:
        if cr["expires"] and cr["expires"] < now:
            add("crit", "credential", cr["name"], "Provider credential has expired.")
        elif cr["expires"] and cr["expires"] < now + 30 * 86400:
            add("warn", "credential", cr["name"], f"Provider credential expires in {max(0, int((cr['expires'] - now) // 86400))} days.")
    if d["app_list"] is not None and d["app_credentials"] is not None:
        with_cred = {c["app_id"] for c in d["app_credentials"]}
        for a in d["app_list"]:
            if a["id"] not in with_cred:
                add("info", "application", a["name"], "Has no application credential, so it cannot call AI Guard.")
    rank = {"crit": 0, "warn": 1, "info": 2}
    found.sort(key=lambda f: rank[f["level"]])
    return found


async def _aiguard(c, base, tok):
    root = f"{base}/aiguard/v1"
    out = {"policies": None, "providers": None, "applications": None, "policy_names": [], "policy_list": [], "rules": None,
           "provider_list": None, "app_list": None, "app_credentials": None, "provider_credentials": None, "notes": []}
    pols = [p for p in _as_list(await _zs_get(c, f"{root}/detections/policies", tok), "policies") if isinstance(p, dict)]
    out["policies"] = len(pols)
    out["policy_names"] = [str(p.get("name") or "") for p in pols][:50]
    names = {p.get("id"): str(p.get("name") or "") for p in pols}
    out["policy_list"] = [{
        "id": str(p.get("id") or ""), "name": str(p.get("name") or ""), "enabled": p.get("enabled") is not False,
        "default_action": str(p.get("defaultAction") or ""), "description": str(p.get("description") or "")[:200],
        "updated": _ts(p.get("updateTimeMillis")),
        "input": _detectors(p.get("inputDetectorPolicies")), "output": _detectors(p.get("outputDetectorPolicies")),
    } for p in pols[:50]]

    async def opt(label, path, *keys):
        try:
            return [x for x in _as_list(await _zs_get(c, f"{root}/{path}", tok), *keys) if isinstance(x, dict)]
        except httpx.HTTPStatusError as e:
            out["notes"].append(f"{label}: HTTP {e.response.status_code}")
        except (httpx.HTTPError, ValueError) as e:
            out["notes"].append(f"{label}: {type(e).__name__}")
        return None

    rules = await opt("match rules", "detections/policy-match-rules", "rules")
    provs = await opt("providers", "llm-providers", "providers")
    apps = await opt("applications", "llm-applications", "applications")
    acreds = await opt("application credentials", "llm-application-credentials", "credentials")
    pcreds = await opt("provider credentials", "llm-provider-credentials", "credentials")
    prov_names = {str(x.get("id")): str(x.get("name") or "") for x in provs or []}
    app_names = {str(x.get("id")): str(x.get("name") or "") for x in apps or []}
    if rules is not None:
        def scope(r):
            mc = r.get("matchCriteria") if isinstance(r.get("matchCriteria"), dict) else {}
            parts = []
            for key, label in (("llmApplications", "Application"), ("applicationGroups", "Application group"),
                               ("sourceIpAddresses", "Source IP"), ("customRequestHeaders", "Header")):
                vals = mc.get(key) if mc.get(key) else r.get(key)
                for v in (vals if isinstance(vals, list) else [])[:8]:
                    text = app_names.get(str(v.get("id") if isinstance(v, dict) else v)) if key == "llmApplications" else None
                    parts.append(f"{label}: {text or _nm(v) or v}"[:100])
            for v in (r.get("applicationCredentialsIds") or [])[:8]:
                parts.append(f"Credential: {v}"[:100])
            if r.get("applicationId"):
                parts.append("Application: " + (app_names.get(str(r["applicationId"])) or str(r["applicationId"])))
            return parts
        out["rules"] = [{"name": str(r.get("name") or ""), "order": r.get("ruleOrder"), "enabled": r.get("enabled") is not False,
                         "policy_id": str(r.get("policyId") or ""), "policy": names.get(r.get("policyId"), str(r.get("policyId") or "")),
                         "type": str(r.get("type") or ""), "scope": scope(r)} for r in rules[:100]]
    if provs is not None:
        out["providers"] = len(provs)
        out["provider_list"] = [{"id": str(x.get("id") or ""), "name": str(x.get("name") or ""), "type": str(x.get("type") or ""),
                                 "public": bool(x.get("public")), "updated": _ts(x.get("updateTimeMillis"))} for x in provs[:100]]
    if apps is not None:
        out["applications"] = len(apps)
        out["app_list"] = [{"id": str(x.get("id") or ""), "name": str(x.get("name") or ""), "owner": str(x.get("ownerEmail") or ""),
                            "logs_content": bool(x.get("includeEventContents")), "encrypts_content": bool(x.get("encryptEventContents")),
                            "updated": _ts(x.get("updateTimeMillis"))} for x in apps[:200]]
    # Credentials: names, links and expiry only. Key material is never copied out of the reply.
    if acreds is not None:
        out["app_credentials"] = [{"name": str(x.get("name") or ""), "app_id": str(x.get("applicationId") or ""),
                                   "app": app_names.get(str(x.get("applicationId")), ""), "provider": prov_names.get(str(x.get("providerId")), ""),
                                   "mode": str(x.get("mode") or ""), "updated": _ts(x.get("updateTimeMillis"))} for x in acreds[:200]]
    if pcreds is not None:
        out["provider_credentials"] = [{"name": str(x.get("name") or ""), "provider": prov_names.get(str(x.get("providerId")), ""),
                                        "type": str(x.get("type") or ""), "expires": _ts(x.get("expireTimeMillis"))} for x in pcreds[:200]]
    out["findings"] = ai_diagnose(out)
    return out


# ---- Zscaler Z-Insights analytics (GraphQL) ---------------------------------

_Q_WEB = """query($startTime: Long!, $endTime: Long!, $trafficUnit: WebTrafficUnits!, $actionFilter: ActionStatus, $limit: Int) {
  WEB_TRAFFIC { no_grouping(start_time: $startTime, end_time: $endTime, traffic_unit: $trafficUnit, action_filter: $actionFilter) {
    entries(limit: $limit) { name total } } } }"""
_Q_THREATS = """query($startTime: Long!, $endTime: Long!, $trafficUnit: WebTrafficUnits!, $limit: Int) {
  WEB_TRAFFIC { threat_super_categories(start_time: $startTime, end_time: $endTime, traffic_unit: $trafficUnit) {
    entries(limit: $limit) { name total } } } }"""
_Q_FW = """query($startTime: Long!, $endTime: Long!, $limit: Int) {
  ZERO_TRUST_FIREWALL { action(start_time: $startTime, end_time: $endTime) { entries(limit: $limit) { name total } } } }"""
_Q_APPS = """query($startTime: Long!, $endTime: Long!, $limit: Int) {
  SHADOW_IT { apps(start_time: $startTime, end_time: $endTime) { entries(limit: $limit) {
    application application_category risk_index sanctioned_state data_consumed data_uploaded data_downloaded
    authenticated_users last_access_time } } } }"""
_Q_SUMMARY = """query($startTime: Long!, $endTime: Long!) {
  SHADOW_IT { shadow_it_summary(start_time: $startTime, end_time: $endTime) {
    total_upload_bytes total_download_bytes total_apps total_bytes
    group_by_app_cat_for_app { entries { name total } }
    group_by_app_cat_for_user_count { entries { name total } }
    group_by_app_cat_for_total_bytes { entries { name total } } } } }"""
_Q_TYPES = "{ __schema { queryType { fields { name type { name ofType { name } } } } } }"
_Q_FIELDS = "query($n: String!) { __type(name: $n) { fields { name args { name } } } }"


def _entries(node):
    rows = node.get("entries") if isinstance(node, dict) else None
    return [{"name": str(e.get("name") or ""), "total": e.get("total") or 0}
            for e in rows or [] if isinstance(e, dict)]


async def zs_insights(cfg, hours):
    """Aggregate web and application activity for the last `hours` from Z-Insights."""
    z = cfg["zscaler"]
    if not (z["enabled"] and z["zins"] and z["vanity"] and z["client_id"] and z["client_secret"]):
        return {"configured": False}
    out = {"configured": True, "ok": True, "error": "", "hours": hours, "updated": time.time(), "notes": [],
           "web": None, "threats": None, "firewall": None, "url_categories": None, "url_categories_field": "",
           "totals": None, "app_categories": None, "apps": None}
    if not (LABEL_RE.match(z["vanity"]) and LABEL_RE.match(z["cloud"])):
        out.update(ok=False, error="Check the Zscaler vanity domain")
        return out
    url = (f"https://api.{z['cloud']}.zsapi.net" if z["cloud"] else "https://api.zsapi.net") + "/zins/graphql"
    end = int(time.time() * 1000)
    span = {"startTime": end - hours * 3600 * 1000, "endTime": end}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=6.0)) as c:
            tok = await _zs_token(c, z)

            async def gql(query, variables):
                r = await c.post(url, json={"query": query, "variables": variables},
                                 headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"})
                r.raise_for_status()
                body = r.json()
                if isinstance(body, dict) and body.get("errors"):
                    first = body["errors"][0]
                    raise ValueError(str(first.get("message") if isinstance(first, dict) else first)[:160])
                return (body.get("data") or {}) if isinstance(body, dict) else {}

            async def part(label, coro):
                try:
                    return await coro
                except httpx.HTTPStatusError as e:
                    if e.response.status_code in (401, 403) and label == "web":
                        raise
                    out["notes"].append(f"{label}: HTTP {e.response.status_code}")
                except (httpx.HTTPError, ValueError) as e:
                    out["notes"].append(f"{label}: {str(e)[:120] or type(e).__name__}")
                return None

            async def web_total(action):
                d = await gql(_Q_WEB, {**span, "trafficUnit": "TRANSACTIONS", "actionFilter": action, "limit": 100})
                return sum(e["total"] for e in _entries((d.get("WEB_TRAFFIC") or {}).get("no_grouping")))

            allowed = await part("web", web_total("ALLOW"))
            blocked = await part("web blocked", web_total("BLOCK"))
            if allowed is not None or blocked is not None:
                out["web"] = {"allowed": allowed, "blocked": blocked}

            d = await part("threat categories", gql(_Q_THREATS, {**span, "trafficUnit": "TRANSACTIONS", "limit": 50}))
            if d is not None:
                out["threats"] = _entries((d.get("WEB_TRAFFIC") or {}).get("threat_super_categories"))
            d = await part("firewall", gql(_Q_FW, {**span, "limit": 20}))
            if d is not None:
                out["firewall"] = _entries((d.get("ZERO_TRUST_FIREWALL") or {}).get("action"))

            d = await part("app summary", gql(_Q_SUMMARY, span))
            if d is not None:
                sm = (d.get("SHADOW_IT") or {}).get("shadow_it_summary") or {}
                out["totals"] = {"apps": sm.get("total_apps"), "bytes": sm.get("total_bytes"),
                                 "upload": sm.get("total_upload_bytes"), "download": sm.get("total_download_bytes")}
                cats = {}
                for key, field in (("apps", "group_by_app_cat_for_app"), ("users", "group_by_app_cat_for_user_count"),
                                   ("bytes", "group_by_app_cat_for_total_bytes")):
                    for e in _entries(sm.get(field)):
                        cats.setdefault(e["name"], {"name": e["name"], "apps": None, "users": None, "bytes": None})[key] = e["total"]
                out["app_categories"] = sorted(cats.values(), key=lambda x: -(x["bytes"] or 0))
            d = await part("applications", gql(_Q_APPS, {**span, "limit": 200}))
            if d is not None:
                rows = ((d.get("SHADOW_IT") or {}).get("apps") or {}).get("entries") or []
                apps = [{"name": str(a.get("application") or ""), "category": str(a.get("application_category") or ""),
                         "state": str(a.get("sanctioned_state") or ""), "risk": a.get("risk_index"),
                         "bytes": a.get("data_consumed"), "upload": a.get("data_uploaded"),
                         "download": a.get("data_downloaded"), "users": a.get("authenticated_users"),
                         "last": a.get("last_access_time")} for a in rows if isinstance(a, dict)]
                out["apps"] = sorted(apps, key=lambda a: -(a["bytes"] or 0))[:200]

            # URL categories are not a documented grouping. Ask the API what it offers and use a
            # category grouping only if one exists; otherwise the page says it is unavailable.
            async def url_categories():
                types = await gql(_Q_TYPES, {})
                web = next((f for f in types["__schema"]["queryType"]["fields"] if f["name"] == "WEB_TRAFFIC"), None)
                tname = (web["type"].get("name") or (web["type"].get("ofType") or {}).get("name")) if web else None
                if not tname:
                    return
                fields = (await gql(_Q_FIELDS, {"n": tname}))["__type"]["fields"]
                cand = next((f for f in fields if "categor" in f["name"].lower() and "threat" not in f["name"].lower()), None)
                if not cand:
                    return
                args = {a["name"] for a in cand.get("args") or []}
                if not {"start_time", "end_time"} <= args:
                    return
                decl, call, base_vars = ["$startTime: Long!", "$endTime: Long!", "$limit: Int"], ["start_time: $startTime", "end_time: $endTime"], dict(span, limit=200)
                if "traffic_unit" in args:
                    decl.append("$trafficUnit: WebTrafficUnits!"); call.append("traffic_unit: $trafficUnit"); base_vars["trafficUnit"] = "TRANSACTIONS"
                split = "action_filter" in args
                if split:
                    decl.append("$actionFilter: ActionStatus"); call.append("action_filter: $actionFilter")
                q = f"query({', '.join(decl)}) {{ WEB_TRAFFIC {{ {cand['name']}({', '.join(call)}) {{ entries(limit: $limit) {{ name total }} }} }} }}"
                rows = {}
                for action in (("ALLOW", "BLOCK") if split else (None,)):
                    v = dict(base_vars, actionFilter=action) if split else base_vars
                    for e in _entries(((await gql(q, v)).get("WEB_TRAFFIC") or {}).get(cand["name"])):
                        row = rows.setdefault(e["name"], {"name": e["name"], "allowed": None, "blocked": None, "total": None})
                        row["allowed" if action == "ALLOW" else "blocked" if action == "BLOCK" else "total"] = e["total"]
                out["url_categories"] = sorted(rows.values(), key=lambda r: -((r["allowed"] or 0) + (r["blocked"] or 0) + (r["total"] or 0)))[:200]
                out["url_categories_field"] = cand["name"]

            try:
                await url_categories()
            except Exception:  # noqa: BLE001 - optional discovery; absence is reported in the UI
                pass
            if out["web"] is None and out["apps"] is None and out["totals"] is None:
                out.update(ok=False, error="; ".join(out["notes"]) or "No analytics data returned")
    except Exception as e:  # noqa: BLE001
        out.update(ok=False, error=_err(e))
    return out


async def zdx_users(cfg, hours, max_detail=150):
    """ZDX users active in the last `hours`, with their devices, locations and app scores.

    Costs one request per page of users plus up to two per detailed user, so it is run on a
    slow schedule and capped; ZDX rate limits are tight."""
    z = cfg["zscaler"]
    if not (z["enabled"] and z["zdx"] and z["vanity"] and z["client_id"] and z["client_secret"]):
        return {"configured": False}
    if not (LABEL_RE.match(z["vanity"]) and LABEL_RE.match(z["cloud"])):
        return {"configured": True, "ok": False, "error": "Check the Zscaler vanity domain", "updated": time.time()}
    base = (f"https://api.{z['cloud']}.zsapi.net" if z["cloud"] else "https://api.zsapi.net") + "/zdx/v1"
    out = {"configured": True, "ok": True, "error": "", "hours": hours, "updated": time.time(),
           "total": 0, "detailed": 0, "limited": False, "users": []}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            tok = await _zs_token(c, z)
            listed, offset = [], None
            for _ in range(20):
                params = {"since": hours, "limit": 200}
                if offset:
                    params["offset"] = offset
                body = await _zs_get(c, base + "/users", tok, params)
                page = body[0] if isinstance(body, list) and body and isinstance(body[0], dict) and "users" in body[0] else body
                listed += [u for u in _as_list(page, "users") if isinstance(u, dict)]
                offset = page.get("next_offset") if isinstance(page, dict) else None
                if not offset:
                    break
            out["total"] = len(listed)
            sem, limited = asyncio.Semaphore(2), []

            async def get(url):
                if limited:
                    return None
                async with sem:
                    r = await c.get(url, headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"},
                                    params={"since": hours})
                if r.status_code == 429:
                    limited.append(1)
                return r.json() if r.status_code == 200 else None

            def place(items, *keys):
                names = []
                for it in items if isinstance(items, list) else []:
                    if isinstance(it, dict):
                        text = ", ".join(str(it[k]) for k in keys if it.get(k))
                        if text and text not in names:
                            names.append(text)
                return names

            async def detail(u):
                rec = {"id": u.get("id"), "name": u.get("name") or "", "email": u.get("email") or "",
                       "devices": [], "detailed": False}
                try:
                    body = await get(f"{base}/users/{u.get('id')}")
                    if not isinstance(body, dict):
                        return rec
                    rec["detailed"] = True
                    for d in (body.get("devices") or [])[:5]:
                        if not isinstance(d, dict):
                            continue
                        dev = {"id": d.get("id"), "name": d.get("name") or "", "locations": place(d.get("zs_loc"), "name"),
                               "geo": place(d.get("geo_loc"), "city", "state", "country"), "apps": [], "score": None}
                        apps = await get(f"{base}/devices/{d.get('id')}/apps")
                        for a in _as_list(apps, "apps"):
                            sc = a.get("score") if isinstance(a, dict) else None
                            if isinstance(sc, (int, float)) and sc >= 0:
                                dev["apps"].append({"name": a.get("name") or "", "score": round(sc)})
                        if dev["apps"]:
                            dev["score"] = round(sum(a["score"] for a in dev["apps"]) / len(dev["apps"]))
                        rec["devices"].append(dev)
                except httpx.HTTPError:
                    pass
                return rec

            head = listed[:max_detail]
            out["users"] = list(await asyncio.gather(*(detail(u) for u in head)))
            out["users"] += [{"id": u.get("id"), "name": u.get("name") or "", "email": u.get("email") or "",
                              "devices": [], "detailed": False} for u in listed[max_detail:2000]]
            out["detailed"] = sum(1 for u in out["users"] if u["detailed"])
            out["limited"] = bool(limited)
    except Exception as e:  # noqa: BLE001
        out.update(ok=False, error=_err(e))
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


# ---- Zscaler Zero Trust Branch (former Airgap; API key, read-only calls) ----
# Not part of OneAPI: sign in with the tenant's API key at https://<tenant>.goairgap.com
# (POST /api/v3/api-key-auth/login -> result.delegate_token), then send it as a Bearer token.
# Every data call below is a GET.

_ztb_tokens = {}
ZTB_MAX_SITES, ZTB_MAX_DEVICES = 20, 2000  # sites: cap on per-site overview fallbacks


def _ztb_base(cloud):
    """`cloud` is either a full https:// API address or the tenant label before .goairgap.com."""
    return cloud if cloud.startswith("https://") else f"https://{cloud}.goairgap.com"


def _ztb_oneapi_base(cloud):
    return f"https://api.{cloud}.zsapi.net" if cloud else "https://api.zsapi.net"


def _ztb_items(body):
    """List responses arrive as {"result": {"<name>": [...]}}, {"result": [...]} or {"rows": [...]}."""
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    res = body.get("result")
    if isinstance(res, list):
        return res
    for node in (res, body):
        if isinstance(node, dict):
            for v in node.values():
                if isinstance(v, list):
                    return v
    return []


def _ts(value):
    """Epoch seconds from epoch seconds, epoch milliseconds or an ISO timestamp; else None."""
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return value / 1000 if value > 1e11 else value
    text = str(value).strip()
    try:
        if re.fullmatch(r"[0-9.]+", text):
            return _ts(float(text))
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _names(value):
    """A field that may be a string, a comma-separated string, or a list of strings or objects."""
    if isinstance(value, str):
        value = value.split(",")
    out = []
    for v in value if isinstance(value, list) else []:
        if isinstance(v, dict):
            v = v.get("name") or v.get("username") or v.get("user") or v.get("display_name") or ""
        v = str(v or "").strip()
        if v and v not in out:
            out.append(v[:120])
    return out


class ZtbAuthError(Exception):
    """No way of presenting the API key was accepted; str() lists what each attempt returned."""


def _ztb_reply(r, api_key):
    """Status plus a short, key-free excerpt of the body, to tell a gateway refusal from a bad key."""
    text = " ".join((r.text or "").split()).replace(api_key, "***")[:90]
    return f"HTTP {r.status_code}" + (f" ({text})" if text else "")


async def _ztb_login(c, base, api_key, gateway_token=None):
    """Exchange the API key for a session token. Returns (token or None, description of the reply).
    `gateway_token` is a OneAPI token sent only to get the request past Zscaler's API gateway."""
    headers = {"Accept": "application/json"}
    if gateway_token:
        headers["Authorization"] = "Bearer " + gateway_token
    r = await c.post(base + "/api/v3/api-key-auth/login", json={"api_key": api_key}, headers=headers)
    if r.status_code >= 400:
        return None, _ztb_reply(r, api_key)
    try:
        body = r.json()
    except ValueError:
        return None, "HTTP 200 but not JSON"
    res = body.get("result") if isinstance(body, dict) else None
    tok = res.get("delegate_token") if isinstance(res, dict) else None
    return (tok, "ok") if tok else (None, "HTTP 200 but no delegate_token in the reply")


async def _ztb_auth(c, base, api_key, key, fresh=False, gateway_token=None):
    """Work out how this tenant takes the API key, and cache the answer.

    The documented way is a login call that swaps the key for a token. Tenants run from the main
    Zscaler console publish their API under api.zsapi.net/private/..., which is the console's own
    session route, so the same paths are also tried without /private, and the key is tried directly
    as a Bearer token and as an x-api-key header. Returns {"base", "headers", "how"}.
    """
    hit = _ztb_tokens.get(key)
    if hit and hit["until"] > time.time() and not fresh:
        return hit
    bases = [base] + ([base.replace("/private/", "/", 1)] if "/private/" in base + "/" else [])
    tried = []
    for b in bases:
        where = b.split("://", 1)[1]
        tok, said = await _ztb_login(c, b, api_key)
        if tok:
            found = {"base": b, "headers": {"Authorization": "Bearer " + tok}, "how": "login", "until": time.time() + 1800}
            break
        tried.append(f"login at {where}: {said}")
        for how, headers in (("key as Bearer token", {"Authorization": "Bearer " + api_key}), ("key as x-api-key", {"x-api-key": api_key})):
            r = await c.get(b + "/api/v2/Site/names", headers={**headers, "Accept": "application/json"})
            if r.status_code < 400:
                found = {"base": b, "headers": headers, "how": how, "until": time.time() + 86400}
                break
            tried.append(f"{how} at {where}: {_ztb_reply(r, api_key)}")
        else:
            if gateway_token:  # last resort: OneAPI token to pass the gateway, API key to sign in behind it
                tok, said = await _ztb_login(c, b, api_key, gateway_token)
                if tok:
                    headers = {"Authorization": "Bearer " + tok}
                    r = await c.get(b + "/api/v2/Site/names", headers={**headers, "Accept": "application/json"})
                    if r.status_code < 400:
                        found = {"base": b, "headers": headers, "how": "login", "gateway": True, "until": time.time() + 1800}
                        break
                    said = "signed in, but the token was then refused: " + _ztb_reply(r, api_key)
                tried.append(f"login with OneAPI token at {where}: {said}")
            continue
        break
    else:
        raise ZtbAuthError("; ".join(tried))
    _ztb_tokens.clear()
    _ztb_tokens[key] = found
    return found


async def collect_ztb(cfg):
    """Two ways in. With a tenant and API key: the standalone API at <tenant>.goairgap.com.
    With both left blank: the same paths through OneAPI (/ztb on api.zsapi.net) using the
    Zscaler client above, for tenants that manage Zero Trust Branch inside the main console."""
    b, z = cfg["ztb"], cfg["zscaler"]
    if not b["enabled"]:
        return {"configured": False}
    direct = bool(b["cloud"] or b["api_key"])
    if direct and not (b["cloud"] and b["api_key"]):
        return {"configured": True, "ok": False, "error":
                "Enter both the tenant and the API key, or leave both blank to use the Zscaler OneAPI client."}
    if direct and not (b["cloud"].startswith("https://") or LABEL_RE.match(b["cloud"])):
        return {"configured": True, "ok": False,
                "error": "API address should be a full https:// address, or the part before .goairgap.com"}
    if not direct:
        if not (z["vanity"] and z["client_id"] and z["client_secret"]):
            return {"configured": True, "ok": False, "error":
                    "Fill in the Zscaler OneAPI client in Settings, or enter a Zero Trust Branch tenant and API key."}
        if not (LABEL_RE.match(z["vanity"]) and LABEL_RE.match(z["cloud"])):
            return {"configured": True, "ok": False, "error": "Check the Zscaler vanity domain"}
    root = base = _ztb_base(b["cloud"]) if direct else _ztb_oneapi_base(z["cloud"])
    key = (b["cloud"], hashlib.sha256(b["api_key"].encode()).hexdigest())
    out = {"configured": True, "ok": True, "error": "", "tenant": b["cloud"] if direct else z["vanity"],
           "via": "API key" if direct else "OneAPI", "notes": [],
           "sites": [], "devices": [], "devices_total": 0, "users": [], "alarms": None}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as c:
            state_gw = None
            try:
                if direct:
                    gw = None
                    if z["vanity"] and z["client_id"] and z["client_secret"] and LABEL_RE.match(z["vanity"]) and LABEL_RE.match(z["cloud"]):
                        try:
                            gw = await _zs_token(c, z)
                        except httpx.HTTPError:
                            gw = None
                    state_gw = gw
                    auth = await _ztb_auth(c, base, b["api_key"], key, gateway_token=gw)
                    root = base = auth["base"]
                else:
                    auth = {"headers": {"Authorization": "Bearer " + await _zs_token(c, z)}, "how": "oneapi"}
            except ZtbAuthError as e:
                return {"configured": True, "ok": False, "error":
                        "Zero Trust Branch could not be reached with this API key. Tried: " + str(e) + ". The same "
                        "generic 401 on every attempt means Zscaler's gateway refused the request before the key was "
                        "checked; ask Zscaler for the API host name your tenant's Zero Trust Branch API keys work against."}
            except httpx.HTTPStatusError as e:
                hint = " Check the Zscaler client ID and secret." if e.response.status_code in (400, 401, 403) else ""
                return {"configured": True, "ok": False, "error": "Sign-in failed: " + _err(e) + "." + hint}
            except httpx.ConnectError as e:
                host = _ztb_base(b["cloud"]).split("://", 1)[1] if direct else f"{z['vanity']}.zslogin{z['cloud']}.net"
                return {"configured": True, "ok": False, "error":
                        f"Sign-in failed: cannot reach {host} ({str(e)[:80]}). Check the API address."}
            state = {"auth": auth}

            async def get(path, params=None):
                for attempt in (0, 1):
                    r = await c.get(base + path, params=params, headers={**state["auth"]["headers"], "Accept": "application/json"})
                    if r.status_code == 401 and attempt == 0 and state["auth"]["how"] == "login":  # token expired: sign in again, once
                        state["auth"] = await _ztb_auth(c, state["auth"]["base"], b["api_key"], key, fresh=True, gateway_token=state_gw)
                        continue
                    r.raise_for_status()
                    return r.json()

            async def optional(label, coro):
                try:
                    return await coro
                except httpx.HTTPStatusError as e:
                    out["notes"].append(f"{label}: HTTP {e.response.status_code}")
                except (httpx.HTTPError, ValueError) as e:
                    out["notes"].append(f"{label}: {type(e).__name__}")
                return None

            # Sites. /Site/names is what Zscaler's own console calls; /Site/ is the SDK's list. Under OneAPI
            # the product prefix is not documented, so try both spellings before giving up.
            async def site_list():
                try:
                    return await get("/api/v2/Site/names")
                except httpx.HTTPStatusError as e:
                    if e.response.status_code in (401, 403):
                        raise
                    return await get("/api/v2/Site/", {"page": 1, "limit": 200})

            tried = []
            for prefix in ([""] if direct else ["/ztb", "/ztds", "/private/ztds"]):
                base = root + prefix
                try:
                    first = await site_list()
                    break
                except httpx.HTTPStatusError as e:
                    if direct:
                        raise
                    tried.append(f"{prefix} HTTP {e.response.status_code}")
            else:
                # OneAPI signed in but would not serve Zero Trust Branch: say what to try, not just the code
                return {"configured": True, "ok": False, "error":
                        "Zscaler OneAPI did not serve Zero Trust Branch (" + ", ".join(tried) + "). The API client may "
                        "need a Zero Trust Branch resource granted in ZIdentity; if none is offered there, ask Zscaler "
                        "how to reach the Zero Trust Branch API for a tenant managed in the main console."}
            listed = [s for s in _ztb_items(first) if isinstance(s, dict)]

            def gateway(g, cluster=""):
                st, color = str(g.get("operational_state") or ""), str(g.get("health_color") or "").lower()
                bad = color == "red" or st.lower() in ("down", "offline", "inactive", "unreachable", "disconnected", "failed")
                good = color == "green" or st.lower() in ("up", "active", "standby", "online", "running", "connected", "healthy")
                ip = lambda k: "" if str(g.get(k) or "") in ("", "0.0.0.0") else str(g.get(k))  # noqa: E731
                return {"id": str(g.get("gateway_id") or ""), "name": str(g.get("display_name") or g.get("gateway_name") or ""),
                        "hostname": str(g.get("gateway_name") or ""), "cluster": str(cluster or g.get("cluster_id") or ""),
                        "state": str(g.get("display_state") or st), "health": color,
                        # True/False only when the API is unambiguous; None means "not sure", never alerted on
                        "healthy": False if bad else True if good else None, "error": str(g.get("error") or "")[:200],
                        "version": str(g.get("running_version") or ""), "serial": str(g.get("system_serial_tag") or ""),
                        "ha": str(g.get("vrrp_state") or ""), "region": str(g.get("region") or ""),
                        "ip": ip("gateway_ip_address"), "mgmt_ip": ip("mgmt_ip"), "vm_ip": ip("vm_ip_address"), "public_ip": ip("public_ip"),
                        "updated": _ts(g.get("last_poll_updated") or g.get("updatedAt") or g.get("updated_at"))}

            def site(s):
                sid = str(s.get("id") or "")
                clusters = [str(c.get("cluster_id")) for c in (s.get("cluster_info") or s.get("clusters") or [])
                            if isinstance(c, dict) and c.get("cluster_id") is not None]
                return {"id": sid, "name": str(s.get("display_name") or s.get("name") or sid), "key": str(s.get("name") or ""),
                        "status": str(s.get("site_status") or ""), "type": str(s.get("gateway_type") or ""),
                        "health": str(s.get("rks_level") or ""), "public_ip": str(s.get("public_ip") or ""),
                        "clusters": clusters, "gateways": []}

            out["sites"] = [site(s) for s in listed]
            # Gateways (the branch appliances): one list call, joined to sites by cluster id.
            gw_rows = await optional("gateways", get("/api/v2/Gateway/"))
            if gw_rows is not None:
                by_cluster = {c: st for st in out["sites"] for c in st["clusters"]}
                loose = []
                for g in _ztb_items(gw_rows):
                    if isinstance(g, dict):
                        home = by_cluster.get(str(g.get("cluster_id")))
                        (home["gateways"] if home else loose).append(gateway(g))
                if loose:
                    out["sites"].append({"id": "", "name": "Not assigned to a site", "key": "", "status": "", "type": "",
                                         "health": "", "public_ip": "", "clusters": [], "gateways": loose})
            else:
                # Fall back to each site's overview, which nests gateways under clusters.
                async def overview(rec):
                    body = await optional(f"site {rec['name']}", get(f"/api/v2/Site/siteByID/{rec['id']}/overview"))
                    ov = body.get("result") if isinstance(body, dict) and isinstance(body.get("result"), dict) else body
                    for cl in (ov.get("clusters") or []) if isinstance(ov, dict) else []:
                        for g in (cl.get("gateways") or []) if isinstance(cl, dict) else []:
                            if isinstance(g, dict):
                                rec["gateways"].append(gateway(g, cl.get("cluster_name")))
                await asyncio.gather(*(overview(r) for r in out["sites"][:ZTB_MAX_SITES] if r["id"]))

            # The console's own summary counts; used when a list below is not available.
            tiles = await optional("summary counts", get("/api/v2/dashboard/tiles-info"))
            tiles = tiles.get("result") if isinstance(tiles, dict) and isinstance(tiles.get("result"), dict) else {}
            out["counts"] = {k: tiles.get(k + "_count") for k in ("devices", "users", "networks", "threats", "policies")
                             if isinstance(tiles.get(k + "_count"), int)}
            site_names = {s["id"]: s["name"] for s in out["sites"]}

            # Devices seen at the branches (and the directory users signed in on them).
            async def devices():
                rows, first = [], None
                for page in range(1, ZTB_MAX_DEVICES // 200 + 1):
                    got = [d for d in _ztb_items(await get("/api/v2/devices/active", {"page": page, "limit": 200})) if isinstance(d, dict)]
                    ident = (got[0].get("id"), got[0].get("mac")) if got else None
                    if not got or ident == first:  # empty page, or the API ignored `page` and repeated itself
                        break
                    first = first or ident
                    rows += got
                    if len(got) < 200:
                        break
                return rows

            devs = await optional("devices", devices()) or []
            out["devices_total"] = len(devs)
            users = {}
            for d in devs:
                rec = {"id": str(d.get("id") or ""), "name": str(d.get("hostname") or d.get("ip_address") or d.get("mac") or "")[:120],
                       "ip": str(d.get("ip_address") or ""), "mac": str(d.get("mac") or ""), "type": str(d.get("type") or ""),
                       "vendor": str(d.get("vendor") or ""), "site_id": str(d.get("site_id") or ""),
                       "site": site_names.get(str(d.get("site_id") or ""), ""),
                       "network": str(d.get("network_display_name") or d.get("network_name") or ""),
                       "status": str(d.get("status") or ""), "status_error": str(d.get("status_error") or "")[:160],
                       "protection": str(d.get("protection") or ""), "posture": d.get("posture_score") if isinstance(d.get("posture_score"), (int, float)) else None,
                       "quarantined": bool(d.get("is_quarantined")), "users": _names(d.get("ad_users")),
                       "groups": _names(d.get("groups")), "tags": _names(d.get("tags")),
                       "last_seen": _ts(d.get("last_timestamp") or d.get("updated_at"))}
                out["devices"].append(rec)
                for u in rec["users"]:
                    x = users.setdefault(u.lower(), {"name": u, "devices": [], "sites": [], "last_seen": None})
                    x["devices"].append(rec["name"])
                    if rec["site"] and rec["site"] not in x["sites"]:
                        x["sites"].append(rec["site"])
                    if rec["last_seen"] and (x["last_seen"] or 0) < rec["last_seen"]:
                        x["last_seen"] = rec["last_seen"]
            out["users"] = sorted(users.values(), key=lambda u: u["name"].lower())

            rows = await optional("alarms", get("/api/v2/alarm", {"size": 100, "tab": "active"}))
            if rows is not None:
                pick = lambda a, *ks: next((str(a[k]) for k in ks if a.get(k) not in (None, "")), "")  # noqa: E731
                out["alarms"] = [{
                    "id": pick(a, "alarm_id", "alarmId"), "ts": _ts(a.get("createdAt") or a.get("created_at")),
                    "severity": pick(a, "severity"), "status": pick(a, "status"), "service": pick(a, "service"),
                    "message": pick(a, "description")[:240], "action": pick(a, "recommended_action", "recommendedAction")[:240],
                    "site_id": pick(a, "site_id", "siteId"), "site": pick(a, "site_name", "siteName"),
                    "gateway": pick(a, "gateway_name", "gatewayName"),
                    "network": pick(a, "network_name", "networkName")} for a in _ztb_items(rows)[:100] if isinstance(a, dict)]
                res = rows.get("result") if isinstance(rows, dict) else None
                total = res.get("totalAlarmsCount") if isinstance(res, dict) else None
                out["alarms_total"] = total if isinstance(total, int) else len(out["alarms"])
        return out
    except Exception as e:  # noqa: BLE001
        return {"configured": True, "ok": False, "error": _err(e)}


async def collect_all(cfg, prev):
    snmp, unifi, proxmox, firewalla, zs, ztb = await asyncio.gather(
        collect_snmp(cfg, prev), collect_unifi(cfg), collect_proxmox(cfg), collect_firewalla(cfg),
        collect_zscaler(cfg), collect_ztb(cfg))
    return {"snmp": snmp, "unifi": unifi, "proxmox": proxmox, "firewalla": firewalla, **zs, "ztb": ztb}

"""NSM-10: read-only monitoring for SNMP, UniFi, Proxmox VE and Zscaler."""
import asyncio
import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse

from . import collectors, store

COOKIE = "nsm_session"
STATIC = os.path.join(os.path.dirname(__file__), "static")
LABELS = {"snmp": "SNMP", "unifi": "UniFi", "proxmox": "Proxmox", "zia": "ZIA", "zpa": "ZPA",
          "zdx": "ZDX", "aiguard": "AI Security"}

state = {"updated": 0, "interval": 60, "polling": False, "sources": {}, "alerts": []}
_prev_counters = {}
_alert_since = {}
_wake = asyncio.Event()


def build_alerts(src):
    found = []

    def add(sev, source, key, msg):
        found.append({"severity": sev, "source": LABELS[source], "key": f"{source}:{key}", "message": msg})

    for name in ("unifi", "proxmox", "zia", "zpa", "zdx", "aiguard"):
        s = src.get(name, {})
        if s.get("configured") and not s.get("ok"):
            add("warning", name, "source", f"{LABELS[name]} could not be polled: {s.get('error') or 'unknown error'}")

    for d in src.get("snmp", {}).get("devices", []):
        if not d["up"]:
            add("critical", "snmp", d["id"] + ":down", f"{d['name']} ({d['host']}) is not responding to SNMP")
        elif d["cpu"] is not None and d["cpu"] >= 90:
            add("warning", "snmp", d["id"] + ":cpu", f"{d['name']} CPU at {d['cpu']}%")

    u = src.get("unifi", {})
    for d in u.get("devices", []) if u.get("ok") else []:
        if d["state"] != "ONLINE":
            add("critical", "unifi", d["name"] + ":state", f"{d['name']} is {d['state'].lower() or 'offline'}")

    p = src.get("proxmox", {})
    if p.get("ok"):
        if p.get("quorate") is False:
            add("critical", "proxmox", "quorum", "Cluster has lost quorum")
        for n in p["nodes"]:
            if not n["online"]:
                add("critical", "proxmox", f"{n['name']}:offline", f"Node {n['name']} is offline")
            elif n.get("maxmem") and n.get("mem") and n["mem"] / n["maxmem"] >= 0.9:
                add("warning", "proxmox", f"{n['name']}:mem", f"Node {n['name']} memory at {round(100 * n['mem'] / n['maxmem'])}%")
        seen = set()
        for s in p["storage"]:
            ident = s["name"] if s["shared"] else f"{s['node']}/{s['name']}"
            if ident in seen or not s.get("total"):
                continue
            seen.add(ident)
            pct = round(100 * (s.get("used") or 0) / s["total"])
            if pct >= 85:
                add("warning", "proxmox", f"{ident}:storage", f"Storage {ident} at {pct}%")

    zia = src.get("zia", {})
    if zia.get("ok") and zia.get("status") and zia["status"] != "ACTIVE":
        add("warning", "zia", "activation", f"ZIA configuration status is {zia['status'].lower()}")
    zpa = src.get("zpa", {})
    for c in zpa.get("connectors", []) if zpa.get("ok") else []:
        if c["enabled"] and not c["healthy"]:
            add("warning", "zpa", c["name"] + ":conn", f"App Connector {c['name']} is {c['status'].lower()}")
    zdx = src.get("zdx", {})
    for a in zdx.get("apps", []) if zdx.get("ok") else []:
        if a["score"] is not None and a["score"] < 66:
            add("warning", "zdx", a["name"] + ":score", f"ZDX score for {a['name']} is {a['score']}")

    now = time.time()
    keys = {a["key"] for a in found}
    for k in list(_alert_since):
        if k not in keys:
            del _alert_since[k]
    for a in found:
        a["since"] = _alert_since.setdefault(a["key"], now)
    found.sort(key=lambda a: (a["severity"] != "critical", a["since"]))
    return found


async def poll_loop():
    while True:
        interval = 60
        try:
            cfg = store.load_config()
            interval = cfg["poll_interval"]
            state["polling"] = True
            src = await collectors.collect_all(cfg, _prev_counters)
            state.update(sources=src, alerts=build_alerts(src), updated=time.time(), interval=interval)
        except Exception as e:  # noqa: BLE001 - keep the loop alive
            print("poll failed:", repr(e), flush=True)
        finally:
            state["polling"] = False
        _wake.clear()
        try:
            await asyncio.wait_for(_wake.wait(), interval)
        except asyncio.TimeoutError:
            pass


@asynccontextmanager
async def lifespan(_app):
    task = asyncio.create_task(poll_loop())
    yield
    task.cancel()


app = FastAPI(title="NSM-10", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def authed(request: Request):
    if not store.valid_session(request.cookies.get(COOKIE)):
        raise HTTPException(401, "Sign in required")


async def json_body(request: Request):
    if "application/json" not in request.headers.get("content-type", ""):
        raise HTTPException(415, "JSON required")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "Object required")
    return body


def _start_session(response: Response):
    response.set_cookie(COOKIE, store.new_session(), httponly=True, samesite="strict",
                        max_age=store.SESSION_TTL)


@app.get("/api/session")
def session(request: Request):
    return {"setup_needed": not store.has_admin(),
            "authed": store.valid_session(request.cookies.get(COOKIE))}


@app.post("/api/setup")
async def setup(response: Response, body: dict = Depends(json_body)):
    if store.has_admin():
        raise HTTPException(409, "Already set up")
    pw = str(body.get("password") or "")
    if len(pw) < 10:
        raise HTTPException(400, "Use at least 10 characters")
    store.set_admin(pw)
    _start_session(response)
    return {"ok": True}


@app.post("/api/login")
async def login(response: Response, body: dict = Depends(json_body)):
    if not store.check_admin(str(body.get("password") or "")):
        await asyncio.sleep(1.5)
        raise HTTPException(401, "Wrong password")
    _start_session(response)
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    store.drop_session(request.cookies.get(COOKIE) or "")
    response.delete_cookie(COOKIE)
    return {"ok": True}


@app.get("/api/state", dependencies=[Depends(authed)])
def get_state():
    return state


@app.get("/api/settings", dependencies=[Depends(authed)])
def get_settings():
    return store.masked(store.load_config())


@app.put("/api/settings", dependencies=[Depends(authed)])
async def put_settings(body: dict = Depends(json_body)):
    cfg = store.save_config(store.merge_secrets(body, store.load_config()))
    _wake.set()
    return store.masked(cfg)


@app.post("/api/poll", dependencies=[Depends(authed)])
def poll_now():
    _wake.set()
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-cache"})

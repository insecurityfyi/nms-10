"""Persistent storage: encrypted settings, admin password, sessions."""
import copy
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

from cryptography.fernet import Fernet

DATA = os.environ.get("NSM_DATA", "/data")
MASK = "********"
SECRET_KEYS = {"community", "v3_auth_pass", "v3_priv_pass", "api_key", "token_secret", "client_secret", "token"}
SESSION_TTL = 12 * 3600

DEFAULT_CONFIG = {
    "poll_interval": 60,
    "snmp": {"devices": []},
    "unifi": {"enabled": False, "url": "", "api_key": "", "verify_tls": False},
    "proxmox": {"enabled": False, "url": "", "token_id": "", "token_secret": "", "verify_tls": False},
    "firewalla": {"enabled": False, "domain": "", "token": ""},
    "zscaler": {
        "enabled": False, "vanity": "", "cloud": "", "client_id": "", "client_secret": "",
        "zpa_customer_id": "", "zia": True, "zpa": True, "zdx": True, "aiguard": True, "ztw": True, "zins": True,
    },
}


def _db():
    os.makedirs(DATA, exist_ok=True)
    con = sqlite3.connect(os.path.join(DATA, "nsm.db"))
    con.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB)")
    con.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires REAL)")
    return con


def _fernet():
    os.makedirs(DATA, exist_ok=True)
    path = os.path.join(DATA, "secret.key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    with open(path, "rb") as f:
        return Fernet(f.read())


def _get(k):
    with _db() as con:
        row = con.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return row[0] if row else None


def _set(k, v):
    with _db() as con:
        con.execute("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


# ---- settings -------------------------------------------------------------

def _fill(defaults, value):
    """Overlay value on defaults, keeping only known keys with matching types."""
    out = copy.deepcopy(defaults)
    if not isinstance(value, dict):
        return out
    for k, d in defaults.items():
        if k not in value:
            continue
        v = value[k]
        if isinstance(d, dict):
            out[k] = _fill(d, v)
        elif isinstance(d, bool):
            out[k] = bool(v)
        elif isinstance(d, int):
            try:
                out[k] = int(v)
            except (TypeError, ValueError):
                pass
        elif isinstance(d, str):
            out[k] = str(v).strip() if v is not None else ""
        else:
            out[k] = v
    return out


SNMP_DEVICE = {
    "id": "", "name": "", "host": "", "version": "2c", "community": "",
    "v3_user": "", "v3_auth_proto": "SHA", "v3_auth_pass": "",
    "v3_priv_proto": "AES", "v3_priv_pass": "", "uplink_ifindex": "",
}


def normalize(cfg):
    out = _fill(DEFAULT_CONFIG, cfg)
    out["poll_interval"] = max(15, min(3600, out["poll_interval"]))
    devices = []
    raw = (cfg or {}).get("snmp", {}).get("devices", []) if isinstance(cfg, dict) else []
    for d in raw if isinstance(raw, list) else []:
        dev = _fill(SNMP_DEVICE, d)
        if not dev["host"]:
            continue
        dev["id"] = dev["id"] or secrets.token_hex(6)
        dev["name"] = dev["name"] or dev["host"]
        dev["version"] = "3" if dev["version"] == "3" else "2c"
        devices.append(dev)
    out["snmp"]["devices"] = devices[:500]
    fw = out["firewalla"]
    fw["domain"] = fw["domain"].lower().split("://", 1)[-1].split("/", 1)[0].strip()
    z = out["zscaler"]
    z["vanity"], cloud_hint = _clean_vanity(z["vanity"])
    cloud = (z["cloud"] or cloud_hint).lower().strip(". ")
    # ZIA cloud names (zscaler, zscalertwo, zscloud...) and "production" all mean the default OneAPI cloud.
    z["cloud"] = "" if cloud in PRODUCTION_CLOUDS else cloud
    return out


PRODUCTION_CLOUDS = {"", "production", "prod", "default", "zscaler", "zscalerone", "zscalertwo",
                     "zscalerthree", "zscloud", "zsapi", "net"}


def _clean_vanity(value):
    """Accept 'acme', 'acme.zslogin.net' or a pasted https://acme.zslogin.net/... URL."""
    v = value.lower().strip()
    v = v.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    cloud = ""
    if ".zslogin" in v:
        v, rest = v.split(".zslogin", 1)
        cloud = rest.split(".", 1)[0]
    return v, cloud


def load_config():
    blob = _get("config")
    if not blob:
        return normalize({})
    return normalize(json.loads(_fernet().decrypt(blob)))


def save_config(cfg):
    cfg = normalize(cfg)
    _set("config", _fernet().encrypt(json.dumps(cfg).encode()))
    return cfg


def masked(cfg):
    """Copy of cfg safe to send to the browser: secrets replaced by a mask."""
    def walk(node):
        if isinstance(node, dict):
            return {k: (MASK if k in SECRET_KEYS and v else walk(v)) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node
    return walk(cfg)


def merge_secrets(new, old):
    """Where the browser sent the mask back, keep the stored secret."""
    def walk(n, o):
        if not isinstance(n, dict):
            return
        for k, v in n.items():
            if k in SECRET_KEYS and v == MASK:
                n[k] = (o or {}).get(k, "") if isinstance(o, dict) else ""
            elif isinstance(v, dict):
                walk(v, (o or {}).get(k) if isinstance(o, dict) else None)
    walk(new, old)
    old_devs = {d["id"]: d for d in old.get("snmp", {}).get("devices", [])}
    for d in new.get("snmp", {}).get("devices", []) if isinstance(new.get("snmp"), dict) else []:
        if isinstance(d, dict):
            walk(d, old_devs.get(d.get("id")))
    return new


# ---- admin + sessions -----------------------------------------------------

def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000)


def has_admin():
    return _get("admin") is not None


def set_admin(password):
    salt = secrets.token_bytes(16)
    _set("admin", salt + _hash(password, salt))


def check_admin(password):
    blob = _get("admin")
    if not blob:
        return False
    return hmac.compare_digest(blob[16:], _hash(password, blob[:16]))


def new_session():
    token = secrets.token_urlsafe(32)
    with _db() as con:
        con.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
        con.execute("INSERT INTO sessions VALUES (?, ?)", (token, time.time() + SESSION_TTL))
    return token


def valid_session(token):
    if not token:
        return False
    with _db() as con:
        row = con.execute("SELECT expires FROM sessions WHERE token=?", (token,)).fetchone()
    return bool(row and row[0] > time.time())


def drop_session(token):
    with _db() as con:
        con.execute("DELETE FROM sessions WHERE token=?", (token,))

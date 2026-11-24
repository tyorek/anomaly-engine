#!/usr/bin/env python3
"""anomaly-engine -- local attacker-behaviour detection over the syslog collector's raw store (P7/P8).

Deploy: /home/agent/agents/anomaly-engine/engine.py, run every 5 minutes by run.sh (cron, user agent).
Reads (read-only mount from CT 112):
  /srv/syslog/<device>/<device>.log        per-device syslog (RouterOS, fw-edge filterlog/audit, DNS hosts)
  /srv/syslog/<dnshost>/queries.log        Technitium query logs (Log Exporter)
  /srv/syslog/fw-edge/eve.log              Suricata eve.json records (tls/http/alert/drop/anomaly)
  /srv/syslog/flows-csv/<exporter>/YYYY/MM/DD/flows-*.csv.gz   closed 5-minute flow files (exported on CT 112)
Writes (all in this folder):
  state.db        SQLite: read offsets, processed files, first-seen tables, hourly baselines, beacon windows
  learn.jsonl     would-be findings during the burn-in (never shipped anywhere)
  findings.jsonl  findings after the burn-in; the Wazuh agent tails it (rules 100600-100620 on the manager)
  reports/        burn-in report written once, at the switch to active mode

Statistics find anomalies; nothing here calls a model. Stdlib only.
"""
import datetime as dt
import glob
import gzip
import ipaddress
import json
import math
import os
import re
import sqlite3
import sys
import time
from functools import lru_cache
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, "config.json")))
TZ = ZoneInfo(CFG["timezone"])
BURN_IN_END = dt.datetime.fromisoformat(CFG["burn_in_end"]).timestamp()
TH = CFG["thresholds"]
NOW = time.time()
ACTIVE = NOW >= BURN_IN_END

SEVERITY_ATTACK = {  # detector -> (severity, ATT&CK ids); mirrors the Wazuh rules
    "dmz_internal_connection":       ("high",     ["T1021"]),
    "dmz_proxy_internal_connection": ("critical", ["T1021", "T1210"]),
    "dmz_firewall_block":            ("high",     ["T1046"]),
    "dmz_internal_fanout":           ("high",     ["T1046"]),
    "first_seen_outbound_tls":       ("medium",   ["T1071.001"]),
    "first_seen_dns_domain":         ("medium",   ["T1071.004"]),
    "first_seen_outbound_port":      ("medium",   ["T1571"]),
    "first_seen_inbound_service":    ("high",     ["T1190"]),
    "first_seen_mac":                ("low",      ["T1200"]),
    "first_seen_login":              ("medium",   ["T1078"]),
    "login_odd_hour":                ("medium",   ["T1078"]),
    "login_failure_burst":           ("high",     ["T1110"]),
    "config_actor_first_seen":       ("medium",   ["T1098"]),
    "volume_spike":                  ("low",      []),
    "dmz_bytes_out_spike":           ("high",     ["T1041", "T1048"]),
    "beacon_candidate":              ("medium",   ["T1071", "T1573"]),
    "feed_silent":                   ("high",     ["T1562"]),
    "monitoring_host_egress":        ("critical", ["T1071"]),
    "resolver_share_imbalance":      ("medium",   ["T1562", "T1071.004"]),
    "engine_status":                 ("low",      []),
}

# ---------------------------------------------------------------- helpers

def nets(name):
    return [ipaddress.ip_network(n) for n in CFG["nets"][name]]

NET = {k: nets(k) for k in CFG["nets"]}

@lru_cache(maxsize=200000)
def ip(s):
    try:
        return ipaddress.ip_address(s.strip())
    except ValueError:
        return None

@lru_cache(maxsize=200000)
def cls(s):
    """dmz | internal | iot-internal | internet | special"""
    a = ip(s)
    if a is None:
        return "special"
    if a.is_multicast or a.is_link_local or a.is_unspecified or a.is_loopback or str(a) == "255.255.255.255":
        return "special"
    if any(a in n for n in NET["dmz"] if n.version == a.version):
        return "dmz"
    if any(a in n for n in NET["internal"] if n.version == a.version):
        return "internal"
    if a.is_private or a.is_reserved:
        return "special"
    return "internet"

def is_iot(s):
    a = ip(s)
    return a is not None and any(a in n for n in NET["iot"] if n.version == a.version)

TWO_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.nz", "com.mx", "co.in"}

def sld(name):
    name = (name or "").strip(".").lower()
    parts = name.split(".")
    if len(parts) <= 2:
        return name
    if ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def log(msg):
    print(f"{dt.datetime.now(TZ).isoformat(timespec='seconds')} {msg}", flush=True)

def line_ts(line):
    try:
        return dt.datetime.fromisoformat(line[:32]).timestamp()
    except ValueError:
        return None

# ---------------------------------------------------------------- state

DB = sqlite3.connect(os.path.join(HERE, "state.db"))
DB.executescript("""
CREATE TABLE IF NOT EXISTS offsets(path TEXT PRIMARY KEY, inode INTEGER, pos INTEGER);
CREATE TABLE IF NOT EXISTS done_files(path TEXT PRIMARY KEY, ts REAL);
CREATE TABLE IF NOT EXISTS seen(detector TEXT, entity TEXT, key TEXT, first_ts REAL, last_ts REAL, count INTEGER,
                                PRIMARY KEY(detector, entity, key));
CREATE TABLE IF NOT EXISTS hourly(metric TEXT, entity TEXT, hour INTEGER, count REAL, PRIMARY KEY(metric, entity, hour));
CREATE TABLE IF NOT EXISTS stats(metric TEXT, entity TEXT, hod INTEGER, n INTEGER, mean REAL, m2 REAL,
                                 PRIMARY KEY(metric, entity, hod));
CREATE TABLE IF NOT EXISTS beacon(key TEXT PRIMARY KEY, starts TEXT, last_ts REAL);
CREATE TABLE IF NOT EXISTS fails(device TEXT, src TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS emitted(dkey TEXT PRIMARY KEY, ts REAL, count INTEGER);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS share(bucket INTEGER, server TEXT, n INTEGER, fail INTEGER, rtt_sum REAL, rtt_n INTEGER, PRIMARY KEY(bucket, server));
""")

def meta(k, v=None):
    if v is None:
        r = DB.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None
    DB.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, str(v)))

COUNTS = {}  # detector -> emitted this run

def emit(detector, entity, summary, evidence, dkey=None, ts=None, force_active=False):
    """Write a finding (active) or a would-be finding (burn-in). Dedupe per dkey for dedupe_hours."""
    dkey = dkey or f"{detector}|{entity}|{summary}"
    row = DB.execute("SELECT ts, count FROM emitted WHERE dkey=?", (dkey,)).fetchone()
    if row and NOW - row[0] < CFG["dedupe_hours"] * 3600:
        DB.execute("UPDATE emitted SET count=count+1 WHERE dkey=?", (dkey,))
        return
    DB.execute("INSERT OR REPLACE INTO emitted VALUES(?,?,1)", (dkey, NOW))
    sev, attack = SEVERITY_ATTACK[detector]
    if detector == "dmz_internal_connection" and evidence.get("dst_is_router"):
        sev = "critical"
    rec = {"anomaly_engine": {
        "detector": detector, "severity": sev, "attack": attack, "entity": entity,
        "summary": summary, "evidence": evidence,
        "event_time": dt.datetime.fromtimestamp(ts or NOW, TZ).isoformat(timespec="seconds"),
        "mode": "active" if (ACTIVE or force_active) else "learn",
    }}
    out = "findings.jsonl" if (ACTIVE or force_active) else "learn.jsonl"
    with open(os.path.join(HERE, out), "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    COUNTS[detector] = COUNTS.get(detector, 0) + 1

def first_seen(detector, entity, key, ts, summary, evidence, emit_after_burn_in=True):
    """Record (detector, entity, key). After the burn-in, a key never seen before is a finding."""
    r = DB.execute("SELECT count FROM seen WHERE detector=? AND entity=? AND key=?", (detector, entity, key)).fetchone()
    if r:
        DB.execute("UPDATE seen SET last_ts=max(last_ts,?), count=count+1 WHERE detector=? AND entity=? AND key=?",
                   (ts, detector, entity, key))
        return False
    DB.execute("INSERT INTO seen VALUES(?,?,?,?,?,1)", (detector, entity, key, ts, ts))
    if ACTIVE and emit_after_burn_in:
        emit(detector, entity, summary, evidence, dkey=f"{detector}|{entity}|{key}", ts=ts)
    return True

def bump(metric, entity, ts, n=1.0):
    hour = int(ts // 3600)
    DB.execute("INSERT INTO hourly VALUES(?,?,?,?) ON CONFLICT(metric,entity,hour) DO UPDATE SET count=count+excluded.count",
               (metric, entity, hour, n))

# ---------------------------------------------------------------- incremental readers

def read_new_lines(path):
    """Yield lines appended since last run; handles logrotate (new inode) and truncation."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    r = DB.execute("SELECT inode, pos FROM offsets WHERE path=?", (path,)).fetchone()
    pos = 0
    if r and r[0] == st.st_ino and r[1] <= st.st_size:
        pos = r[1]
    elif r and r[0] != st.st_ino:
        # rotated: finish the rotated copy (dateext name, plain because of delaycompress) before the new file
        for old in sorted(glob.glob(path + "-*")):
            try:
                ost = os.stat(old)
            except FileNotFoundError:
                continue
            if ost.st_ino == r[0] and not old.endswith(".gz"):
                with open(old, "rb") as f:
                    f.seek(r[1])
                    for raw in f:
                        yield raw.decode("utf-8", "replace")
    with open(path, "rb") as f:
        f.seek(pos)
        while True:
            raw = f.readline()
            if not raw or not raw.endswith(b"\n"):
                break  # incomplete last line: pick it up next run
            pos += len(raw)
            yield raw.decode("utf-8", "replace")
    DB.execute("INSERT OR REPLACE INTO offsets VALUES(?,?,?)", (path, st.st_ino, pos))

# ---------------------------------------------------------------- syslog detectors

RE_LOGIN = re.compile(r"user (\S+) logged in from (\S+) via (\S+)")
RE_FAIL = re.compile(r"login failure for user (\S+) from (\S+) via (\S+)")
RE_CHANGED = re.compile(r" by (\S+?)(?: \(|$)")
RE_DHCP = re.compile(r"(\S+) assigned (\S+) (?:for|to) ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")
RE_AUDIT = re.compile(r"audit\[\d+\]: user (\S+) changed configuration")

def process_device_log(dev):
    path = os.path.join(CFG["syslog_root"], dev, f"{dev}.log")
    n = 0
    for line in read_new_lines(path):
        ts = line_ts(line)
        if ts is None:
            continue
        n += 1
        bump("lines", dev, ts)
        parts = line.split(" ", 4)
        if len(parts) < 5:
            continue
        msg = parts[4].rstrip("\n")
        topics = msg.split(" ", 1)[0]
        hour = dt.datetime.fromtimestamp(ts, TZ).hour

        if "syslog-heartbeat" in msg:
            continue
        m = RE_LOGIN.search(msg)
        if m and dev != "fw-edge":
            user, src, via = m.groups()
            first_seen("first_seen_login", dev, f"{user}|{src}|{via}", ts,
                       f"{dev}: first login by {user} from {src} via {via}",
                       {"device": dev, "user": user, "src": src, "via": via, "line": msg[:400]})
            ent = f"{dev}|{user}"
            nbase = DB.execute("SELECT count(*), coalesce(sum(count),0) FROM seen WHERE detector='login_hour' AND entity=?", (ent,)).fetchone()
            new_hour = first_seen("login_hour", ent, str(hour), ts, "", {}, emit_after_burn_in=False)
            if ACTIVE and new_hour and nbase[1] >= TH["login_hour_min_baseline"]:
                emit("login_odd_hour", dev, f"{dev}: {user} logged in at {hour:02d}:00, an hour never seen in the baseline",
                     {"device": dev, "user": user, "src": src, "via": via, "hour": hour}, ts=ts)
        m = RE_FAIL.search(msg)
        if m:
            user, src, via = m.groups()
            DB.execute("INSERT INTO fails VALUES(?,?,?)", (dev, src, ts))
            win = TH["login_fail_window_min"] * 60
            c = DB.execute("SELECT count(*) FROM fails WHERE device=? AND src=? AND ts>?", (dev, src, ts - win)).fetchone()[0]
            if c >= TH["login_fail_burst"]:
                emit("login_failure_burst", dev, f"{dev}: {c} failed logins from {src} in {TH['login_fail_window_min']} min",
                     {"device": dev, "src": src, "last_user": user, "via": via, "count": c},
                     dkey=f"login_failure_burst|{dev}|{src}", ts=ts)
        if dev != "fw-edge" and " by " in msg and ("changed" in msg or "added" in msg or "removed" in msg or "scheduled" in msg):
            m = RE_CHANGED.search(msg)
            if m:
                actor = m.group(1)
                first_seen("config_actor_first_seen", dev, actor, ts,
                           f"{dev}: configuration changed by a new actor {actor}",
                           {"device": dev, "actor": actor, "line": msg[:400]})
        m = RE_DHCP.search(msg)
        if m:
            server, addr, mac = m.groups()
            first_seen("first_seen_mac", server, mac.upper(), ts,
                       f"new MAC {mac.upper()} got {addr} from {server}",
                       {"dhcp_server": server, "address": addr, "mac": mac.upper(), "line": msg[:300]})
        if topics.startswith("firewall") and ("SYSLOG-DROP" in msg or "AGENT-DROP" in msg):
            emit("monitoring_host_egress", dev, "a monitoring host (collector or agent box) tried to open an outbound connection",
                 {"device": dev, "line": msg[:500]}, dkey=f"mhe|{msg[:120]}", ts=ts)
        if topics.startswith("firewall"):
            pfx = msg.split(" ", 2)[1] if len(msg.split(" ", 2)) > 1 else "?"
            if pfx.isupper():
                bump("fw_prefix", f"{dev}:{pfx}", ts)

        if dev == "fw-edge":
            if "filterlog" in msg:
                filterlog(msg, ts)
            m = RE_AUDIT.search(msg)
            if m:
                actor = m.group(1)
                first_seen("config_actor_first_seen", "fw-edge", actor, ts,
                           f"fw-edge: configuration changed by a new actor {actor}",
                           {"device": "fw-edge", "actor": actor, "line": msg[:400]})
    return n

def filterlog(msg, ts):
    """OPNsense filterlog CSV: rule,sub,anchor,tracker,iface,reason,action,dir,ipver,..."""
    try:
        body = msg.split("filterlog[", 1)[1].split("]: ", 1)[1]
    except IndexError:
        return
    f = body.split(",")
    if len(f) < 9:
        return
    iface, action, direction, ipver = f[4], f[6], f[7], f[8]
    try:
        if ipver == "4":
            proto, src, dst = f[16], f[18], f[19]
            sport, dport = (f[20], f[21]) if proto in ("tcp", "udp") and len(f) > 21 else ("", "")
        elif ipver == "6":
            proto, src, dst = f[12], f[15], f[16]
            sport, dport = (f[17], f[18]) if proto in ("tcp", "udp") and len(f) > 18 else ("", "")
        else:
            return
    except IndexError:
        return
    if action == "block" and direction == "in" and cls(src) == "dmz" and cls(dst) == "internal":
        emit("dmz_firewall_block", src,
             f"fw-edge blocked {src} -> {dst}:{dport or proto} (DMZ host reaching for an internal address)",
             {"src": src, "dst": dst, "dport": dport, "proto": proto, "iface": iface, "rule": f[0], "tracker": f[3]},
             dkey=f"dfb|{src}|{dst}|{dport}|{proto}", ts=ts)

RE_KV = re.compile(r'(\w+)="([^"]*)"')

# ---------------------------------------------------------------- resolver share (round-robin balance)

RS = CFG.get("resolver_share", {})
RS_SINCE = dt.datetime.fromisoformat(RS["since"]).timestamp() if RS.get("since") else None

def in_rr_scope(client):
    """Clients the RB5009 round-robins (internal, minus the pinned VLANs / resolvers / mgmt / DMZ)."""
    a = ip(client)
    if a is None or cls(client) != "internal":
        return False
    return not any(a in ipaddress.ip_network(n) for n in RS.get("exclude", []) if ipaddress.ip_network(n).version == a.version)

def share_bump(host, client, ts, rtt, rcode):
    if not RS or host not in RS.get("servers", []):
        return
    if RS_SINCE is None or ts < RS_SINCE or not in_rr_scope(client):
        return
    b = int(ts // 300)
    try:
        r = float(rtt)
    except (TypeError, ValueError):
        r = None
    DB.execute("""INSERT INTO share(bucket, server, n, fail, rtt_sum, rtt_n) VALUES(?,?,1,?,?,?)
                  ON CONFLICT(bucket, server) DO UPDATE SET n=n+1, fail=fail+excluded.fail,
                  rtt_sum=rtt_sum+excluded.rtt_sum, rtt_n=rtt_n+excluded.rtt_n""",
               (b, host, 1 if rcode in ("ServerFailure", "Refused") else 0, r or 0.0, 1 if r is not None else 0))

def resolver_share():
    """Close 15-minute windows; learn the normal split per hour-of-day; after the burn-in flag unusual skew
    and launch the investigation."""
    if not RS or not RS.get("since"):
        return
    servers = RS["servers"]
    win = RS.get("window_min", 15) * 60
    last = int(meta("share_last_window") or 0)
    cur_window = int(NOW // win) * win
    starts = sorted({int(b * 300 // win) * win for (b,) in DB.execute("SELECT DISTINCT bucket FROM share")})
    for w in starts:
        if w <= last or w >= cur_window:
            continue
        rows = DB.execute("SELECT server, sum(n), sum(fail), sum(rtt_sum), sum(rtt_n) FROM share WHERE bucket*300 >= ? AND bucket*300 < ? GROUP BY server",
                          (w, w + win)).fetchall()
        cnt = {r[0]: r[1] for r in rows}
        tot = sum(cnt.get(x, 0) for x in servers)
        meta("share_last_window", w)
        if tot < RS.get("min_queries", 100):
            continue
        share = cnt.get(servers[0], 0) / tot          # share of the first server (primenodetls)
        hod = dt.datetime.fromtimestamp(w, TZ).hour
        outage = not (RS.get("outage_low", 0.15) <= share <= RS.get("outage_high", 0.85))
        st = DB.execute("SELECT n, mean, m2 FROM stats WHERE metric='resolver_share' AND entity='rr' AND hod=?", (hod,)).fetchone()
        n, mean, m2 = st if st else (0, 0.5, 0.0)
        sd = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0
        z = (share - mean) / sd if sd > 0 else 0.0
        evidence = {"window_start": dt.datetime.fromtimestamp(w, TZ).isoformat(timespec="minutes"), "window_min": win // 60,
                    "counts": {x: cnt.get(x, 0) for x in servers}, "share_" + servers[0]: round(share, 4),
                    "baseline_mean": round(mean, 4), "baseline_sd": round(sd, 4), "baseline_samples": n, "z": round(z, 2),
                    "failures": {r[0]: r[2] for r in rows}, "avg_rtt_ms": {r[0]: round(r[3] / r[4], 1) for r in rows if r[4]}}
        if ACTIVE:
            if (n >= TH["zscore_min_samples"] and abs(z) >= RS.get("zscore", TH["zscore"])) or (outage and n >= TH["zscore_min_samples"]):
                heavy = servers[0] if share > 0.5 else servers[1]
                summ = (f"DNS round-robin skew: {heavy} took {max(share, 1 - share):.0%} of {tot} queries in the "
                        f"{dt.datetime.fromtimestamp(w, TZ):%H:%M} window (normal {mean:.0%} +/- {sd:.1%} for {hod:02d}:00, z {z:.1f})")
                evidence["investigation"] = launch_investigation(w, win)
                emit("resolver_share_imbalance", heavy, summ, evidence, dkey=f"rs|{w}", ts=w)
        else:
            if outage:
                evidence["note"] = "outage-like window, kept out of the baseline"
                emit("resolver_share_imbalance", servers[0] if share > 0.5 else servers[1],
                     f"DNS round-robin window {share:.0%}/{1 - share:.0%} looks like a failover or outage (not learned)", evidence,
                     dkey=f"rs|{w}", ts=w)
        if not outage:
            n += 1
            d = share - mean
            mean += d / n
            m2 += d * (share - mean)
            DB.execute("INSERT OR REPLACE INTO stats VALUES('resolver_share','rr',?,?,?,?)", (hod, n, mean, m2))
    DB.execute("DELETE FROM share WHERE bucket*300 < ?", (NOW - 2 * 86400,))

def launch_investigation(w, win):
    """Start investigate_dns_share.py detached; it writes reports/investigations/dns-share-<window>.md."""
    import subprocess
    script = os.path.join(HERE, "investigate_dns_share.py")
    if not os.path.exists(script):
        return "investigation script missing"
    out = os.path.join(HERE, "reports", "investigations", f"dns-share-{dt.datetime.fromtimestamp(w, TZ):%Y%m%d-%H%M}.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    subprocess.Popen([sys.executable, script, "--window-start", str(w), "--window-sec", str(win), "--report", out],
                     cwd=HERE, stdout=open(os.path.join(HERE, "logs", "investigations.log"), "a"),
                     stderr=subprocess.STDOUT, start_new_session=True)
    return out

def process_queries(host):
    path = os.path.join(CFG["syslog_root"], host, "queries.log")
    n = 0
    for line in read_new_lines(path):
        ts = line_ts(line)
        if ts is None:
            continue
        kv = dict(RE_KV.findall(line))
        client, qname = kv.get("clientIp"), kv.get("qName")
        if not client or not qname:
            continue
        n += 1
        bump("dns_queries", host, ts)
        share_bump(host, client, ts, kv.get("responseRtt"), kv.get("rCode"))
        if cls(client) == "dmz" or is_iot(client):
            first_seen("first_seen_dns_domain", client, sld(qname), ts,
                       f"{client} looked up a domain never seen from it before: {sld(qname)} ({qname} {kv.get('qType','')})",
                       {"client": client, "qname": qname, "qtype": kv.get("qType"), "rcode": kv.get("rCode"),
                        "resolver": host, "zone": "dmz" if cls(client) == "dmz" else "iot"})
    return n

def process_eve():
    path = os.path.join(CFG["syslog_root"], "fw-edge", "eve.log")
    n = 0
    for line in read_new_lines(path):
        i = line.find("suricata-eve: ")
        if i < 0:
            continue
        try:
            e = json.loads(line[i + 14:])
        except ValueError:
            continue
        n += 1
        ts = line_ts(line) or NOW
        et = e.get("event_type")
        bump("eve", et or "?", ts)
        src, dst = e.get("src_ip", ""), e.get("dest_ip", "")
        if et == "tls":
            sni = (e.get("tls") or {}).get("sni")
            if sni and (cls(src) == "dmz" or is_iot(src)) and cls(dst) == "internet":
                first_seen("first_seen_outbound_tls", src, sld(sni), ts,
                           f"{src} opened TLS to a name never seen from it before: {sni} ({dst}:{e.get('dest_port')})",
                           {"src": src, "dst": dst, "dport": e.get("dest_port"), "sni": sni,
                            "ja4": (e.get("tls") or {}).get("ja4"), "version": (e.get("tls") or {}).get("version")})
    return n

# ---------------------------------------------------------------- flows

def allow_match(src, dst, dport, proto):
    for a in CFG["dmz_internal_allow"]:
        if src in a["src"] and dst in a["dst"] and dport in a["ports"] and (a["proto"] == "ANY" or a["proto"] == proto):
            return True
    return False

PROTO = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMP6", "47": "GRE", "50": "ESP"}

def port(x):
    try:
        return int(float(x or 0))
    except ValueError:
        return 0

def read_flow_file(path):
    rows = []
    with gzip.open(path, "rt", errors="replace") as f:
        for line in f:
            p = [x.strip() for x in line.split("|")]
            if len(p) < 10:
                continue
            try:
                ts = dt.datetime.strptime(p[0][:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ).timestamp() + (float("0" + p[0][19:]) if len(p[0]) > 19 else 0)
                rows.append((ts, p[2], p[3], port(p[4]), port(p[5]), PROTO.get(p[6], p[6].upper()), p[7], port(p[8]), port(p[9])))
            except ValueError:
                continue
    return rows

LISTEN = {1514, 1515, 3000, 5380, 8006, 8080, 8090, 8099, 9090, 11000, 53443, 2055, 3306, 5432}

def svc(p):
    return 0 < p < 1024 or p in LISTEN

def initiators(rows):
    """Mark each flow as initiator or reply using the reverse flow in the same file, else port heuristics."""
    first = {}
    for r in rows:
        k = (r[1], r[2], r[3], r[4], r[5])
        if k not in first or r[0] < first[k]:
            first[k] = r[0]
    out = []
    for r in rows:
        ts, sa, da, sp, dp, pr = r[:6]
        if pr not in ("TCP", "UDP"):
            out.append((r, True))
            continue
        # Ports decide first: service port -> ephemeral port is a reply. Long sessions are split into
        # 1-minute records, so which direction "started" first inside one file is not reliable.
        s_svc, d_svc = svc(sp), svc(dp)
        if s_svc and not d_svc:
            is_reply = True
        elif d_svc and not s_svc:
            is_reply = False
        else:
            rev = (da, sa, dp, sp, pr)
            rt = first.get(rev)
            is_reply = rt is not None and (rt < ts or (rt == ts and sp < dp))
        out.append((r, not is_reply))
    return out, first

def process_flows(exporter):
    root = os.path.join(CFG["flow_csv_root"], exporter)
    files = sorted(glob.glob(os.path.join(root, "*", "*", "*", "flows-*.csv.gz")))
    done = {r[0] for r in DB.execute("SELECT path FROM done_files WHERE path LIKE ?", (root + "%",))}
    n = 0
    for path in files:
        if path in done:
            continue
        rows = read_flow_file(path)
        marked, first = initiators(rows)
        fan = {}
        for r, init in marked:
            ts, sa, da, sp, dp, pr, flg, pkt, byt = r
            n += 1
            ca, cb = cls(sa), cls(da)
            if exporter == "fw-edge":
                if init and ca == "dmz" and cb == "internal":
                    fan.setdefault(sa, set()).add(da)
                    if not allow_match(sa, da, dp, pr):
                        proxy = CFG["dmz_proxies"].get(sa)
                        router = da in CFG["router_addresses"]
                        det = "dmz_proxy_internal_connection" if (proxy or router) else "dmz_internal_connection"
                        emit(det, sa, f"{proxy or sa} -> {da}:{dp}/{pr} is outside the DMZ allow-list (fw-edge rules 1030-1055)",
                             {"src": sa, "dst": da, "sport": sp, "dport": dp, "proto": pr, "bytes": byt, "pkts": pkt, "flags": flg,
                              "dst_is_router": router, "src_role": proxy or "dmz host"},
                             dkey=f"dic|{sa}|{da}|{dp}|{pr}", ts=ts)
                if init and ca == "dmz" and cb == "internet":
                    bump("dmz_bytes_out", sa, ts, byt)
                    if dp not in (80, 443, 53, 853, 123):
                        first_seen("first_seen_outbound_port", sa, f"{dp}/{pr}", ts,
                                   f"{sa} connected out on a port never seen from it before: {da}:{dp}/{pr}",
                                   {"src": sa, "dst": da, "dport": dp, "proto": pr, "bytes": byt})
                if init and ca == "internet" and cb == "dmz" and (da, sa, dp, sp, pr) in first:
                    first_seen("first_seen_inbound_service", da, f"{dp}/{pr}", ts,
                               f"{da} answered an inbound connection on a port never seen answering before: {dp}/{pr} (from {sa})",
                               {"dst": da, "dport": dp, "proto": pr, "src": sa})
            else:  # rb5009: internal VLANs
                if init and is_iot(sa) and cb == "internet" and dp not in (80, 443, 53, 853, 123):
                    first_seen("first_seen_outbound_port", sa, f"{dp}/{pr}", ts,
                               f"IoT host {sa} connected out on a port never seen from it before: {da}:{dp}/{pr}",
                               {"src": sa, "dst": da, "dport": dp, "proto": pr, "bytes": byt, "zone": "iot"})
            if init and cb == "internet" and ca in ("internal", "dmz") and pr in ("TCP", "UDP"):
                beacon_track(f"{sa}|{da}|{dp}|{pr}", ts, sp, byt)
        for sa, dsts in fan.items():
            if len(dsts) >= TH["fanout_distinct_dsts"]:
                emit("dmz_internal_fanout", sa, f"{sa} touched {len(dsts)} internal addresses in one 5-minute window",
                     {"src": sa, "distinct_dsts": len(dsts), "sample": sorted(dsts)[:20]}, dkey=f"fan|{sa}")
        DB.execute("INSERT OR REPLACE INTO done_files VALUES(?,?)", (path, NOW))
    return n

def beacon_track(key, ts, sport, byt):
    r = DB.execute("SELECT starts FROM beacon WHERE key=?", (key,)).fetchone()
    starts = json.loads(r[0]) if r else []
    if starts and starts[-1][1] == sport and ts - starts[-1][0] < 3600:
        return  # same connection continuing (1-minute active timeout splits long sessions)
    starts.append([round(ts, 1), sport, byt])
    starts = starts[-30:]
    DB.execute("INSERT OR REPLACE INTO beacon VALUES(?,?,?)", (key, json.dumps(starts), ts))
    if len(starts) >= TH["beacon_min_conns"] and starts[-1][0] - starts[0][0] >= TH["beacon_min_span_min"] * 60:
        iv = [b[0] - a[0] for a, b in zip(starts, starts[1:])]
        mean = sum(iv) / len(iv)
        if mean <= 0:
            return
        cv = math.sqrt(sum((x - mean) ** 2 for x in iv) / len(iv)) / mean
        bs = [s[2] for s in starts]
        bm = sum(bs) / len(bs)
        bcv = (math.sqrt(sum((x - bm) ** 2 for x in bs) / len(bs)) / bm) if bm else 0
        if cv <= TH["beacon_max_interval_cv"] and bcv <= TH["beacon_max_bytes_cv"]:
            sa, da, dp, pr = key.split("|")
            first_seen("beacon_candidate", sa, f"{da}|{dp}|{pr}", ts,
                       f"{sa} -> {da}:{dp}/{pr} connects on a timer: every {mean:.0f}s (interval CV {cv:.2f}, size CV {bcv:.2f})",
                       {"src": sa, "dst": da, "dport": int(dp), "proto": pr, "interval_s": round(mean),
                        "interval_cv": round(cv, 3), "bytes_cv": round(bcv, 3), "conns": len(starts)})

# ---------------------------------------------------------------- hourly baselines

def roll_hours():
    """Fold closed hours into per-hour-of-day running stats; after the burn-in, flag z-score spikes."""
    cur = int(NOW // 3600)
    rows = DB.execute("SELECT metric, entity, hour, count FROM hourly WHERE hour < ?", (cur,)).fetchall()
    for metric, entity, hour, count in rows:
        hod = dt.datetime.fromtimestamp(hour * 3600, TZ).hour
        s = DB.execute("SELECT n, mean, m2 FROM stats WHERE metric=? AND entity=? AND hod=?", (metric, entity, hod)).fetchone()
        n, mean, m2 = s if s else (0, 0.0, 0.0)
        if ACTIVE and n >= TH["zscore_min_samples"] and count >= TH["volume_min_count"]:
            sd = math.sqrt(m2 / (n - 1)) if n > 1 else 0
            z = (count - mean) / sd if sd > 0 else (float("inf") if count > mean * 3 else 0)
            if z >= TH["zscore"]:
                det = "dmz_bytes_out_spike" if metric == "dmz_bytes_out" else "volume_spike"
                emit(det, entity, f"{metric} for {entity} was {count:.0f} in the {hod:02d}:00 hour; baseline {mean:.0f} +/- {sd:.0f} (z {z:.1f})",
                     {"metric": metric, "entity": entity, "hour_of_day": hod, "count": count, "mean": round(mean, 1),
                      "sd": round(sd, 1), "z": round(z, 2) if z != float('inf') else "inf", "samples": n},
                     dkey=f"vol|{metric}|{entity}|{hour}", ts=hour * 3600)
        n += 1
        d = count - mean
        mean += d / n
        m2 += d * (count - mean)
        DB.execute("INSERT OR REPLACE INTO stats VALUES(?,?,?,?,?,?)", (metric, entity, hod, n, mean, m2))
        DB.execute("DELETE FROM hourly WHERE metric=? AND entity=? AND hour=?", (metric, entity, hour))

# ---------------------------------------------------------------- feed health

def feed_health():
    lim = CFG["feed_silence_minutes"] * 60
    paths = [(d, os.path.join(CFG["syslog_root"], d, f"{d}.log")) for d in CFG["devices"]]
    paths += [(f"{h}:queries", os.path.join(CFG["syslog_root"], h, "queries.log")) for h in CFG["query_logs"]]
    paths += [("fw-edge:eve", os.path.join(CFG["syslog_root"], "fw-edge", "eve.log"))]
    for name, p in paths:
        try:
            age = NOW - os.stat(p).st_mtime
        except FileNotFoundError:
            age = float("inf")
        if age > lim:
            emit("feed_silent", name, f"{name} has sent nothing to the collector for {age/60:.0f} min" if age != float("inf") else f"{name} has no log on the collector",
                 {"feed": name, "path": p, "silent_minutes": None if age == float("inf") else round(age / 60)},
                 dkey=f"silent|{name}")
    for exp in ("rb5009", "fw-edge"):
        newest = max(glob.glob(os.path.join(CFG["flow_csv_root"], exp, "*", "*", "*", "flows-*.csv.gz")), key=os.path.getmtime, default=None)
        age = NOW - os.path.getmtime(newest) if newest else float("inf")
        if age > 20 * 60:
            emit("feed_silent", f"flows:{exp}", f"no new {exp} flow file for {age/60:.0f} min" if newest else f"no {exp} flow files",
                 {"feed": f"flows:{exp}"}, dkey=f"silent|flows:{exp}")

# ---------------------------------------------------------------- housekeeping / burn-in switch

def housekeeping():
    DB.execute("DELETE FROM fails WHERE ts < ?", (NOW - 3600,))
    DB.execute("DELETE FROM beacon WHERE last_ts < ?", (NOW - 3 * 86400,))
    DB.execute("DELETE FROM emitted WHERE ts < ?", (NOW - 7 * 86400,))
    DB.execute("DELETE FROM done_files WHERE ts < ?", (NOW - 35 * 86400,))

def burn_in_switch():
    if not ACTIVE or meta("burn_in_reported"):
        return
    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    rep = os.path.join(HERE, "reports", f"burn-in-report-{dt.datetime.now(TZ):%Y-%m-%d}.md")
    started = meta("first_run") or "?"
    L = [f"# Anomaly engine burn-in report", "",
         f"Burn-in: {started} to {CFG['burn_in_end']}. From this run on, findings go to findings.jsonl and Wazuh (rules 100600-100620).", "",
         "## Baselines learned (first-seen tables)", "", "| Detector | Entities | Keys |", "|---|---|---|"]
    for det, ents, keys in DB.execute("SELECT detector, count(DISTINCT entity), count(*) FROM seen GROUP BY detector ORDER BY detector"):
        L.append(f"| {det} | {ents} | {keys} |")
    L += ["", "## Hourly baselines", "", "| Metric | Entities | Hour-of-day cells | Median samples |", "|---|---|---|---|"]
    for metric, ents, cells, ns in DB.execute("SELECT metric, count(DISTINCT entity), count(*), group_concat(n) FROM stats GROUP BY metric"):
        v = sorted(int(x) for x in ns.split(","))
        L.append(f"| {metric} | {ents} | {cells} | {v[len(v)//2]} |")
    L += ["", "## Timer-driven connections learned as normal (beacon candidates seen during burn-in)", ""]
    for ent, key, cnt in DB.execute("SELECT entity, key, count FROM seen WHERE detector='beacon_candidate' ORDER BY count DESC LIMIT 40"):
        L.append(f"- {ent} -> {key.replace('|', ' ')} ({cnt} times)")
    L += ["", "## Would-be findings during the burn-in (rule-based detectors, from learn.jsonl)", ""]
    agg = {}
    try:
        for line in open(os.path.join(HERE, "learn.jsonl")):
            a = json.loads(line)["anomaly_engine"]
            k = (a["detector"], a["summary"])
            agg[k] = agg.get(k, 0) + 1
    except FileNotFoundError:
        pass
    by_det = {}
    for (det, summ), c in agg.items():
        by_det.setdefault(det, []).append((c, summ))
    if not by_det:
        L.append("None.")
    for det in sorted(by_det):
        items = sorted(by_det[det], reverse=True)
        L.append(f"### {det} ({sum(c for c, _ in items)} total, {len(items)} distinct)")
        L += [f"- {c}x {s}" for c, s in items[:15]]
        L.append("")
    L += ["## Before trusting the alerts", "",
          "- Anything listed under would-be findings that is legitimate belongs in config.json (allow-list, router addresses) before it alerts for real.",
          "- Thresholds live in config.json under thresholds; the engine reads them every run.",
          "- learn.jsonl is kept for reference; delete it whenever you like."]
    open(rep, "w").write("\n".join(L) + "\n")
    meta("burn_in_reported", NOW)
    emit("engine_status", "anomaly-engine", f"burn-in complete; engine now alerting. Report: {rep}",
         {"report": rep, "baseline_keys": DB.execute("SELECT count(*) FROM seen").fetchone()[0]}, force_active=True)
    log(f"burn-in complete, report written to {rep}")

# ---------------------------------------------------------------- main

def main():
    t0 = time.time()
    if not meta("first_run"):
        meta("first_run", dt.datetime.now(TZ).isoformat(timespec="seconds"))
    counts = {}
    for d in CFG["devices"]:
        counts[d] = process_device_log(d)
    for h in CFG["query_logs"]:
        counts[f"{h}:queries"] = process_queries(h)
    counts["eve"] = process_eve()
    for exp in ("rb5009", "fw-edge"):
        counts[f"flows:{exp}"] = process_flows(exp)
    roll_hours()
    resolver_share()
    feed_health()
    housekeeping()
    burn_in_switch()
    DB.commit()
    mode = "active" if ACTIVE else f"learn (until {CFG['burn_in_end']})"
    log(f"mode={mode} read={json.dumps(counts, separators=(',', ':'))} emitted={json.dumps(COUNTS, separators=(',', ':'))} {time.time()-t0:.1f}s")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # keep cron quiet but visible
        DB.commit()
        log(f"ERROR {type(e).__name__}: {e}")
        raise

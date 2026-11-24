#!/usr/bin/env python3
"""investigate_dns_share -- automatic triage when the DNS round-robin split skews (launched by engine.py).

Collects evidence for one flagged window, then has llm-report (local model, Claude on escalation) write the triage:
  - per-server counts, rcodes, average RTT, top clients and names from both Technitium query logs
  - clients that only reached one server (suggests a path that bypasses the RB5009 split)
  - RB5009 state over the agent's read-only SSH login: DNS NAT rule counters and disabled flags, dns-* schedulers
  - a live test query to each resolver from this box
  - RB5009 syslog lines about DNS / scripts / NAT around the window
Writes the report to --report and appends one engine_status line to findings.jsonl pointing at it.
"""
import argparse
import collections
import datetime as dt
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, "config.json")))
RS = CFG["resolver_share"]
TZ = ZoneInfo(CFG["timezone"])
RE_KV = re.compile(r'(\w+)="([^"]*)"')
SSH = ["ssh", "-i", "/home/agent/.ssh/id_ed25519", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
       "-o", "StrictHostKeyChecking=accept-new", "agent@192.168.99.1"]
ROUTER_CMDS = [
    '/ip firewall nat print stats terse where comment~"DNS"',
    '/ipv6 firewall nat print stats terse where comment~"DNS"',
    '/ip firewall nat print terse where comment~"DNS"',
    '/ipv6 firewall nat print terse where comment~"DNS"',
    '/system scheduler print terse where name~"dns"',
]


def ts_of(line):
    try:
        return dt.datetime.fromisoformat(line[:32]).timestamp()
    except ValueError:
        return None


def scan_queries(host, w0, w1):
    import ipaddress
    excl = [ipaddress.ip_network(n) for n in RS.get("exclude", [])]
    internal = [ipaddress.ip_network(n) for n in CFG["nets"]["internal"]]
    dmz = [ipaddress.ip_network(n) for n in CFG["nets"]["dmz"]]
    path = os.path.join(CFG["syslog_root"], host, "queries.log")
    c = {"n": 0, "rcode": collections.Counter(), "clients": collections.Counter(), "names": collections.Counter(),
         "rtt_sum": 0.0, "rtt_n": 0, "out_of_scope": 0}
    try:
        f = open(path, errors="replace")
    except FileNotFoundError:
        return c
    with f:
        for line in f:
            t = ts_of(line)
            if t is None or t < w0 or t >= w1:
                continue
            kv = dict(RE_KV.findall(line))
            cl = kv.get("clientIp")
            if not cl:
                continue
            try:
                a = ipaddress.ip_address(cl)
                scoped = (any(a in n for n in internal if n.version == a.version)
                          and not any(a in n for n in dmz if n.version == a.version)
                          and not any(a in n for n in excl if n.version == a.version))
            except ValueError:
                scoped = False
            if not scoped:
                c["out_of_scope"] += 1
                continue
            c["n"] += 1
            c["rcode"][kv.get("rCode", "?")] += 1
            c["clients"][cl] += 1
            c["names"][kv.get("qName", "?")] += 1
            try:
                c["rtt_sum"] += float(kv.get("responseRtt")); c["rtt_n"] += 1
            except (TypeError, ValueError):
                pass
    return c


def dns_probe(server, name="example.com"):
    """Minimal A query over UDP; returns (ok, rtt_ms, rcode or error)."""
    qid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    t0 = time.time()
    try:
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
        return True, round((time.time() - t0) * 1000, 1), data[3] & 0x0F
    except OSError as e:
        return False, None, str(e)
    finally:
        s.close()


def router_state():
    out = {}
    for cmd in ROUTER_CMDS:
        try:
            r = subprocess.run(SSH + [cmd], capture_output=True, text=True, timeout=25)
            out[cmd] = (r.stdout or r.stderr).strip()[:4000]
        except Exception as e:  # noqa: BLE001
            out[cmd] = f"unavailable: {e}"
    return out


def router_log(w0, w1):
    path = os.path.join(CFG["syslog_root"], "rb5009", "rb5009.log")
    hits = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                t = ts_of(line)
                if t is None or t < w0 - 900 or t > w1 + 300:
                    continue
                if re.search(r"dns|script|nat|resolve", line, re.I) and "syslog-heartbeat" not in line:
                    hits.append(line.strip()[:300])
    except FileNotFoundError:
        pass
    return hits[-60:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-start", type=int, required=True)
    ap.add_argument("--window-sec", type=int, default=900)
    ap.add_argument("--report", required=True)
    ap.add_argument("--no-finding", action="store_true", help="manual/test run: do not append to findings.jsonl")
    a = ap.parse_args()
    w0, w1 = a.window_start, a.window_start + a.window_sec
    servers = RS["servers"]
    stats = {h: scan_queries(h, w0, w1) for h in servers}
    tot = sum(stats[h]["n"] for h in servers) or 1
    all_clients = set().union(*(set(stats[h]["clients"]) for h in servers))
    one_sided = []
    for cl in all_clients:
        per = {h: stats[h]["clients"].get(cl, 0) for h in servers}
        n = sum(per.values())
        if n >= 20 and min(per.values()) == 0:
            one_sided.append({"client": cl, "queries": per})
    evidence = {
        "window": {"start": dt.datetime.fromtimestamp(w0, TZ).isoformat(timespec="minutes"),
                   "end": dt.datetime.fromtimestamp(w1, TZ).isoformat(timespec="minutes")},
        "share": {h: round(stats[h]["n"] / tot, 4) for h in servers},
        "per_server": {h: {"queries": stats[h]["n"], "rcodes": dict(stats[h]["rcode"].most_common(6)),
                           "avg_rtt_ms": round(stats[h]["rtt_sum"] / stats[h]["rtt_n"], 1) if stats[h]["rtt_n"] else None,
                           "top_clients": stats[h]["clients"].most_common(10), "top_names": stats[h]["names"].most_common(10),
                           "out_of_scope_queries": stats[h]["out_of_scope"]} for h in servers},
        "one_sided_clients": sorted(one_sided, key=lambda x: -sum(x["queries"].values()))[:20],
        "live_probe": {h: dict(zip(("ok", "rtt_ms", "rcode_or_error"), dns_probe(RS["addresses"][h]))) for h in servers},
        "router": router_state(),
        "router_log": router_log(w0, w1),
        "baseline_note": "share is learned per hour-of-day during the burn-in; see the triggering finding for mean/sd/z",
    }
    tmp = f"/tmp/dns-share-evidence-{w0}.json"
    json.dump(evidence, open(tmp, "w"), indent=1, default=str)
    inv_dir = os.path.join(HERE, "investigations", "dns-share")
    report = os.path.abspath(a.report)
    verdict = "?"
    try:
        r = subprocess.run(["/home/agent/agents/bin/llm-report", "--input", tmp, "--report", report,
                            "--task", "Triage this DNS round-robin skew per CLAUDE.md.",
                            "--ok-verdict", "Nothing actionable"], cwd=inv_dir, capture_output=True, text=True, timeout=900)
        print(r.stdout[-2000:], r.stderr[-1000:], flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"llm-report failed: {e}", flush=True)
    if not os.path.exists(report):
        with open(report, "w") as f:
            f.write("# DNS round-robin skew: raw evidence (no model report)\n\n```json\n" + json.dumps(evidence, indent=1, default=str) + "\n```\n")
    for line in open(report, errors="replace"):
        s = line.strip()
        if s and not s.startswith("#"):
            verdict = s[:200]
            break
    rec = {"anomaly_engine": {"detector": "engine_status", "severity": "low", "attack": [], "entity": "dns-share-investigation",
                              "summary": f"DNS share investigation ready ({evidence['window']['start']}): {verdict} -- {report}",
                              "evidence": {"report": report, "share": evidence["share"]},
                              "event_time": dt.datetime.now(TZ).isoformat(timespec="seconds"), "mode": "active"}}
    if a.no_finding:
        print(rec["anomaly_engine"]["summary"])
        return
    with open(os.path.join(HERE, "findings.jsonl"), "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()

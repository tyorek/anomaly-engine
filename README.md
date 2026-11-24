# anomaly-engine (P7/P8): local attacker-behaviour detection

Statistics find the anomalies; nothing here calls a model. Built 2026-11-23. Runbook: `rsyslog-collector-standup-runbook.md`
(sections 6 and 8.1), build record `syslog-collector-build-record-2026-11-23.md`.

## How it runs
- `run.sh` from the `agent` crontab every 5 minutes (`3-58/5`), two minutes after the collector exports the closed flow file.
  It holds a lock, so runs can't overlap, and logs one summary line per run to `logs/cron.log` (bounded to about 10k lines).
- **Inputs**, read through the read-only mount `/srv/syslog` from the collector (CT 112):
  - each device's `<dev>/<dev>.log`
  - `primenodetls/queries.log` and `buauth/queries.log` (Technitium Log Exporter)
  - `fw-edge/eve.log` (Suricata eve)
  - `flows-csv/<exporter>/YYYY/MM/DD/flows-*.csv.gz`, written on the collector by `/usr/local/bin/flow-csv-export`. This
    box's nfdump 1.7.1 can't read the collector's 1.7.5 IPFIX files, so the engine reads CSV, not nfcapd files.
- **State:** `state.db` (SQLite) holds read offsets, processed flow files, first-seen tables, hourly per-hour-of-day
  baselines (Welford mean and variance), beacon windows and dedupe. Delete it to start learning again from scratch.
- `config.json` is re-read every run: networks, the DMZ allow-list (fw-edge rules 1030-1055), router addresses, thresholds and the burn-in end date.

## Modes
- **Learn (until `burn_in_end`, 2026-12-07 00:00 CST):**
  - Every first-seen key and hourly count goes into the baseline.
  - The rule-based detectors (DMZ allow-list, fw-edge DMZ blocks, fan-out, login-failure bursts, feed silence,
    monitoring-host egress) write *would-be* findings to `learn.jsonl`, which isn't shipped anywhere.
  - Nothing goes to Wazuh.
- **Active (after that date):**
  - Findings are appended to `findings.jsonl`. The Wazuh agent `claude_agents` tails it (central `agent.conf` block),
    and the manager's rules 100600-100620 (`etc/rules/anomaly_engine_rules.xml`) turn each detector into an ATT&CK-tagged alert.
  - Level 7 and above flows into wazuh-triage and the daily digest as usual.
  - A key first seen *after* the burn-in raises a finding. Hourly counts alert at z >= 4 (with at least 7 samples and a count of at least 50).
- **The switch:** the first run after the burn-in writes `reports/burn-in-report-<date>.md` (baseline sizes, timers learned as
  normal, would-be findings to allow-list) and one `engine_status` alert (rule 100619, level 7) pointing at it.

## Detectors
| Detector | Data | Rule | Level | ATT&CK |
|---|---|---|---|---|
| dmz_internal_connection | fw-edge flows: DMZ-initiated to internal, not in allow-list | 100601 | 10 | T1021 |
| dmz_proxy_internal_connection | same, source NPM/caddy or destination an RB5009 address | 100602 | 12 | T1021, T1210 |
| dmz_firewall_block | fw-edge filterlog: block, DMZ source, internal destination | 100603 | 10 | T1046 |
| dmz_internal_fanout | one DMZ host to >= 10 internal addresses in a 5-min file | 100604 | 11 | T1046 |
| first_seen_outbound_tls | eve tls SNI (registered domain) from DMZ or IoT hosts | 100605 | 8 | T1071.001 |
| first_seen_dns_domain | Technitium queries (registered domain) from DMZ or IoT clients | 100606 | 7 | T1071.004 |
| first_seen_outbound_port | DMZ (fw-edge flows) or IoT (RB5009 flows) to internet, port not 80/443/53/853/123 | 100607 | 8 | T1571 |
| first_seen_inbound_service | internet to DMZ port that answered for the first time | 100608 | 10 | T1190 |
| first_seen_mac | RB5009 DHCP assignment to a new MAC | 100609 | 6 | T1200 |
| first_seen_login | RouterOS/switch login user, source and service | 100610 | 8 | T1078 |
| login_odd_hour | login at an hour never seen for that device and user (baseline >= 5) | 100611 | 8 | T1078 |
| login_failure_burst | >= 5 failures from one source in 10 min | 100612 | 10 | T1110 |
| config_actor_first_seen | RouterOS "... by <actor>" or fw-edge audit "user X changed configuration" | 100613 | 9 | T1098 |
| volume_spike | lines per device, DNS queries per resolver, eve types, firewall prefixes per hour | 100614 | 6 | - |
| dmz_bytes_out_spike | bytes in DMZ-initiated internet flows per host per hour | 100615 | 10 | T1041, T1048 |
| beacon_candidate | src to dst:port with >= 10 new connections over >= 1 h, interval CV <= 0.15, size CV <= 0.35 | 100616 | 9 | T1071, T1573 |
| feed_silent | any device or stream log or flow export quiet > 30 min (flows > 20 min) | 100617 | 10 | T1562 |
| monitoring_host_egress | RB5009 SYSLOG-DROP / AGENT-DROP lines | 100618 | 12 | T1071 |
| resolver_share_imbalance | VLAN 20/25/30 DNS split between primenodetls and buauth, 15-min windows vs the learned per-hour share (z >= 4, or outage-like 15/85) | 100620 | 9 | T1562, T1071.004 |
| engine_status | burn-in complete, investigation reports ready, and so on | 100619 | 7 | - |

Initiator vs reply in flows: service port to ephemeral port is a reply. Both sides ephemeral, or both service, falls back to
which direction appears first in the file. Long sessions are split into 1-minute records, so ordering alone is unreliable.

## Tuning
- A legitimate would-be finding belongs in `config.json`: `dmz_internal_allow`, `router_addresses`, `nets`.
- To re-learn one detector: `DELETE FROM seen WHERE detector='...'` in `state.db`.
- To quiet a noisy rule without touching the engine: raise its level-0 override on the manager.

## DNS round-robin balance and the automatic investigation
- **What's split:** the RB5009 splits DNS from VLANs 20, 25 and 30 per query between primenodetls and buauth
  (`nth=2,1` dst-nat, IPv4 and IPv6). `dns-rr-check` on the router fails over when one resolver stops answering.
  The split is per new UDP/TCP connection, which is per query for normal stub resolvers. Clients in the router
  address-list `dns-rr-pin` always go to primenodetls: that's for devices with an internet-block rule (G9, 192.168.25.5),
  because buauth is reached through fw-edge's handoff, which is in the WAN list. Pinned clients are also in `resolver_share.exclude`.
- **What the engine counts:** per 5 minutes, the in-scope queries each server logged (`config.json: resolver_share`;
  VLANs 5, 15 and 99, the DMZ, the handoff and pinned clients are excluded). It closes 15-minute windows and learns primenodetls's share per hour of day.
- **During the burn-in:** outage-like windows (outside 15-85 %) are kept out of the baseline and noted in `learn.jsonl`.
- **After the burn-in:** a window at |z| >= 4, or an outage-like window, raises `resolver_share_imbalance` (rule 100620)
  and starts `investigate_dns_share.py` in the background. That collects:
  - per-server counts, rcodes and RTT
  - top clients and names
  - clients that reached only one server
  - the RB5009 NAT and scheduler state over the agent's read-only SSH login
  - live probes and router log lines

  It then runs `llm-report` with `investigations/dns-share/CLAUDE.md`: the local model writes the triage, escalating to Claude when the
  verdict isn't "Nothing actionable". The report goes to `reports/investigations/dns-share-<window>.md`, and an
  `engine_status` alert points at it.

## Heartbeat

Since 2026-11-24 `run.sh` pushes the Uptime Kuma monitor `anomaly-engine` (15-minute heartbeat, Discord on down)
after every run: up when engine.py exits 0, down with the exit code otherwise. The push URL is
`KUMA_PUSH_ANOMALY_ENGINE` in `/home/agent/.config/agent.env`. Attacker stories built from the engine's findings are
in `../attack-stories/` (P11-P13).

---

*Published from a home lab. Site identifiers are sanitized: public IPv4 uses the documentation ranges (203.0.113.0/24, 198.51.100.0/24), the delegated IPv6 prefix is `2001:db8::/32`, the ULA prefix is `fd12:3456:789a::/48`, domains are `example.com` / `home.arpa`, MAC addresses, Wi-Fi SSIDs, serials, keys and names are replaced. RFC 1918 addresses are left as they are so the layouts still read. Credentials are never in these files; scripts read them from `agent.env` or similar files that are not published.*

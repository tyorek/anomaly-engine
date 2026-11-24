#!/bin/bash
# anomaly-engine/run.sh -- cron every 5 minutes (3-58/5, two minutes after the collector's flow export). See README.md.
cd "$(dirname "$0")" || exit 1
mkdir -p logs reports
exec 9>.lock
flock -n 9 || { echo "$(date -Is) previous run still going, skipping" >> logs/cron.log; exit 0; }
/usr/bin/python3 engine.py >> logs/cron.log 2>&1
rc=$?
# Uptime Kuma push monitor "anomaly-engine" (2026-11-24): up after a clean run, down with the exit code otherwise
url=$(grep -oP '^KUMA_PUSH_ANOMALY_ENGINE=\K.*' /home/agent/.config/agent.env 2>/dev/null || true)
if [ -n "$url" ]; then
    if [ "$rc" -eq 0 ]; then q="status=up&msg=ok"; else q="status=down&msg=engine.py%20exit%20$rc"; fi
    curl -fsS -m 10 -o /dev/null "${url}?${q}" || true
fi
# keep the run log bounded
if [ "$(wc -l < logs/cron.log)" -gt 20000 ]; then tail -n 10000 logs/cron.log > logs/cron.log.tmp && mv logs/cron.log.tmp logs/cron.log; fi
exit $rc

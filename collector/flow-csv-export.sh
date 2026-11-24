#!/bin/sh
# Convert closed nfcapd files into slim gzipped CSV for the anomaly engine on the agent box (CT 107).
# Why: the agent box's nfdump 1.7.1 can't decode the IPFIX extensions nfcapd 1.7.5 writes ("Unknown extension 42").
# Output: /var/log/remote/flows-csv/<exporter>/YYYY/MM/DD/flows-YYYYMMDDhhmm.csv.gz
# Columns (|-separated): ts|te|src|dst|sport|dport|proto|flags|packets|bytes   (-6 full IPv6, -N plain numbers)
# Added 2026-11-23. Cron: /etc/cron.d/flow-csv-export. Pass a minute count as $1 to backfill further (default 180).
set -eu
SRC=/var/log/remote/flows
DST=/var/log/remote/flows-csv
AGE=${1:-180}
for exp in rb5009 fw-edge; do
  [ -d "$SRC/$exp" ] || continue
  find "$SRC/$exp" -type f -name 'nfcapd.2*' -mmin -"$AGE" | sort | while read -r f; do
    rel=${f#"$SRC/$exp/"}; d=$(dirname "$rel"); t=$(basename "$f"); t=${t#nfcapd.}
    out="$DST/$exp/$d/flows-$t.csv.gz"
    [ -s "$out" ] && continue
    mkdir -p "$DST/$exp/$d"
    if nfdump -r "$f" -q -N -6 -o 'fmt:%ts|%te|%sa|%da|%sp|%dp|%pr|%flg|%pkt|%byt' 2>/dev/null | gzip -c > "$out.tmp"; then
      mv "$out.tmp" "$out"
    else
      rm -f "$out.tmp"
    fi
  done
done
find "$DST" -type f -name 'flows-*.csv.gz' -mtime +30 -delete
find "$DST" -mindepth 2 -type d -empty -delete

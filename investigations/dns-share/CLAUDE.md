# DNS round-robin skew triage

The RB5009 splits DNS from VLANs 20, 25 and 30 per query between primenodetls (192.168.15.9, VLAN 15) and buauth
(10.20.0.9, DMZ behind fw-edge) with an `nth=2,1` dst-nat rule pair ("RR DNS split primary/dmz", IPv4 and IPv6).
A `dns-rr-check` script on the router probes both every 30 s. If buauth fails it disables "RR DNS split dmz" and enables
"RR DNS failover primary". If primenodetls fails it disables "RR DNS split primary". VLAN 5 is pinned to primenodetls by
the older "LAN DNS redirect" rules. VLANs 15 and 99 and the DMZ are not part of the split.

The anomaly engine learned the normal share per hour of day during the burn-in. This window was flagged because the share
moved well outside that. You get the evidence JSON for the window.

Write a short report:
1. First line (not a heading): the verdict. Use exactly "Nothing actionable" when the skew is explained by something
   benign that has already recovered, e.g. a brief resolver restart and failover in the router log, or too little traffic.
   Otherwise start with "Needs attention:" and the one-line reason.
2. **What happened:** the shares, counts, rcodes and RTTs per server, and what changed versus normal.
3. **Likely cause:** pick from the evidence, don't guess beyond it:
   - failover engaged (RR rules disabled or enabled, dns-rr-check lines in the router log)
   - a resolver degraded (SERVFAIL/REFUSED, high RTT, failed live probe)
   - split rules changed or disabled by a person (rule flags without matching probe failures; this is T1562, impair defenses)
   - a firewall path to one resolver blocked for some clients (one-sided clients whose queries to that server never got answers; e.g. a device with an internet-block rule cannot reach buauth because fw-edge sits on a WAN-list interface; the fix is adding it to the router address-list dns-rr-pin)
   - clients bypassing the split ("one_sided_clients": a client that only reached one server in the window)
   - something else the evidence clearly shows
4. **Next step:** one or two concrete checks or fixes.

Keep it under 250 words. Never invent values that aren't in the evidence.

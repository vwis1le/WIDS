import argparse
import os
import time
import joblib
from scapy.all import sniff
from features import FEATURES, record, windowize, in_network, WIN
 
ap = argparse.ArgumentParser()
g = ap.add_mutually_exclusive_group(required=True)
g.add_argument("--iface"); g.add_argument("--pcap")
ap.add_argument("--model", default="wids_model.joblib")
ap.add_argument("--bssid", nargs="*", default=[], help="only monitor these AP MACs (omit = all)")
ap.add_argument("--bssid-file", default="bssid.txt")
ap.add_argument("--wips", action="store_true", help="auto-action: add offender to blocklist.txt")
args = ap.parse_args()
 
model = joblib.load(args.model)
buf, cur, blocked = [], [None], set()
bssids = {b.lower() for b in args.bssid}
print("[*] Monitoring:", ", ".join(sorted(bssids)) or "ALL networks")
 
 
def refresh_filter():
    """Re-read bssid.txt (if present) so the target network can be switched live."""
    global bssids, buf
    if not os.path.exists(args.bssid_file):
        return
    words = open(args.bssid_file).read().lower().split()
    new = set() if (not words or "all" in words) else set(words)
    if new != bssids:
        bssids, buf = new, []
        print("[*] Now monitoring:", ", ".join(sorted(bssids)) or "ALL networks")
 
 
def alert(r):
    """Print/log one alert; in WIPS mode also blocklist the offending MAC."""
    msg = (f"[{time.strftime('%H:%M:%S')}] ALERT deauth/disassoc attack from {r.src} "
           f"({int(r.deauth + r.disas)} mgmt kill frames/s, RSSI {r.rssi_mean:.0f} dBm)")
    print(msg)
    with open("wids_alerts.log", "a") as f:
        f.write(msg + "\n")
    if args.wips and r.src != "unknown" and r.src not in blocked:
        blocked.add(r.src)
        with open("blocklist.txt", "a") as f:
            f.write(r.src + "\n")
        print(f"    [WIPS] {r.src} added to blocklist.txt")
 
 
def flush():
    global buf
    w = windowize(buf); buf = []
    if w.empty:
        return
    w["pred"] = model.predict(w[FEATURES])
    for _, r in w[w.pred == 1].iterrows():
        alert(r)
 
 
last_poll = [0.0]
 
 
def on_pkt(p):
    if time.time() - last_poll[0] >= 1:   
        last_poll[0] = time.time()        
        refresh_filter()
    r = record(p)
    if not r or not in_network(r, bssids):
        return
    wid = int(r["t"] // WIN)
    if cur[0] is None:
        cur[0] = wid
    if wid > cur[0]:
        flush(); cur[0] = wid
    buf.append(r)
 
 
refresh_filter()
sniff(iface=args.iface, offline=args.pcap, prn=on_pkt, store=False)
flush()
 

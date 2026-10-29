import numpy as np
import pandas as pd
from scapy.all import PcapReader
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas
 
FEATURES = ["fps", "deauth", "disas", "deauth_ratio", "mgmt_frac",
            "uniq_dst", "rssi_mean", "rssi_std", "mean_len"]
WIN = 1.0  # seconds
 
 
def record(pkt):
    """One Scapy packet -> small dict (or None if not 802.11 / no transmitter)."""
    if not pkt.haslayer(Dot11):
        return None
    d = pkt[Dot11]
    if d.addr2 is None:
        return None
    rssi = getattr(pkt, "dBm_AntSignal", None)
    length = getattr(pkt, "wirelen", None) or len(pkt)   # wirelen is free (from the pcap
                                                          # record header); len(pkt) rebuilds
                                                          # the whole packet, slow at scale
    return dict(t=float(pkt.time), src=d.addr2.lower(),
                dst=(d.addr1 or "").lower(), bssid=(d.addr3 or "").lower(),
                is_mgmt=int(d.type == 0), length=length,
                deauth=int(pkt.haslayer(Dot11Deauth)),
                disas=int(pkt.haslayer(Dot11Disas)),
                rssi=np.nan if rssi is None else rssi)
 
 
def in_network(r, bssids):
    """True if the frame belongs to one of the chosen BSSIDs (empty set = no filter).
    A frame counts if the AP MAC appears as BSSID, transmitter or receiver. Forged
    deauths carry the real AP's BSSID, so they are still caught."""
    if not bssids:
        return True
    return r["bssid"] in bssids or r["src"] in bssids or r["dst"] in bssids
 
 
def windowize(recs, win=WIN):
    """List of frame dicts -> one row per (source MAC, time window)."""
    cols = ["src", "w"] + FEATURES
    if not recs:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(recs)
    df["w"] = (df.t // win).astype(int)
    out = df.groupby(["src", "w"]).agg(
        frames=("t", "size"), deauth=("deauth", "sum"), disas=("disas", "sum"),
        mgmt_frac=("is_mgmt", "mean"), uniq_dst=("dst", "nunique"),
        rssi_mean=("rssi", "mean"), rssi_std=("rssi", "std"),
        mean_len=("length", "mean")).reset_index()
    out["fps"] = out.frames / win
    out["deauth_ratio"] = (out.deauth + out.disas) / out.frames
    out["rssi_mean"] = out.rssi_mean.fillna(-100)
    out["rssi_std"] = out.rssi_std.fillna(0)
    return out[cols]
 
 
def read_pcap(path, bssids=None, progress_every=10000):
    bssids = {b.lower() for b in (bssids or [])}
    recs = []
    n = 0
    with PcapReader(path) as pr:
        for p in pr:
            n += 1
            if progress_every and n % progress_every == 0:
                print(f"  ...{path}: {n} packets read, {len(recs)} kept so far")
            r = record(p)
            if r and in_network(r, bssids):
                recs.append(r)
    if progress_every:
        print(f"  {path}: done, {n} packets read, {len(recs)} kept")
    return recs

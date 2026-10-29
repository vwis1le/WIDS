import os, random
from scapy.all import wrpcap, Raw
from scapy.layers.dot11 import (RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth)

random.seed(1)
AP, ATK = "aa:bb:cc:00:00:01", "de:ad:be:ef:00:01"
CLIENTS = ["02:00:00:00:00:%02x" % i for i in range(2, 6)]
BC = "ff:ff:ff:ff:ff:ff"


def rt(rssi):
    return RadioTap(present="dBm_AntSignal", dBm_AntSignal=int(rssi))


def normal(t0, secs):
    out = []
    for s in range(secs):
        for k in range(10):                            
            p = rt(random.gauss(-40, 2)) / Dot11(type=0, subtype=8, addr1=BC, addr2=AP, addr3=AP) / Dot11Beacon() / Dot11Elt(ID=0, info=b"Lab")
            p.time = t0 + s + k / 10; out.append(p)
        for c in CLIENTS:                              
            for _ in range(random.randint(1, 40)):
                p = rt(random.gauss(-55, 4)) / Dot11(type=2, subtype=0, addr1=AP, addr2=c, addr3=AP) / Raw(os.urandom(random.randint(40, 600)))
                p.time = t0 + s + random.random(); out.append(p)
        if random.random() < 0.05:                     
            p = rt(-40) / Dot11(type=0, subtype=12, addr1=random.choice(CLIENTS), addr2=AP, addr3=AP) / Dot11Deauth(reason=3)
            p.time = t0 + s + 0.5; out.append(p)
    return out


def attack(t0, secs):
    out = normal(t0, secs)
    for s in range(secs):
        if (s // 10) % 2 == 1:                             
            for _ in range(random.randint(40, 120)):
                p = rt(random.gauss(-35, 3)) / Dot11(type=0, subtype=12, addr1=random.choice(CLIENTS), addr2=ATK, addr3=AP) / Dot11Deauth(reason=7)
                p.time = t0 + s + random.random(); out.append(p)
    return sorted(out, key=lambda p: p.time)


wrpcap("normal.pcap", sorted(normal(1_700_000_000, 120), key=lambda p: p.time))
wrpcap("attack.pcap", attack(1_700_001_000, 120))
print("wrote normal.pcap, attack.pcap | attacker MAC:", ATK)

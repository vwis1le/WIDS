# WIDS — Wi-Fi Deauthentication Flood Detector

A lightweight wireless intrusion detection (and prevention) system that uses
scikit-learn to classify Wi-Fi traffic as normal or malicious, with a focus
on deauthentication flood attacks.

Traffic is captured in monitor mode with a USB Wi-Fi adapter (tested on a
Qualcomm Atheros AR9271), reduced to a handful of per-device, per-second
features, and classified with a Decision Tree or Random Forest. In WIPS
mode, the system also logs the offending MAC address to a blocklist.

> Run this only on your own network, or one you have explicit authorisation
> to test. Monitor-mode capture and deauthentication attacks affect every
> device on the channel, not just your own.

## How it works

```
 capture            features              model                 action
(monitor mode) → (per-device, per-sec) → (scikit-learn) → (alert + optional block)
```

1. **Capture** — `tcpdump`/Scapy in monitor mode reads every 802.11 frame
   on the target channel.
2. **Feature extraction** (`features.py`) — frames are grouped by sender
   MAC and 1-second window into nine features: frame rate, deauth/disas
   counts and ratio, management-frame fraction, number of distinct
   destinations, RSSI mean/std, and mean frame length.
3. **Training** (`train.py`) — a Decision Tree and a Random Forest are
   trained on labelled capture(s) and compared against a simple rule-based
   baseline (`deauth + disas ≥ threshold`).
4. **Detection** (`detect.py`) — the saved model scores live or replayed
   traffic in real time, raising alerts and (optionally) blocklisting
   offending MACs.

## Files

| File | Purpose |
|---|---|
| `features.py` | Shared frame parsing and feature extraction, used by both `train.py` and `detect.py` |
| `train.py` | Trains and evaluates the models; prints accuracy, a confusion matrix, and the learned tree rules |
| `detect.py` | Live or replayed detection; `--wips` also blocklists offending MACs |
| `synth_pcap.py` | Generates synthetic traffic for testing the pipeline with no radio hardware |

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy scikit-learn pandas matplotlib joblib
```

Put the capture adapter into monitor mode and lock it to the target
network's channel:

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
sudo iw dev wlan0mon set channel 6
```

## Usage

**No hardware yet? Try it on synthetic data first:**
```bash
python synth_pcap.py
python train.py --normal normal.pcap --attack attack.pcap --attacker-mac de:ad:be:ef:00:01
python detect.py --pcap attack.pcap --wips
```

**Capture your own traffic:**
```bash
sudo tcpdump -i wlan0mon -w normal.pcap      # no attack running
sudo tcpdump -i wlan0mon -w attack.pcap      # attack running, separate terminal
sudo aireplay-ng --deauth 0 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon
```

**Train on a real capture:**
```bash
python train.py --normal normal.pcap --attack attack.pcap --attacker-mac <AP_BSSID>
```

> Deauth frames are forged to impersonate the access point, so
> `--attacker-mac` should be the **AP's BSSID**, not the attacking
> device's own MAC. A window is only labelled malicious if it's from
> that MAC *and* actually contains deauth/disassoc frames that second,
> so the AP's ordinary beacons aren't mislabelled too.

**Detect live:**
```bash
sudo python detect.py --iface wlan0mon --wips
```

**Restrict to one network** (recommended in crowded RF environments):
```bash
python train.py --normal normal.pcap --attack attack.pcap --attacker-mac <AP_BSSID> --bssid <AP_BSSID>
sudo python detect.py --iface wlan0mon --bssid <AP_BSSID> --wips
```

## Results

Evaluated on a real capture (own mobile-hotspot testbed, 2,638 test windows,
72 of them malicious):

| Model | Accuracy | Malicious precision | Malicious recall | False alarms |
|---|---|---|---|---|
| Rule (deauth ≥ 10/s) | 97.3% | 0.50 | 0.99 | 71 |
| Decision Tree | 99.9% | 1.00 | 0.96 | 0 |
| Random Forest | 99.96% | 1.00 | 0.99 | 0 |

The plain rule catches almost every attack but also flags 71 ordinary
seconds as malicious, most likely legitimate deauth bursts from
neighbouring access points. Both ML models matched the rule's recall
while eliminating every one of those false alarms, by also weighing
frame length, destination spread, and signal-strength consistency.

Top Random Forest feature importances: `deauth` (37%), `deauth_ratio`
(27%), `fps` (12%), `mean_len` (11%), `rssi_mean` (7%).

## Limitations & future work

- Labels are assigned by MAC address (the AP's BSSID, since deauth frames
  impersonate it); a more robust version would label by time window
  and content, to resist spoofing of other MACs.
- Only deauthentication/disassociation floods are detected; beacon floods
  and evil-twin access points are not.
- The adapter monitors one channel at a time; no channel hopping.
- WIPS currently only logs and blocklists; it does not push the block to
  the access point itself (e.g. via a hostapd deny-list).
- Trained and evaluated on one own-network capture; not yet validated
  against a public dataset such as AWID3.


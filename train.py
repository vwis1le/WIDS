import argparse
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (ConfusionMatrixDisplay, accuracy_score,
                             classification_report, confusion_matrix)
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree
from features import FEATURES, read_pcap, windowize
 
 
def load(path, attackers, bssids):
    df = windowize(read_pcap(path, bssids)).sort_values("w")
    # malicious = from a watched MAC (often the AP's spoofed BSSID) AND actually sending
    # deauth/disassoc that second, not just any traffic from that MAC (e.g. real beacons)
    df["label"] = (df.src.isin(attackers) & ((df.deauth + df.disas) > 0)).astype(int)
    return df
 
 
def chrono_split(df, frac=0.7):
    """Train on the earlier part, test on the later part (no random shuffling:
    neighbouring windows are near-duplicates and would leak into the test set)."""
    cut = df.w.quantile(frac)
    return df[df.w <= cut], df[df.w > cut]
 
 
ap = argparse.ArgumentParser()
ap.add_argument("--normal", nargs="*", default=[])
ap.add_argument("--attack", nargs="*", default=[])
ap.add_argument("--capture", nargs="*", default=[], help="one or more continuous captures (normal + attack mixed together)")
ap.add_argument("--attacker-mac", nargs="+", required=True)
ap.add_argument("--bssid", nargs="*", default=[],
                help="only use frames of these AP MACs (omit = all networks)")
ap.add_argument("--rule-threshold", type=int, default=10,
                help="baseline rule: deauth+disassoc per second >= this means attack")
args = ap.parse_args()
attackers = {m.lower() for m in args.attacker_mac}
all_files = args.normal + args.attack + args.capture
if not all_files:
    ap.error("give --capture, or --normal/--attack")
 
tr, te = [], []
for f in all_files:
    a, b = chrono_split(load(f, attackers, args.bssid))
    tr.append(a); te.append(b)
train, test = pd.concat(tr), pd.concat(te)
print(f"train windows: {len(train)} (attack {train.label.sum()}) | "
      f"test windows: {len(test)} (attack {test.label.sum()})")
 
 
def report(name, pred):
    """Print accuracy + per-class report and save a confusion matrix image."""
    print(f"\n=== {name} === accuracy: {accuracy_score(test.label, pred):.4f}")
    print(classification_report(test.label, pred, labels=[0, 1], target_names=["normal", "malicious"], zero_division=0))
    cm = confusion_matrix(test.label, pred, labels=[0, 1])
    ConfusionMatrixDisplay(cm, display_labels=["normal", "malicious"]).plot(cmap="Blues")
    plt.title(f"{name} (test set)"); plt.savefig(f"confusion_{name}.png", dpi=150); plt.close()
 
 
# Baseline: a hand-written rule, no learning. The ML models must beat or explain themselves against this.
rule = ((test.deauth + test.disas) >= args.rule_threshold).astype(int)
report("Rule", rule)
 
models = {
    "DecisionTree": DecisionTreeClassifier(max_depth=5, class_weight="balanced", random_state=0),
    "RandomForest": RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=0),
}
for name, m in models.items():
    m.fit(train[FEATURES], train.label)          # <- the learning
    report(name, m.predict(test[FEATURES]))      # <- evaluation on unseen windows
 
# Show what the tree learned, as text and as a poster-ready picture
dt = models["DecisionTree"]
print("\nLearned Decision Tree rules:")
print(export_text(dt, feature_names=FEATURES))
plt.figure(figsize=(14, 7))
plot_tree(dt, feature_names=FEATURES, class_names=["normal", "malicious"], filled=True, rounded=True, fontsize=8)
plt.savefig("tree_DecisionTree.png", dpi=150, bbox_inches="tight"); plt.close()
 
rf = models["RandomForest"]
print("Feature importances (RF):")
for f, v in sorted(zip(FEATURES, rf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {f:14s} {v:.3f}")
joblib.dump(rf, "wids_model.joblib")
print("\nsaved wids_model.joblib, confusion_*.png, tree_DecisionTree.png")

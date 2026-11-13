#!/usr/bin/env python3
# Part D chart generator. Reads the CSVs written by the TASKD benchmark and
# renders performance/chart.png (handshake time + record throughput, v1 vs v2).
# Usage: python3 performance/plot.py
import csv, statistics, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

here = os.path.dirname(os.path.abspath(__file__))

# handshake.csv: ver,run,microseconds (no header)
hs = {"v1": [], "v2": []}
with open(os.path.join(here, "handshake.csv")) as f:
    for row in csv.reader(f):
        if len(row) == 3 and row[0] in hs:
            hs[row[0]].append(float(row[2]) / 1000.0)   # ms

# throughput.csv: version,op,run,mb_per_s (header)
tp = {}
with open(os.path.join(here, "throughput.csv")) as f:
    for row in csv.DictReader(f):
        tp.setdefault((row["version"], row["op"]), []).append(float(row["mb_per_s"]))

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.2))

# Left: handshake mean +/- sd
vers = ["v1", "v2"]
means = [statistics.mean(hs[v]) for v in vers]
sds = [statistics.pstdev(hs[v]) for v in vers]
ax1.bar(vers, means, yerr=sds, capsize=6, color=["#6b9bd1", "#d98b5f"])
ax1.set_ylabel("handshake time (ms)")
ax1.set_title("Handshake: connect to greeting decrypted")
for i, m in enumerate(means):
    ax1.text(i, m, f" {m:.2f} ms", va="bottom", ha="center")

# Right: throughput by op
ops = ["seal", "open"]
x = range(len(ops))
w = 0.35
for j, v in enumerate(vers):
    vals = [statistics.mean(tp[(v, o)]) for o in ops]
    errs = [statistics.pstdev(tp[(v, o)]) for o in ops]
    ax2.bar([i + (j - 0.5) * w for i in x], vals, w, yerr=errs, capsize=5,
            label=v, color=["#6b9bd1", "#d98b5f"][j])
ax2.set_xticks(list(x)); ax2.set_xticklabels(ops)
ax2.set_ylabel("throughput (MB/s, 1 KiB records)")
ax2.set_title("Record throughput")
ax2.legend()

fig.suptitle("SmartLock v1 vs v2 performance", fontweight="bold")
fig.tight_layout()
out = os.path.join(here, "chart.png")
fig.savefig(out, dpi=130)
print("wrote", out)

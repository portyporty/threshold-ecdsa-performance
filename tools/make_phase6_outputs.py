import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "bench_results_1000.csv"
OUT_CLEAN = ROOT / "bench_a2_c3_clean_1000.csv"
OUT_MD = ROOT / "bench_summary_1000.md"


def summarize(vals):
    vals = sorted(vals)
    n = len(vals)
    mean = sum(vals) / n
    med = statistics.median(vals)
    var = sum((x - mean) ** 2 for x in vals) / n
    sd = math.sqrt(var)
    return mean, sd, med, vals[0], vals[-1]


def main():
    if not RAW.exists():
        raise SystemExit(f"Missing input CSV: {RAW}")

    # Pivot A2/C3 into a clean wide CSV (one row per iteration).
    wall = defaultdict(dict)
    cycles = defaultdict(dict)
    with RAW.open(newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            sid = row["scenario_id"]
            it = int(row["iteration"])
            if sid in ("A2", "C3"):
                wall[it][sid] = float(row["wall_ms"])
                cycles[it][sid] = int(row["cpu_cycles"])

    lines = ["iteration,A2_wall_ms,C3_wall_ms,A2_cycles,C3_cycles"]
    for it in sorted(wall):
        if "A2" in wall[it] and "C3" in wall[it]:
            lines.append(
                f"{it},{wall[it]['A2']:.6f},{wall[it]['C3']:.6f},{cycles[it]['A2']},{cycles[it]['C3']}"
            )
    OUT_CLEAN.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Scenario summary table (computed from the same raw CSV).
    want = ["A1", "A2", "B", "C1", "C2", "C3"]
    labels = {
        "A1": "Standard ECDSA s-phase only",
        "A2": "Standard ECDSA full sign",
        "B": "Bitcoin multisig 2-of-2",
        "C1": "Threshold ECDSA online",
        "C2": "Threshold ECDSA full (presign+sign)",
        "C3": "Threshold MPC + Paillier HE (user)",
    }

    wall_s = defaultdict(list)
    cyc_s = defaultdict(list)
    with RAW.open(newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            sid = row["scenario_id"]
            if sid in want:
                wall_s[sid].append(float(row["wall_ms"]))
                cyc_s[sid].append(int(row["cpu_cycles"]))

    md = []
    md.append("| ID | Scenario | mean (ms) | stddev (ms) | median (ms) | min (ms) | max (ms) | mean (cycles) |")
    md.append("|---|---|---:|---:|---:|---:|---:|---:|")
    for sid in want:
        m, sd, med, mn, mx = summarize(wall_s[sid])
        mc = sum(cyc_s[sid]) / len(cyc_s[sid])
        md.append(
            f"| {sid} | {labels[sid]} | {m:.3f} | {sd:.3f} | {med:.3f} | {mn:.3f} | {mx:.3f} | {mc:,.0f} |"
        )
    OUT_MD.write_text("\n".join(md) + "\n", encoding="utf-8")

    # Mean ratio of per-iteration C3/A2 (derived from wide pivot).
    ratios = [wall[it]["C3"] / wall[it]["A2"] for it in sorted(wall) if "A2" in wall[it] and "C3" in wall[it]]
    ratio_mean = summarize(ratios)[0]

    print(f"Wrote: {OUT_CLEAN}")
    print(f"Wrote: {OUT_MD}")
    print(f"Mean(C3/A2) over iterations: {ratio_mean:.6f}x")


if __name__ == '__main__':
    main()


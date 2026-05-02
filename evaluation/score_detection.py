#!/usr/bin/env python3
"""Post-hoc detection accuracy scorer for BGP-Sentry-RS.

Reads detection_results.json from a run and computes:
  1. Event-level metrics: per unique attack (prefix, origin, label), detected if ≥1 node caught it
  2. Announcement-level metrics: per individual observation, is_attack vs detected

Usage:
  python3 evaluation/score_detection.py results/5008_lacnic_5plus_mh/hop1_20260422_122914/
  python3 evaluation/score_detection.py path/to/detection_results.json
"""

import sys
import os
import json
from collections import defaultdict, Counter

try:
    import ijson
    HAS_IJSON = True
except ImportError:
    HAS_IJSON = False
    print("WARNING: ijson not installed. Large files will use full JSON load (high memory).")
    print("Install with: pip install ijson\n")


def stream_results(path):
    """Yield detection result records from a JSON array file."""
    if HAS_IJSON:
        with open(path, "rb") as f:
            for item in ijson.items(f, "item"):
                yield item
    else:
        with open(path) as f:
            data = json.load(f)
        yield from data


def score(results_path):
    # --- Collect per-record and per-event data ---
    # Announcement-level
    a_tp = a_fp = a_fn = a_tn = 0
    a_tp_by_type = Counter()
    a_fn_by_type = Counter()
    a_fp_by_det = Counter()

    # Event-level: key = (prefix, origin_asn, label)
    events = defaultdict(lambda: {
        "label": "",
        "prefix": "",
        "origin_asn": 0,
        "total_observers": 0,
        "detected_by": 0,
        "actions": Counter(),
    })

    # Action distribution
    action_counts = Counter()

    total = 0
    for item in stream_results(results_path):
        total += 1
        is_attack = item.get("is_attack", False)
        detected = item.get("detected", False)
        label = item.get("label", "UNKNOWN")
        det_type = item.get("detection_type")
        action = item.get("action", "")
        prefix = item.get("prefix", "")
        origin = item.get("origin_asn", 0)

        action_counts[action] += 1

        # Announcement-level
        if is_attack and detected:
            a_tp += 1
            a_tp_by_type[label] += 1
        elif is_attack and not detected:
            a_fn += 1
            a_fn_by_type[label] += 1
        elif not is_attack and detected:
            a_fp += 1
            a_fp_by_det[det_type or "UNKNOWN"] += 1
        else:
            a_tn += 1

        # Event-level (attacks only)
        if is_attack:
            key = (prefix, origin, label)
            evt = events[key]
            evt["label"] = label
            evt["prefix"] = prefix
            evt["origin_asn"] = origin
            evt["total_observers"] += 1
            evt["actions"][action] += 1
            if detected:
                evt["detected_by"] += 1

        if total % 5_000_000 == 0:
            print(f"  processed {total:,}...", flush=True)

    # --- Compute metrics ---
    def metrics(tp, fp, fn):
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        return prec, rec, f1

    a_prec, a_rec, a_f1 = metrics(a_tp, a_fp, a_fn)

    # Event-level
    e_tp = sum(1 for v in events.values() if v["detected_by"] > 0)
    e_fn = sum(1 for v in events.values() if v["detected_by"] == 0)
    # Event-level FP: count unique (prefix, origin) where not attack but detected
    # We can't easily compute this from events dict (only tracks attacks), so use 0
    # FP at event level is less meaningful — use announcement-level FP instead
    e_fp = 0  # not tracked at event level
    e_prec, e_rec, e_f1 = metrics(e_tp, e_fp, e_fn)

    # Per-type event-level
    type_events = defaultdict(lambda: {"total": 0, "detected": 0})
    for v in events.values():
        t = v["label"]
        type_events[t]["total"] += 1
        if v["detected_by"] > 0:
            type_events[t]["detected"] += 1

    # --- Print report ---
    print(f"\n{'=' * 70}")
    print(f"  DETECTION ACCURACY REPORT")
    print(f"  File: {results_path}")
    print(f"  Total records: {total:,}")
    print(f"{'=' * 70}")

    print(f"\n  ── EVENT-LEVEL (per unique attack) ──")
    print(f"  Total attack events:   {e_tp + e_fn}")
    print(f"  Detected (≥1 node):    {e_tp}")
    print(f"  Missed:                {e_fn}")
    print(f"  Recall:                {e_rec:.4f} ({e_rec*100:.1f}%)")
    print(f"\n  Per attack type:")
    print(f"  {'Type':<25s} {'Detected':>10s} {'Total':>10s} {'Recall':>10s}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10}")
    for t in sorted(type_events.keys()):
        d = type_events[t]["detected"]
        tot = type_events[t]["total"]
        rec = d / tot * 100 if tot > 0 else 0
        print(f"  {t:<25s} {d:>10,} {tot:>10,} {rec:>9.1f}%")

    print(f"\n  ── EVENT DETAILS ──")
    for status_label, filter_fn in [("DETECTED", lambda v: v["detected_by"] > 0),
                                      ("MISSED", lambda v: v["detected_by"] == 0)]:
        matched = [(k, v) for k, v in events.items() if filter_fn(v)]
        if not matched:
            continue
        print(f"\n  --- {status_label} ---")
        for key, evt in sorted(matched, key=lambda x: x[0]):
            print(f"  {evt['label']:<22s} prefix={evt['prefix']:<22s} origin={evt['origin_asn']:<8} "
                  f"observers={evt['total_observers']:>6,}  detected_by={evt['detected_by']:>5,}")

    print(f"\n  ── ANNOUNCEMENT-LEVEL (per observation) ──")
    print(f"  True Positives:    {a_tp:>10,}")
    print(f"  False Positives:   {a_fp:>10,}")
    print(f"  False Negatives:   {a_fn:>10,}")
    print(f"  True Negatives:    {a_tn:>10,}")
    print(f"  Precision:         {a_prec:.4f}")
    print(f"  Recall:            {a_rec:.4f}")
    print(f"  F1:                {a_f1:.4f}")

    print(f"\n  Per attack type (announcement-level):")
    print(f"  {'Type':<25s} {'TP':>10s} {'FN':>10s} {'Total':>10s} {'Recall':>10s}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    all_types = sorted(set(list(a_tp_by_type.keys()) + list(a_fn_by_type.keys())))
    for t in all_types:
        tp = a_tp_by_type[t]
        fn = a_fn_by_type[t]
        tot = tp + fn
        rec = tp / tot * 100 if tot > 0 else 0
        print(f"  {t:<25s} {tp:>10,} {fn:>10,} {tot:>10,} {rec:>9.1f}%")

    if a_fp > 0:
        print(f"\n  False positives by detection type:")
        for t, c in sorted(a_fp_by_det.items(), key=lambda x: -x[1]):
            print(f"    {t:<25s} {c:>8,}")

    print(f"\n  ── ACTION DISTRIBUTION ──")
    for t, c in sorted(action_counts.items(), key=lambda x: -x[1]):
        print(f"  {t:<35s} {c:>12,}  ({c/total*100:.2f}%)")

    # --- Save JSON summary ---
    summary = {
        "file": results_path,
        "total_records": total,
        "event_level": {
            "total_events": e_tp + e_fn,
            "detected": e_tp,
            "missed": e_fn,
            "recall": round(e_rec, 4),
            "per_type": {t: {"detected": type_events[t]["detected"], "total": type_events[t]["total"],
                             "recall": round(type_events[t]["detected"] / type_events[t]["total"], 4) if type_events[t]["total"] > 0 else 0}
                         for t in sorted(type_events.keys())},
        },
        "announcement_level": {
            "true_positives": a_tp,
            "false_positives": a_fp,
            "false_negatives": a_fn,
            "true_negatives": a_tn,
            "precision": round(a_prec, 4),
            "recall": round(a_rec, 4),
            "f1_score": round(a_f1, 4),
        },
    }

    out_dir = os.path.dirname(results_path)
    out_path = os.path.join(out_dir, "accuracy_report.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n  Saved: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 evaluation/score_detection.py <results_dir_or_detection_results.json>")
        sys.exit(1)

    path = sys.argv[1]
    if os.path.isdir(path):
        path = os.path.join(path, "detection_results.json")

    if not os.path.exists(path):
        print(f"Error: {path} not found")
        sys.exit(1)

    score(path)

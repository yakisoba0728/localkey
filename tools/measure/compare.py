"""Compare two (redacted) runs probe by probe; write Markdown and JSON.

Verdicts:
- identical: every non-timing feature is equal and every timing value is within its
  tolerance;
- differs: the list of features that are not (status words, CTAP/CTAPHID status, TLV tag
  sets, lengths, redacted data, reply sequences, timings beyond tolerance);
- missing: the probe is only in one run.

Features. CCID: per exchange the APDU, SW, length, TLV tag paths and the redacted data
(`xx` bytes compare as written; the time per exchange is not compared). FIDO: the probe
summary, where keys ending in `_ms` are timings and `count`, `polls`, `keepalives`,
`keepalives_after_cancel` are counts, plus the sequence of device messages with
consecutive KEEPALIVEs collapsed into one entry with a count.

Tolerances (explicit, so "identical except jitter" is computed):
- interval_mean_ms ±15 ms; interval_stdev_ms ±20 ms; interval_min/max_ms ±50 ms;
- any other *_ms: ±max(50 ms, 10 % of the larger value);
- counts: ±max(2, 15 % of the larger value).
"""

from __future__ import annotations

import argparse
import json

COUNT_KEYS = {"count", "polls", "keepalives", "keepalives_after_cancel"}


def tolerance(key: str, a: float, b: float) -> float:
    if key == "interval_mean_ms":
        return 15.0
    if key == "interval_stdev_ms":
        return 20.0
    if key in ("interval_min_ms", "interval_max_ms"):
        return 50.0
    if key.endswith("_ms"):
        return max(50.0, 0.10 * max(abs(a), abs(b)))
    if key in COUNT_KEYS:
        return max(2.0, 0.15 * max(abs(a), abs(b)))
    return 0.0


def is_tolerant(key: str) -> bool:
    return key.endswith("_ms") or key in COUNT_KEYS


def diff_values(a, b, path: str, out: list, timing: list):
    """Collect differences between two JSON values; tolerant keys go through tolerance()."""
    key = path.rsplit(".", 1)[-1].split("[", 1)[0]
    if is_tolerant(key) and isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
        tol = tolerance(key, a, b)
        delta = abs(a - b)
        entry = {"path": path, "a": a, "b": b, "tolerance": round(tol, 2)}
        if delta > tol:
            out.append(entry)
        else:
            timing.append(entry)
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append({"path": f"{path}.{k}", "a": a.get(k, "<absent>"), "b": b.get(k, "<absent>")})
            else:
                diff_values(a[k], b[k], f"{path}.{k}", out, timing)
        return
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append({"path": f"{path}.length", "a": len(a), "b": len(b)})
        for i, (x, y) in enumerate(zip(a, b)):
            diff_values(x, y, f"{path}[{i}]", out, timing)
        return
    if a != b:
        out.append({"path": path, "a": a, "b": b})


def ccid_features(result: dict) -> list[dict]:
    return [
        {k: e[k] for k in ("apdu", "sw", "len", "tags", "data", "chain_total_len") if k in e}
        for e in result.get("exchanges", [])
    ]


def fido_sequence(result: dict) -> list[dict]:
    seq = []
    for record in result.get("packets", []):
        if record["dir"] != "in" or "message" not in record:
            continue
        message = dict(record["message"])
        item = {"cid": record["cid"], "cmd": record.get("cmd"), **message}
        if record.get("cmd") == "KEEPALIVE":
            if seq and seq[-1].get("cmd") == "KEEPALIVE" and seq[-1]["cid"] == item["cid"] and seq[-1].get("status") == item.get("status"):
                seq[-1]["count"] += 1
                continue
            item["count"] = 1
        seq.append(item)
    return seq


def compare_probe(a: dict, b: dict) -> dict:
    out: list = []
    timing: list = []
    if a.get("error") or b.get("error"):
        if a.get("error") != b.get("error"):
            out.append({"path": "error", "a": a.get("error"), "b": b.get("error")})
    diff_values(a.get("summary"), b.get("summary"), "summary", out, timing)
    if a.get("kind") == "ccid":
        diff_values(ccid_features(a), ccid_features(b), "exchanges", out, timing)
    elif a.get("kind") == "fido":
        diff_values(fido_sequence(a), fido_sequence(b), "replies", out, timing)
    return {"verdict": "identical" if not out else "differs", "differences": out, "within_tolerance": timing}


def compare_runs(run_a: dict, run_b: dict) -> dict:
    index_b = {(p["set"], p["id"]): p for p in run_b["probes"]}
    seen = set()
    results = []
    for p in run_a["probes"]:
        key = (p["set"], p["id"])
        seen.add(key)
        if key not in index_b:
            results.append({"set": p["set"], "id": p["id"], "desc": p.get("desc"), "verdict": "missing in B"})
            continue
        r = compare_probe(p, index_b[key])
        results.append({"set": p["set"], "id": p["id"], "desc": p.get("desc"), **r})
    for p in run_b["probes"]:
        if (p["set"], p["id"]) not in seen:
            results.append({"set": p["set"], "id": p["id"], "desc": p.get("desc"), "verdict": "missing in A"})
    counts: dict = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return {
        "a": {k: run_a["meta"].get(k) for k in ("label", "target", "started_utc", "sets", "setup")},
        "b": {k: run_b["meta"].get(k) for k in ("label", "target", "started_utc", "sets", "setup")},
        "counts": counts,
        "probes": results,
    }


def _short(value) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 80 else text[:77] + "..."


def to_markdown(report: dict) -> str:
    lines = [
        "# Measurement comparison",
        "",
        f"- A: `{report['a'].get('label')}` ({report['a'].get('target')}, {report['a'].get('started_utc')})",
        f"- B: `{report['b'].get('label')}` ({report['b'].get('target')}, {report['b'].get('started_utc')})",
        f"- Verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(report["counts"].items())),
        "",
        "| Set | Probe | Verdict | Differences |",
        "| --- | --- | --- | --- |",
    ]
    for r in report["probes"]:
        diffs = r.get("differences", [])
        text = "; ".join(f"`{d['path']}`" for d in diffs[:4]) + (f" (+{len(diffs) - 4})" if len(diffs) > 4 else "")
        lines.append(f"| {r['set']} | {r['id']} | {r['verdict']} | {text} |")
    detailed = [r for r in report["probes"] if r.get("differences")]
    if detailed:
        lines += ["", "## Differences", ""]
        for r in detailed:
            lines.append(f"### {r['set']} / {r['id']}")
            lines.append("")
            lines.append(r.get("desc") or "")
            lines.append("")
            for d in r["differences"]:
                tol = f" (tolerance {d['tolerance']})" if "tolerance" in d else ""
                lines.append(f"- `{d['path']}`: A {_short(d['a'])} / B {_short(d['b'])}{tol}")
            lines.append("")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Compare two measurement runs (redacted or raw)")
    parser.add_argument("a")
    parser.add_argument("b")
    parser.add_argument("--md", required=True, help="Markdown output path")
    parser.add_argument("--json", required=True, help="JSON output path")
    args = parser.parse_args()
    runs = []
    for path in (args.a, args.b):
        with open(path) as f:
            run = json.load(f)
        if not run["meta"].get("redacted"):
            from normalize import redact_run

            run = redact_run(run)
        runs.append(run)
    report = compare_runs(*runs)
    with open(args.json, "w") as f:
        json.dump(report, f, indent=1)
    with open(args.md, "w") as f:
        f.write(to_markdown(report))
    print(", ".join(f"{k}: {v}" for k, v in sorted(report["counts"].items())))


if __name__ == "__main__":
    main()

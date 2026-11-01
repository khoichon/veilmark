"""Aggregate benchmark records into JSON, CSV and a self-contained HTML report."""

from __future__ import annotations

import csv
import html
import json
import statistics
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from veilmark import __version__
from veilmark.benchmarks.stats import fmt_rate, rate


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in records if "error" not in r]
    errors = [r for r in records if "error" in r]
    by: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in ok:
        if r.get("polarity") in ("positive", "negative"):
            by[(r["media"], r["attack"])].append(r)
    rows = []
    for (media, attack), rs in sorted(by.items(), key=lambda kv: (kv[0][0], _order(kv[1]))):
        pos = [r for r in rs if r["polarity"] == "positive"]
        neg = [r for r in rs if r["polarity"] == "negative"]
        rows.append(
            {
                "media": media,
                "attack": attack,
                "group": rs[0].get("group"),
                "expected": rs[0].get("expected"),
                "params": rs[0].get("params"),
                "payload_recovery": rate(sum(r["payload_match"] for r in pos), len(pos)),
                "id_recovery": rate(sum(r["id_match"] for r in pos), len(pos)),
                "authentic": rate(sum(bool(r["authentic"]) for r in pos), len(pos)),
                "detected": rate(sum(bool(r["detected"]) for r in pos), len(pos)),
                "false_negative": rate(sum(not r["detected"] for r in pos), len(pos)),
                "wrong_payload": rate(sum(bool(r.get("wrong_payload")) for r in pos), len(pos)),
                "false_positive_detect": rate(sum(bool(r["detected"]) for r in neg), len(neg)),
                "false_positive_payload": rate(
                    sum(r["status"] == "payload-recovered" for r in neg), len(neg)
                ),
                "median_sync_z_pos": _med([r.get("sync_z") for r in pos]),
                "max_sync_z_neg": max([r.get("sync_z") or 0 for r in neg], default=None),
                "median_detect_seconds": _med([r.get("detect_seconds") for r in pos]),
                "median_attacked_bytes": _med([r.get("attacked_bytes") for r in pos]),
            }
        )
    neg_all = [r for r in ok if r.get("polarity") == "negative"]
    pos_all = [r for r in ok if r.get("polarity") == "positive"]
    forg = [r for r in ok if r.get("polarity") == "forgery"]
    forg_rows = []
    for name in sorted({r["attack"] for r in forg}):
        rs = [r for r in forg if r["attack"] == name]
        forg_rows.append(
            {
                "check": name,
                "correctly_rejected": rate(sum(r["correctly_rejected"] for r in rs), len(rs)),
                "payload_recovered": rate(sum(r["payload_recovered"] for r in rs), len(rs)),
                "accepted_as_authentic": rate(sum(bool(r["authentic"]) for r in rs), len(rs)),
            }
        )
    quality: dict[str, dict[str, Any]] = {}
    for r in pos_all:
        key = f"{r['media']}:{r['sample']}:{r['seed']}"
        quality[key] = {
            "media": r["media"],
            "sample": r["sample"],
            "split": r["split"],
            "kind": r["kind"],
            "size": f"{r['width']}x{r['height']}",
            "chip_px": r.get("chip_px"),
            "psnr_db": r.get("psnr_db"),
            "ssim": r.get("ssim"),
            "payload_bytes": r.get("payload_bytes"),
        }
    return {
        "rows": rows,
        "overall": {
            "positives": len(pos_all),
            "negatives": len(neg_all),
            "negatives_detected": rate(sum(bool(r["detected"]) for r in neg_all), len(neg_all)),
            "negatives_payload": rate(sum(r["status"] == "payload-recovered" for r in neg_all), len(neg_all)),
            "positives_wrong_payload": rate(sum(bool(r.get("wrong_payload")) for r in pos_all), len(pos_all)),
            "max_negative_sync_z": max([r.get("sync_z") or 0 for r in neg_all], default=None),
            "errors": len(errors),
        },
        "forgery": forg_rows,
        "quality": sorted(quality.values(), key=lambda q: (q["media"], q["sample"])),
        "quality_summary": {
            m: {
                "psnr_db_median": _med([q["psnr_db"] for q in quality.values() if q["media"] == m]),
                "psnr_db_min": min(
                    [q["psnr_db"] for q in quality.values() if q["media"] == m and q["psnr_db"]], default=None
                ),
                "ssim_median": _med([q["ssim"] for q in quality.values() if q["media"] == m]),
            }
            for m in sorted({q["media"] for q in quality.values()})
        },
        "errors": errors[:50],
    }


def _order(rs: list[dict[str, Any]]) -> int:
    """Catalogue position of the attack, so tables follow the documented order."""
    from veilmark.benchmarks import attacks as atk

    names = [a.name for a in atk.IMAGE_ATTACKS] + [a.name for a in atk.VIDEO_ATTACKS]
    name = rs[0]["attack"]
    return names.index(name) if name in names else len(names)


def _med(vals: list[Any]) -> float | None:
    v = [x for x in vals if isinstance(x, int | float)]
    return round(statistics.median(v), 3) if v else None


def write_all(records: list[dict[str, Any]], meta: dict[str, Any], out: Path) -> dict[str, Any]:
    agg = aggregate(records)
    summary = {
        "veilmark_version": __version__,
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "meta": meta,
        **agg,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    with (out / "summary.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "media",
                "attack",
                "group",
                "expected",
                "n_pos",
                "payload_recovery",
                "pr_ci_low",
                "pr_ci_high",
                "id_recovery",
                "authentic",
                "false_negative",
                "wrong_payload",
                "n_neg",
                "false_positive_detect",
                "false_positive_payload",
                "median_sync_z_pos",
                "max_sync_z_neg",
                "median_detect_seconds",
                "median_attacked_bytes",
                "params",
            ]
        )
        for r in agg["rows"]:
            w.writerow(
                [
                    r["media"],
                    r["attack"],
                    r["group"],
                    r["expected"],
                    r["payload_recovery"]["n"],
                    round(r["payload_recovery"]["rate"], 4),
                    round(r["payload_recovery"]["ci95_low"], 4),
                    round(r["payload_recovery"]["ci95_high"], 4),
                    round(r["id_recovery"]["rate"], 4),
                    round(r["authentic"]["rate"], 4),
                    round(r["false_negative"]["rate"], 4),
                    round(r["wrong_payload"]["rate"], 4),
                    r["false_positive_detect"]["n"],
                    round(r["false_positive_detect"]["rate"], 4),
                    round(r["false_positive_payload"]["rate"], 4),
                    r["median_sync_z_pos"],
                    r["max_sync_z_neg"],
                    r["median_detect_seconds"],
                    r["median_attacked_bytes"],
                    json.dumps(r["params"]),
                ]
            )
    (out / "report.html").write_text(render_html(summary))
    (out / "report.md").write_text(render_markdown(summary))
    return summary


def render_markdown(s: dict[str, Any]) -> str:
    m = s["meta"]
    lines = [
        f"# Veilmark robustness benchmark ({m['split']} split, profile {m['profile']})",
        "",
        f"Generated {s['generated']} by veilmark {s['veilmark_version']}; {m['jobs']} jobs, "
        f"{m['seeds']} seed(s) per sample, strength {m['strength']}, {m['seconds']} s.",
        "",
        "Rates are shown as `rate [95% Wilson CI] (n)`. *Payload* = exact signed payload recovered; "
        "*ID* = 64-bit watermark id recovered; *Authentic* = valid signature from a trusted issuer; "
        "*FP* = detections on unwatermarked copies under the same transformation.",
        "",
    ]
    o = s["overall"]
    lines += [
        "## Overall",
        "",
        f"- Positive detections run: {o['positives']}; negative (unwatermarked) runs: {o['negatives']}",
        f"- False positives (any detection claim) on negatives: {fmt_rate(o['negatives_detected'])}",
        f"- False payload recoveries on negatives: {fmt_rate(o['negatives_payload'])}",
        f"- Wrong payload decoded on positives: {fmt_rate(o['positives_wrong_payload'])}",
        f"- Highest sync z on any negative: {o['max_negative_sync_z']}",
        f"- Errors: {o['errors']}",
        "",
    ]
    for media in sorted({r["media"] for r in s["rows"]}):
        lines += [
            f"## {media.capitalize()} attacks",
            "",
            "| Attack | Expected | Payload | ID | Authentic | FN | FP (neg) | med z | med s |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for r in [r for r in s["rows"] if r["media"] == media]:
            lines.append(
                f"| {r['attack']} | {r['expected']} | {fmt_rate(r['payload_recovery'])} | "
                f"{100 * r['id_recovery']['rate']:.0f}% | {100 * r['authentic']['rate']:.0f}% | "
                f"{100 * r['false_negative']['rate']:.0f}% | "
                f"{fmt_rate(r['false_positive_detect']) if r['false_positive_detect']['n'] else '–'} | "
                f"{r['median_sync_z_pos']} | {r['median_detect_seconds']} |"
            )
        lines.append("")
    if s["forgery"]:
        lines += [
            "## Forgery and integrity checks",
            "",
            "| Check | Correctly rejected | Accepted as authentic |",
            "|---|---|---|",
        ]
        for f in s["forgery"]:
            lines.append(
                f"| {f['check']} | {fmt_rate(f['correctly_rejected'])} | {fmt_rate(f['accepted_as_authentic'])} |"
            )
        lines.append("")
    lines += [
        "## Embedding quality",
        "",
        "| Media | Sample | Split | Kind | Size | Chip | PSNR dB | SSIM | Payload B |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for q in s["quality"]:
        lines.append(
            f"| {q['media']} | {q['sample']} | {q['split']} | {q['kind']} | {q['size']} | {q['chip_px']} | "
            f"{q['psnr_db']} | {q['ssim'] if q['ssim'] is not None else '–'} | {q['payload_bytes']} |"
        )
    return "\n".join(lines) + "\n"


def render_html(s: dict[str, Any]) -> str:
    md = render_markdown(s)
    body = []
    in_table = False
    for line in md.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-"):
                continue
            if not in_table:
                body.append("<table>")
                body.append("<tr>" + "".join(f"<th>{html.escape(c)}</th>" for c in cells) + "</tr>")
                in_table = True
            else:
                body.append("<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("- "):
            body.append(f"<li>{html.escape(line[2:])}</li>")
        elif line.strip():
            body.append(f"<p>{html.escape(line).replace('`', '')}</p>")
    if in_table:
        body.append("</table>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Veilmark benchmark</title>
<style>
:root {{ --bg:#fbfbfa; --fg:#1d1d1f; --muted:#666; --line:#ddd; --head:#f0efeb; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#18181a; --fg:#e8e8e8; --muted:#aaa; --line:#333; --head:#232326; }} }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,sans-serif; margin:0 auto; padding:16px; max-width:1200px; }}
table {{ border-collapse:collapse; width:100%; margin:8px 0 24px; display:block; overflow-x:auto; }}
th,td {{ border-bottom:1px solid var(--line); padding:4px 8px; text-align:left; white-space:nowrap; font-variant-numeric:tabular-nums; }}
th {{ background:var(--head); position:sticky; top:0; }}
p {{ color:var(--muted); }}
</style></head><body>{"".join(body)}</body></html>"""

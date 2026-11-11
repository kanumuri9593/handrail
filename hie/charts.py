"""Two report charts from eval rows, as plain SVG (standard library only).

    charts/by-model.svg    per model: followed silently / followed + told / refused + warned / refused silently
    charts/by-channel.svg  per hiding place: how often the planted instruction was followed
"""

from __future__ import annotations

import os
from collections import defaultdict
from html import escape

INK, MUTED, GRID, BG = "#1f2328", "#59636e", "#d1d9e0", "#ffffff"
RED, AMBER, GREEN, GREY = "#c93c37", "#d4a72c", "#2f9e5b", "#8c959f"
FONT = "font-family='-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif'"


def _svg(width: int, height: int, body: list[str], title: str) -> str:
    return (f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' "
            f"viewBox='0 0 {width} {height}' role='img' aria-label='{escape(title)}' {FONT}>"
            f"<rect width='100%' height='100%' fill='{BG}'/>" + "".join(body) + "</svg>")


def _stacked(rows: list[tuple[str, list[tuple[float, str, str]]]], title: str, legend: list[tuple[str, str]]) -> str:
    """rows: (label, [(fraction, color, segment label)]) drawn as 100% horizontal bars."""
    left, bar_w, bar_h, gap, top = 170, 440, 22, 14, 64
    width = left + bar_w + 40
    height = top + len(rows) * (bar_h + gap) + 40
    b = [f"<text x='16' y='26' font-size='15' font-weight='600' fill='{INK}'>{escape(title)}</text>"]
    x = 16
    for name, color in legend:
        b.append(f"<rect x='{x}' y='38' width='10' height='10' rx='2' fill='{color}'/>"
                 f"<text x='{x + 15}' y='47' font-size='11' fill='{MUTED}'>{escape(name)}</text>")
        x += 22 + 6.2 * len(name)
    for i, (label, segs) in enumerate(rows):
        y = top + i * (bar_h + gap)
        b.append(f"<text x='{left - 10}' y='{y + 15}' font-size='12' fill='{INK}' text-anchor='end'>{escape(label)}</text>")
        b.append(f"<rect x='{left}' y='{y}' width='{bar_w}' height='{bar_h}' fill='{GRID}' rx='3'/>")
        cx = left
        for frac, color, seg_label in segs:
            w = bar_w * frac
            if w <= 0:
                continue
            b.append(f"<rect x='{cx:.1f}' y='{y}' width='{w:.1f}' height='{bar_h}' fill='{color}'/>")
            if w >= 34:
                b.append(f"<text x='{cx + w / 2:.1f}' y='{y + 15}' font-size='11' fill='#fff' "
                         f"text-anchor='middle'>{escape(seg_label)}</text>")
            cx += w
    return _svg(width, height, b, title)


def by_model_svg(rows: list[dict]) -> str:
    groups = defaultdict(list)
    for r in rows:
        if r.get("payload") != "none" and "complied" in r:
            groups[r["model"]].append(r)
    data = []
    for model, xs in groups.items():
        n = len(xs)
        silent = sum(1 for x in xs if x["complied"] and not x["disclosed"])
        told = sum(1 for x in xs if x["complied"] and x["disclosed"])
        warned = sum(1 for x in xs if not x["complied"] and x["disclosed"])
        quiet = n - silent - told - warned
        data.append((model, [(silent / n, RED, f"{silent}/{n}"), (told / n, AMBER, f"{told}/{n}"),
                             (warned / n, GREEN, f"{warned}/{n}"), (quiet / n, GREY, f"{quiet}/{n}")]))
    return _stacked(data, "Did the agent follow an instruction planted in the repo?",
                    [("followed silently", RED), ("followed, told user", AMBER),
                     ("refused + warned user", GREEN), ("refused, no explanation", GREY)])


def by_channel_svg(rows: list[dict]) -> str:
    groups = defaultdict(list)
    for r in rows:
        if r.get("payload") != "none" and "complied" in r:
            groups[r["channel"]].append(r)
    data = []
    for ch, xs in sorted(groups.items(), key=lambda kv: -sum(x["complied"] for x in kv[1]) / len(kv[1])):
        n, k = len(xs), sum(1 for x in xs if x["complied"])
        data.append((ch, [(k / n, RED, f"{k}/{n}"), ((n - k) / n, GREEN, f"{n - k}/{n}")]))
    return _stacked(data, "Where the instruction was hidden (all models)", [("followed", RED), ("didn't follow", GREEN)])


def write_charts(rows: list[dict], out: str) -> list[str]:
    d = os.path.join(out, "charts")
    os.makedirs(d, exist_ok=True)
    paths = []
    for name, fn in (("by-model.svg", by_model_svg), ("by-channel.svg", by_channel_svg)):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(fn(rows))
        paths.append(p)
    return paths

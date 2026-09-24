"""Render docs/demo.gif from the real output of scripts/run_demo.py.

Dev-only (needs Pillow, which the package itself does not depend on):
    python3 -m pip install pillow && python3 scripts/make_demo_gif.py

Both demo modes run for real; their output is abridged (health-check lines and
the approval prompt are skipped, long lines truncated, the repo path removed) so
it fits one screen; the padding inside `[   ALLOW]` is collapsed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "demo.gif"
COLS, ROWS = 100, 22
FONT_SIZE, LINE_H, PAD = 15, 21, 18
BG, FG, DIM = (13, 17, 23), (201, 209, 217), (139, 148, 158)
GREEN, RED, BLUE, YELLOW = (63, 185, 80), (248, 81, 73), (88, 166, 255), (210, 153, 34)
FONT_CANDIDATES = [
    Path.home() / ".local/share/fonts/JetBrainsMono/JetBrainsMonoNLNerdFontMono-Regular.ttf",
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
]


def font() -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), FONT_SIZE)
    return ImageFont.load_default()


def run(*args: str) -> list[str]:
    subprocess.run([sys.executable, "scripts/run_demo.py", "--reset"], cwd=REPO,
                   capture_output=True, check=True)
    proc = subprocess.run([sys.executable, "scripts/run_demo.py", *args], cwd=REPO,
                          capture_output=True, text=True, stdin=subprocess.DEVNULL)
    lines, skipping = [], False
    for line in proc.stdout.replace(str(REPO) + "/", "").splitlines():
        if line.startswith("health ok"):
            continue
        if line.startswith("=== HUMAN APPROVAL"):
            skipping = True
        if skipping:
            skipping = not line.startswith("non-interactive")
            continue
        line = re.sub(r"\[\s+(ALLOW|BLOCK|REQUIRE_APPROVAL)\]", r"[\1]", line)
        lines.append(line if len(line) <= COLS else line[:COLS - 1] + "…")
    while lines and not lines[0].strip():
        lines.pop(0)
    return lines


def color(line: str):
    if "BLOCK]" in line or line.startswith(("exfiltrated", "receiver collected 1", "read ")):
        return RED
    if "ALLOW]" in line or line.startswith("DEMO PASSED") or "collected: 0" in line:
        return GREEN
    if line.startswith("---"):
        return YELLOW
    return FG


def frame(screen: list[tuple[str, tuple]], f) -> Image.Image:
    img = Image.new("RGB", (PAD * 2 + int(f.getlength("M") * COLS),
                            PAD * 2 + LINE_H * ROWS), BG)
    draw = ImageDraw.Draw(img)
    for i, (text, fill) in enumerate(screen[-ROWS:]):
        draw.text((PAD, PAD + i * LINE_H), text, font=f, fill=fill)
    return img


def scene(command: str, output: list[str], f, frames, durations) -> None:
    screen: list[tuple[str, tuple]] = []
    prompt = "$ "
    for i in range(0, len(command) + 1, 3):
        frames.append(frame(screen + [(prompt + command[:i] + "█", BLUE)], f))
        durations.append(40)
    screen.append((prompt + command, BLUE))
    for line in output:
        screen.append((line, color(line)))
        frames.append(frame(screen, f))
        durations.append(140 if line.strip() else 60)
    durations[-1] = 3200


def main() -> None:
    f = font()
    frames: list[Image.Image] = []
    durations: list[int] = []
    scene("python3 scripts/run_demo.py --no-firewall   # the injected agent, unprotected",
          run("--no-firewall"), f, frames, durations)
    scene("python3 scripts/run_demo.py                 # the same agent, through the gateway",
          run(), f, frames, durations)
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, optimize=True)
    print(f"wrote {OUT.relative_to(REPO)}: {len(frames)} frames, "
          f"{OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()

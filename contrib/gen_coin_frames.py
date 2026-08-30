#!/usr/bin/env python3
"""Generate rotation frames for a coin rendered as ASCII.

The coin turns about its vertical axis. At angle t the face is foreshortened by
cos(t) and the rim presents an edge whose apparent width follows sin(t), so the
disc narrows to a thin ridged bar at 90 degrees and opens back out at 180.

Ridges sit at fixed angular positions around the rim, so their spacing
compresses toward the silhouette limbs on its own -- that foreshortening, not
the edge band itself, is what reads as depth.

    gen_coin_frames.py face.txt --frames 48 --out frames.txt
"""
import argparse
import math
import sys

# Darkest last: the renderer picks by coverage, so index 0 is background.
RAMP = " .:-=+*#%@"
EDGE_LIGHT = "|"
EDGE_RIDGE = "#"


def read_face(path):
    with open(path) as handle:
        lines = [line.rstrip("\n") for line in handle]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        raise SystemExit("face art is empty")
    width = max(len(line) for line in lines)
    return [line.ljust(width) for line in lines]


def sample_face(face, u, v):
    """Sample the face at normalised (u, v), both in [0, 1]."""
    rows = len(face)
    cols = len(face[0])
    y = min(rows - 1, max(0, int(v * rows)))
    x = min(cols - 1, max(0, int(u * cols)))
    return face[y][x]


def render(face, angle, width, height, ridges, depth):
    """One frame at `angle` radians, drawn into width x height."""
    cos_t = math.cos(angle)
    sin_t = math.sin(angle)
    face_half = abs(cos_t) * (width - depth) / 2.0
    edge_w = abs(sin_t) * depth
    cx = width / 2.0
    cy = height / 2.0
    ry = height / 2.0

    grid = [[" "] * width for _ in range(height)]

    for row in range(height):
        # Vertical position on the disc, -1 at the top edge and +1 at the bottom.
        ny = (row + 0.5 - cy) / ry
        if abs(ny) > 1.0:
            continue
        # Half-width of the disc at this row, before foreshortening.
        span = math.sqrt(max(0.0, 1.0 - ny * ny))

        # The visible face, squeezed horizontally by cos(t).
        half = face_half * span
        if half >= 0.5:
            start = int(cx - half)
            end = int(cx + half)
            for col in range(start, end + 1):
                if not (0 <= col < width):
                    continue
                # Undo the foreshortening to find where this column lands on the
                # face, so the art itself compresses rather than being clipped.
                nx = (col + 0.5 - cx) / half
                if abs(nx) > 1.0:
                    continue
                u = (nx * span + 1.0) / 2.0
                v = (ny + 1.0) / 2.0
                ch = sample_face(face, u, v)
                grid[row][col] = ch if ch != " " else "."

        # The rim. Widest when the coin is edge-on, absent when face-on.
        if edge_w >= 1.0:
            # The rim trails the face on whichever side is turning away.
            side = 1.0 if cos_t >= 0 else -1.0
            inner = cx + side * half
            outer = inner + side * edge_w * span
            lo, hi = sorted((inner, outer))
            for col in range(int(lo), int(hi) + 1):
                if not (0 <= col < width) or grid[row][col] != " ":
                    continue
                # Angular position of this column around the rim, so ridges
                # bunch toward the limb exactly as they do on a real coin.
                frac = (col - lo) / max(1e-6, hi - lo)
                phi = angle + frac * math.pi
                lit = (math.sin(phi * ridges) + 1.0) / 2.0
                grid[row][col] = EDGE_RIDGE if lit > 0.5 else EDGE_LIGHT

    return ["".join(r).rstrip() for r in grid]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("face")
    ap.add_argument("--frames", type=int, default=48)
    ap.add_argument("--width", type=int, default=64)
    ap.add_argument("--height", type=int, default=24)
    ap.add_argument("--ridges", type=int, default=14, help="ridge count around the rim")
    ap.add_argument("--depth", type=int, default=6, help="edge thickness in columns")
    ap.add_argument("--out", default="-")
    args = ap.parse_args()

    face = read_face(args.face)
    out = sys.stdout if args.out == "-" else open(args.out, "w")
    for i in range(args.frames):
        angle = 2.0 * math.pi * i / args.frames
        for line in render(face, angle, args.width, args.height, args.ridges, args.depth):
            out.write(line + "\n")
        out.write("\n")
    if out is not sys.stdout:
        out.close()
        print("wrote %d frames to %s" % (args.frames, args.out))


if __name__ == "__main__":
    main()

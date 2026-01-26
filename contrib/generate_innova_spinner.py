#!/usr/bin/env python3
import math
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_INPUT = os.path.join(ROOT, "src/qt/res/icons/innova-256.png")
OUT_HEADER = os.path.join(ROOT, "src/innova_spinner_frames.h")
OUT_SH = os.path.join(ROOT, "contrib/innova_spinner_frames.sh")

FRAME_COUNT = 60
WIDTH = 48
HEIGHT = 24
MIN_SCALE = 0.15
SPIN_DELAY_MS = 97
GRADIENT = " .:-=+*#%@"

def parse_pgm(pgm_bytes):
    # Parse binary PGM (P5) or ASCII (P2) into (width, height, maxval, pixels).
    tokens = []
    i = 0
    length = len(pgm_bytes)
    while len(tokens) < 4 and i < length:
        while i < length and pgm_bytes[i] in b" \t\r\n":
            i += 1
        if i < length and pgm_bytes[i] == ord("#"):
            while i < length and pgm_bytes[i] not in b"\r\n":
                i += 1
            continue
        start = i
        while i < length and pgm_bytes[i] not in b" \t\r\n":
            i += 1
        if start < i:
            tokens.append(pgm_bytes[start:i].decode("ascii"))
    if len(tokens) < 4:
        raise ValueError("Invalid PGM header")
    magic, width, height, maxval = tokens[:4]
    width = int(width)
    height = int(height)
    maxval = int(maxval)
    data_start = i
    if magic == "P5":
        pixels = pgm_bytes[data_start:data_start + (width * height)]
        if len(pixels) < width * height:
            raise ValueError("PGM data truncated")
        return width, height, maxval, list(pixels)
    if magic == "P2":
        # ASCII pixels
        ascii_data = pgm_bytes[data_start:].decode("ascii").split()
        pixels = [int(v) for v in ascii_data[:width * height]]
        return width, height, maxval, pixels
    raise ValueError("Unsupported PGM format: %s" % magic)

def convert_frame(input_path, angle):
    cmd = [
        "convert",
        input_path,
        "-background", "black",
        "-alpha", "remove",
        "-alpha", "off",
        "-resize", "%dx%d!" % (WIDTH, HEIGHT),
        "-rotate", str(angle),
        "-gravity", "center",
        "-extent", "%dx%d" % (WIDTH, HEIGHT),
        "-colorspace", "gray",
        "-depth", "8",
        "pgm:-",
    ]
    pgm = subprocess.check_output(cmd)
    width, height, maxval, pixels = parse_pgm(pgm)
    if width != WIDTH or height != HEIGHT:
        raise ValueError("Unexpected size: %dx%d" % (width, height))
    lines = []
    scale = float(maxval) if maxval else 255.0
    for y in range(height):
        line_chars = []
        for x in range(width):
            val = pixels[y * width + x]
            idx = int((val / scale) * (len(GRADIENT) - 1))
            line_chars.append(GRADIENT[idx])
        lines.append("".join(line_chars))
    return lines

def normalize_ascii(lines):
    if not lines:
        return [""]
    max_width = max(len(line) for line in lines)
    return [line.ljust(max_width) for line in lines]

def scale_ascii(lines, new_w, new_h):
    src_h = len(lines)
    src_w = max(len(line) for line in lines) if lines else 1
    src = [line.ljust(src_w) for line in lines]
    out = []
    for y in range(new_h):
        src_y = int((y * src_h) / new_h)
        if src_y >= src_h:
            src_y = src_h - 1
        row = src[src_y]
        out_row = []
        for x in range(new_w):
            src_x = int((x * src_w) / new_w)
            if src_x >= src_w:
                src_x = src_w - 1
            out_row.append(row[src_x])
        out.append("".join(out_row))
    return out

def squash_ascii(lines, new_w, total_w):
    if new_w < 1:
        new_w = 1
    if new_w == total_w:
        return lines, 0, new_w
    out = []
    pad_left = (total_w - new_w) // 2
    pad_right = total_w - new_w - pad_left
    for line in lines:
        row = line.ljust(total_w)
        squashed = []
        for x in range(new_w):
            src_x = int((x * total_w) / new_w)
            if src_x >= total_w:
                src_x = total_w - 1
            squashed.append(row[src_x])
        out.append((" " * pad_left) + "".join(squashed) + (" " * pad_right))
    return out, pad_left, new_w

def apply_thickness(lines, pad_left, new_w, total_w, scale, backside):
    edge_chars = " .:-=+*#%@"
    if scale <= MIN_SCALE:
        idx = len(edge_chars) - 1
    else:
        idx = int((1.0 - scale) / (1.0 - MIN_SCALE) * (len(edge_chars) - 1))
    if idx < 1:
        idx = 1
    if idx >= len(edge_chars):
        idx = len(edge_chars) - 1
    edge = edge_chars[idx]
    edge_alt = edge_chars[idx - 1] if idx > 1 else edge
    if backside and idx > 1:
        edge = edge_chars[idx - 1]
        edge_alt = edge_chars[idx - 2] if idx > 2 else edge
    thickness = 2
    if scale < 0.65:
        thickness = 3
    if new_w < 30:
        thickness = 2
    if new_w < 20:
        thickness = 1
    out = []
    for row_idx, line in enumerate(lines):
        row = list(line.ljust(total_w))
        left = None
        right = None
        for i, ch in enumerate(row):
            if ch != " ":
                left = i if left is None else left
                right = i
        if left is None:
            out.append("".join(row))
            continue
        for t in range(0, thickness):
            lpos = left - t
            rpos = right + t
            tone = edge_alt if (row_idx + t) % 2 else edge
            if 0 <= lpos < total_w:
                row[lpos] = tone
            if 0 <= rpos < total_w:
                row[rpos] = tone
        for t in range(1, thickness):
            lpos = left + t
            rpos = right - t
            tone = edge_alt if (row_idx + t) % 2 else edge
            if 0 <= lpos < total_w:
                row[lpos] = tone
            if 0 <= rpos < total_w:
                row[rpos] = tone
        out.append("".join(row))
    return out

def spin_frames_from_ascii(lines):
    normalized = normalize_ascii([line.rstrip("\n") for line in lines])
    base = scale_ascii(normalized, WIDTH, HEIGHT)
    frames = []
    min_width = max(2, int(round(WIDTH * MIN_SCALE)))
    for i in range(FRAME_COUNT):
        theta = (2.0 * math.pi) * ((float(i) + 0.5) / float(FRAME_COUNT))
        scale = abs(math.cos(theta))
        scale = max(scale, MIN_SCALE)
        new_w = max(2, int(round(WIDTH * scale)))
        frame, pad_left, new_w = squash_ascii(base, new_w, WIDTH)
        backside = math.cos(theta) < 0
        if backside:
            frame = [line[::-1] for line in frame]
        frame = apply_thickness(frame, pad_left, new_w, WIDTH, scale, backside)
        frames.append(frame)
    return frames

def write_header(frames):
    with open(OUT_HEADER, "w", encoding="ascii") as f:
        f.write("// Auto-generated by contrib/generate_innova_spinner.py\n")
        f.write("#ifndef INNOVA_SPINNER_FRAMES_H\n")
        f.write("#define INNOVA_SPINNER_FRAMES_H\n\n")
        f.write("static const int INNOVA_SPINNER_FRAME_COUNT = %d;\n" % len(frames))
        f.write("static const int INNOVA_SPINNER_LINE_COUNT = %d;\n\n" % HEIGHT)
        f.write("static const char* INNOVA_SPINNER_FRAMES[INNOVA_SPINNER_FRAME_COUNT][INNOVA_SPINNER_LINE_COUNT] = {\n")
        for frame in frames:
            f.write("    {\n")
            for line in frame:
                escaped = line.replace("\\", "\\\\").replace("\"", "\\\"")
                f.write("        \"%s\",\n" % escaped)
            f.write("    },\n")
        f.write("};\n\n")
        f.write("#endif\n")

def write_shell(frames):
    with open(OUT_SH, "w", encoding="ascii") as f:
        f.write("#!/bin/sh\n")
        f.write("# Auto-generated by contrib/generate_innova_spinner.py\n")
        f.write("SPINNER_LINES=%d\n" % HEIGHT)
        f.write("SPINNER_FRAMES=%d\n\n" % len(frames))
        f.write("print_frame() {\n")
        f.write("    case \"$1\" in\n")
        for idx, frame in enumerate(frames):
            f.write("        %d)\n" % idx)
            for line in frame:
                safe_line = line.replace("\\", "\\\\").replace("\"", "\\\"")
                f.write("            printf \"\\r\\033[2K%s\\n\" \"%s\"\n" % ("%s", safe_line))
            f.write("            ;;\n")
        f.write("        *)\n")
        f.write("            ;;\n")
        f.write("    esac\n")
        f.write("}\n")

def main():
    input_path = DEFAULT_INPUT
    if len(sys.argv) > 1:
        input_path = os.path.abspath(sys.argv[1])
    if not os.path.exists(input_path):
        raise SystemExit("Missing input: %s" % input_path)
    if input_path.lower().endswith(".txt"):
        with open(input_path, "r", encoding="ascii", errors="replace") as f:
            raw_lines = [line.rstrip("\n") for line in f.readlines()]
        normalized = normalize_ascii(raw_lines)
        if normalized:
            max_width = max(len(line) for line in normalized)
            global WIDTH, HEIGHT
            WIDTH = max_width
            HEIGHT = len(normalized)
        frames = spin_frames_from_ascii(normalized)
    else:
        frames = []
        for i in range(FRAME_COUNT):
            angle = (360.0 / FRAME_COUNT) * i
            frames.append(convert_frame(input_path, angle))
    write_header(frames)
    write_shell(frames)
    os.chmod(OUT_SH, 0o755)

if __name__ == "__main__":
    main()

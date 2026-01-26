#!/usr/bin/env python3
import argparse
import math
import signal
import sys
import time
import shutil
import select
import termios
import tty

FRAME_COUNT = 60
WIDTH = 48
HEIGHT = 24
MIN_SCALE = 0.15
GRADIENT = " .:-=+*#%@"
DEFAULT_MS = 97


def read_ascii(path):
    with open(path, "r", encoding="ascii", errors="replace") as f:
        return [line.rstrip("\n") for line in f.readlines()]


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
    normalized = normalize_ascii(lines)
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


def hide_cursor(out):
    out.write("\033[?25l")
    out.flush()


def show_cursor(out):
    out.write("\033[?25h")
    out.flush()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ascii_file")
    parser.add_argument("--ms", type=int, default=DEFAULT_MS)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--stderr", action="store_true")
    parser.add_argument("--toggle-key", default="i")
    parser.add_argument("--output-lines", type=int, default=5)
    parser.add_argument("--min-output", type=int, default=5)
    parser.add_argument("--max-output", type=int, default=15)
    parser.add_argument("--scroll-region", action="store_true")
    parser.add_argument("--tty", default=None)
    args = parser.parse_args()

    raw_lines = read_ascii(args.ascii_file)
    normalized = normalize_ascii(raw_lines)
    out = sys.stderr if args.stderr else sys.stdout
    printed_lines = 0
    last_size = None
    frames = []
    height = 0
    output_lines = args.output_lines

    def update_frames():
        nonlocal frames, height, printed_lines, last_size, output_lines
        max_width = max(len(line) for line in normalized) if normalized else 1
        max_height = len(normalized) if normalized else 1
        cols, rows = shutil.get_terminal_size((max_width, max_height))
        if rows > 1:
            rows -= 1
        scale = 1.0
        if max_width > 0 and max_height > 0:
            available_rows = rows
            if args.scroll_region:
                min_spinner = 6
                max_output = max(args.min_output, min(args.max_output, rows - min_spinner))
                if output_lines > max_output:
                    output_lines = max_output
                if output_lines < args.min_output:
                    output_lines = args.min_output
                available_rows = max(min_spinner, rows - output_lines)
            if max_width > cols or max_height > available_rows:
                scale_w = float(cols) / float(max_width) if cols > 0 else 1.0
                scale_h = float(available_rows) / float(max_height) if available_rows > 0 else 1.0
                scale = scale_w if scale_w < scale_h else scale_h
                if scale > 1.0:
                    scale = 1.0
        global WIDTH, HEIGHT
        WIDTH = max(2, int(max_width * scale + 0.5))
        HEIGHT = max(2, int(max_height * scale + 0.5))
        frames = spin_frames_from_ascii(normalized)
        height = len(frames[0]) if frames else 0
        last_size = (cols, rows)
        if args.scroll_region and rows > 0:
            max_output = max(args.min_output, min(args.max_output, rows - height))
            if output_lines > max_output:
                output_lines = max_output
            if output_lines < args.min_output:
                output_lines = args.min_output
            top = height + 1
            bottom = height + output_lines
            out.write("\0337")
            out.write("\033[%d;%dr" % (top, bottom))
            out.write("\033[%d;1H" % bottom)
            out.write("\0338")
            out.flush()
        if printed_lines > 0 and height != printed_lines:
            for _ in range(printed_lines):
                out.write("\r\033[2K\n")
            out.write("\033[%dA" % printed_lines)
            out.flush()
            printed_lines = 0

    update_frames()
    if not frames:
        return 0

    stop = False

    def handle_sigint(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    toggle_enabled = False
    toggle_key = args.toggle_key[0] if args.toggle_key else "i"
    old_tty = None
    toggle_fd = None
    if args.tty:
        try:
            toggle_fd = open(args.tty, "rb", buffering=0)
            toggle_enabled = True
        except OSError:
            toggle_fd = None
            toggle_enabled = False
    elif sys.stdin.isatty():
        toggle_fd = sys.stdin
        toggle_enabled = True
    if toggle_enabled and toggle_fd is not None:
        fd = toggle_fd.fileno()
        old_tty = termios.tcgetattr(fd)
        tty.setcbreak(fd)

    hide_cursor(out)
    try:
        idx = 0
        paused = False
        while True:
            if toggle_enabled and toggle_fd is not None:
                ready, _, _ = select.select([toggle_fd], [], [], 0)
                if ready:
                    ch = toggle_fd.read(1)
                    key = ch.decode(errors="ignore")
                    if key == toggle_key:
                        paused = not paused
                        if paused and printed_lines > 0:
                            out.write("\0337")
                            out.write("\033[H")
                            out.write(("\r\033[2K\n" * printed_lines))
                            if args.scroll_region:
                                out.write("\033[r")
                            out.write("\0338")
                            out.flush()
                            printed_lines = 0
                        if not paused and args.scroll_region:
                            update_frames()
                    elif key in ["+", "="]:
                        output_lines = min(args.max_output, output_lines + 1)
                        update_frames()
                    elif key in ["-", "_"]:
                        output_lines = max(args.min_output, output_lines - 1)
                        update_frames()
            cols, rows = shutil.get_terminal_size(last_size)
            if last_size is None or (cols, rows) != last_size:
                update_frames()
                if paused:
                    time.sleep(0.05)
                    continue
            frame = frames[idx]
            if not paused:
                out.write("\0337")
                out.write("\033[H")
                out.write("\r\033[2K" + ("\n\033[2K".join(frame)) + "\n")
                out.write("\0338")
                out.flush()
                printed_lines = height
            time.sleep(max(1, args.ms) / 1000.0)
            idx = (idx + 1) % len(frames)
            if args.once and idx == 0:
                break
            if stop:
                break
    finally:
        if args.scroll_region:
            out.write("\0337")
            out.write("\033[r")
            out.write("\0338")
            out.flush()
        if printed_lines > 0:
            out.write("\0337")
            out.write("\033[H")
            out.write(("\r\033[2K\n" * printed_lines))
            out.write("\0338")
            out.flush()
        if old_tty is not None and toggle_fd is not None:
            termios.tcsetattr(toggle_fd.fileno(), termios.TCSADRAIN, old_tty)
        if toggle_fd is not None and toggle_fd is not sys.stdin:
            toggle_fd.close()
        show_cursor(out)
        out.write("\n")
        out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

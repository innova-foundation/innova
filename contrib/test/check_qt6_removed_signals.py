#!/usr/bin/env python3
"""Reject connections to Qt5 signals that Qt6 removed.

String-based connects, Designer's connectSlotsByName convention and .ui
<connections> blocks all resolve by name at runtime, so a signal Qt6 deleted
still compiles and links. The connection then silently never fires. This scans
for the removed signatures instead.

Matching is by signature, not by receiver type: a project-defined signal that
happens to share one of these signatures would be reported. None exists today;
rename it, or add the site to ALLOWED_SITES, if one ever does.
"""

import os
import re
import sys

# Signal signatures present in Qt5 and absent in Qt6, with the replacement to use.
REMOVED = {
    "activated(QString)": "QComboBox::textActivated(QString)",
    "highlighted(QString)": "QComboBox::textHighlighted(QString)",
    "currentIndexChanged(QString)": "QComboBox::currentTextChanged(QString)",
    "valueChanged(QString)": "QSpinBox/QDoubleSpinBox::textChanged(QString)",
    "buttonClicked(int)": "QButtonGroup::idClicked(int)",
    "buttonPressed(int)": "QButtonGroup::idPressed(int)",
    "buttonReleased(int)": "QButtonGroup::idReleased(int)",
    "buttonToggled(int,bool)": "QButtonGroup::idToggled(int,bool)",
    "error(QAbstractSocket::SocketError)": "QAbstractSocket::errorOccurred()",
    "error(QProcess::ProcessError)": "QProcess::errorOccurred()",
}

# repo-relative path -> signatures accepted there, for a deliberate exception.
ALLOWED_SITES = {}

SCAN_DIRS = ("src/qt",)
SOURCE_EXT = (".cpp", ".h")

MACRO_RE = re.compile(r"\b(?:SIGNAL|SLOT)\s*\(([^()]*\([^()]*\))\s*\)")
AUTOCONNECT_RE = re.compile(r"\bon_[A-Za-z0-9_]+_([A-Za-z0-9_]+)\s*\(([^()]*)\)")
UI_SIGNAL_RE = re.compile(r"<signal>([^<]+)</signal>")


def normalise(signature):
    """Qt's own signature normalisation, reduced to what these patterns need."""
    name, _, args = signature.partition("(")
    args = args.rstrip(")")
    parts = []
    for arg in args.split(","):
        arg = re.sub(r"\bconst\b", " ", arg)
        arg = arg.replace("&", " ")
        arg = re.sub(r"\s+", " ", arg).strip()
        if not arg:
            continue
        tokens = arg.split(" ")
        # drop a trailing parameter name: "QString txType" -> "QString"
        if len(tokens) > 1 and re.fullmatch(r"[a-z_][A-Za-z0-9_]*", tokens[-1]):
            tokens = tokens[:-1]
        parts.append(" ".join(tokens).replace(" *", "*"))
    return "%s(%s)" % (name.strip(), ",".join(parts))


def scan_source(rel, full, findings):
    with open(full, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, 1):
            for pattern, group in ((MACRO_RE, 1), (AUTOCONNECT_RE, 0)):
                for match in pattern.finditer(line):
                    if group:
                        signature = normalise(match.group(1))
                    else:
                        signature = normalise("%s(%s)" % (match.group(1), match.group(2)))
                    if signature not in REMOVED:
                        continue
                    if signature in ALLOWED_SITES.get(rel, ()):
                        continue
                    findings.append((rel, lineno, match.group(0).strip(), REMOVED[signature]))


def scan_ui(rel, full, findings):
    with open(full, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, 1):
            for match in UI_SIGNAL_RE.finditer(line):
                signature = normalise(match.group(1))
                if signature not in REMOVED:
                    continue
                if signature in ALLOWED_SITES.get(rel, ()):
                    continue
                findings.append((rel, lineno, match.group(1), REMOVED[signature]))


def main(argv):
    root = os.path.abspath(argv[1] if len(argv) > 1 else os.getcwd())
    findings = []
    scanned = 0
    for scan_dir in SCAN_DIRS:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            sys.stderr.write("no %s under %s\n" % (scan_dir, root))
            return 2
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root)
                if name.endswith(SOURCE_EXT):
                    scan_source(rel, full, findings)
                elif name.endswith(".ui"):
                    scan_ui(rel, full, findings)
                else:
                    continue
                scanned += 1

    if findings:
        print("Qt6 removed-signal connections: %d" % len(findings))
        for rel, lineno, raw, replacement in findings:
            print("  %s:%d  %s  -> use %s" % (rel, lineno, raw, replacement))
        print("These resolve by name at runtime: they compile, link, and never fire under Qt6.")
        return 1

    print("scanned %d files under %s; no Qt6 removed-signal connections"
          % (scanned, ", ".join(SCAN_DIRS)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

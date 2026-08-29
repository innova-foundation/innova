#!/usr/bin/env python3
"""Fail when a core source compiled by the daemon makefiles is missing from
innova-qt.pro, or the reverse. Source-list drift between the two build systems
is what dropped the v5 privacy layer out of the GUI link."""

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Compiled by one build system only, for reasons that are not drift.
MAKEFILE_ONLY = {
    "noui",          # the GUI supplies its own UI callbacks
}
QT_ONLY = {
    "qtipcserver",   # GUI-only IPC endpoint
    "kernelrecord",  # backing record for the GUI minting view
}
# Subdirectory sources are not part of the shared core list.
SKIP_DIR_PREFIXES = ("qt/", "test/", "tor/", "json/", "minizip/", "leveldb/",
                     "obj/", "fuzz/", "compat/", "crypto/")


def fail(msg):
    sys.stderr.write("check_build_source_parity: ERROR: %s\n" % msg)
    sys.exit(1)


def makefile_core_objects(path):
    """Object stems from every OBJS assignment, minus subdirectory objects."""
    text = open(path).read()
    stems = set()
    for m in re.finditer(r"^OBJS\s*\+?=(.*?)(?=^\S|\Z)", text, re.M | re.S):
        for obj in re.findall(r"obj/([A-Za-z0-9_./-]+)\.o", m.group(1)):
            if "/" in obj:
                continue
            stems.add(obj)
    if not stems:
        fail("%s: no OBJS entries parsed" % path)
    return stems


def pro_core_sources(path):
    stems = set()
    for src in re.findall(r"src/([A-Za-z0-9_./-]+)\.cpp", open(path).read()):
        if src.startswith(SKIP_DIR_PREFIXES) or "/" in src:
            continue
        stems.add(src)
    if not stems:
        fail("%s: no SOURCES entries parsed" % path)
    return stems


def main():
    pro = pro_core_sources(os.path.join(ROOT, "innova-qt.pro"))
    problems = []
    for name in ("makefile.unix", "makefile.osx"):
        mk = makefile_core_objects(os.path.join(ROOT, "src", name))
        # Compare only stems that exist as C++ sources; assembly and platform
        # stubs are compiled from other suffixes.
        mk = set(s for s in mk
                 if os.path.exists(os.path.join(ROOT, "src", s + ".cpp")))
        for stem in sorted(mk - pro - MAKEFILE_ONLY):
            problems.append("src/%s.cpp is compiled by src/%s but is absent "
                            "from innova-qt.pro SOURCES" % (stem, name))
        for stem in sorted(pro - mk - QT_ONLY):
            problems.append("src/%s.cpp is in innova-qt.pro SOURCES but is not "
                            "compiled by src/%s" % (stem, name))
    if problems:
        for p in problems:
            sys.stderr.write("check_build_source_parity: %s\n" % p)
        fail("build source lists have drifted")
    print("check_build_source_parity: OK")


if __name__ == "__main__":
    main()

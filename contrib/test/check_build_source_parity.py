#!/usr/bin/env python3
"""Fail when a core source compiled by the daemon makefiles is missing from
innova-qt.pro, or the reverse. Source-list drift between the two build systems
is what dropped the v5 privacy layer out of the GUI link."""

import os
import re
import subprocess
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


def check_pro_entries_exist(pro_text, failures):
    """A .pro entry whose file was deleted stops the GUI build with "No rule to
    make target". Generated headers are exempt."""
    generated = {"src/build.h"}
    seen = set()
    for match in re.finditer(r"(src/[A-Za-z0-9_/]+\.(?:cpp|h|ui|qrc))", pro_text):
        name = match.group(1)
        if name in seen or name in generated:
            continue
        seen.add(name)
        if not os.path.exists(os.path.join(ROOT, name)):
            failures.append("innova-qt.pro lists %s, which does not exist" % name)


def check_tor_sources(problems):
    """The vendored tor is listed once, in src/tor/tor_sources.txt, and both
    build systems consume generated fragments. Verify the fragments are current
    and that both build systems actually include them, so the tor lists cannot
    drift the way the core lists once did."""
    gen = os.path.join(ROOT, "contrib", "gen_tor_sources.py")
    if not os.path.exists(gen):
        problems.append("contrib/gen_tor_sources.py is missing")
        return
    result = subprocess.run([sys.executable, gen, "--check"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        problems.append("tor source fragments are stale: %s"
                        % result.stdout.decode().strip().replace("\n", "; "))

    consumers = (("src/makefile.unix", "include tor/tor_sources.mk"),
                 ("innova-qt.pro", "include(src/tor/tor_sources.pri)"))
    for name, needle in consumers:
        with open(os.path.join(ROOT, name)) as handle:
            if needle not in handle.read():
                problems.append("%s no longer includes the generated tor source "
                                "list (%s)" % (name, needle))


def main():
    pro_path = os.path.join(ROOT, "innova-qt.pro")
    pro = pro_core_sources(pro_path)
    problems = []
    check_tor_sources(problems)
    with open(pro_path) as handle:
        check_pro_entries_exist(handle.read(), problems)
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

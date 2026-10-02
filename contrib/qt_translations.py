#!/usr/bin/env python3
"""Print the language codes that both Qt and the Innova wallet translate,
comma-separated, for choosing which Qt translations to ship.

usage: qt_translations.py <qt-translations-dir> <innova-src/qt/locale>
"""

import glob
import os
import re
import sys


def codes(directory, prefix, exts):
    found = set()
    for ext in exts:
        for path in glob.glob(os.path.join(directory, prefix + "*" + ext)):
            m = re.match(re.escape(prefix) + r"(.+)" + re.escape(ext) + "$", os.path.basename(path))
            if m:
                found.add(m.group(1))
    return found


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: %s <qt-translations-dir> <innova-src/qt/locale>" % sys.argv[0])
    qt = codes(sys.argv[1], "qt_", (".qm",))
    innova = codes(sys.argv[2], "bitcoin_", (".qm", ".ts"))
    print(",".join(sorted(qt & innova)))


if __name__ == "__main__":
    main()

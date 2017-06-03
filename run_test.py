#!/usr/bin/env python

from __future__ import print_function

import unittest
import os

LIBS = ["/usr/local/lib/pkcs11/libsofthsm2.so",  # macOS or local build
        "/usr/lib/softhsm/libsofthsm2.so",  # Debian libsofthsm2
        "/usr/lib/softhsm/libsofthsm.so",  # Debian libsofthsm
        "/usr/lib/libsofthsm.so"]  # Ubuntu 12.04 libsofthsm
for lib in LIBS:
    if os.path.isfile(lib):
        print("Using lib:", lib)
        os.environ['PYKCS11LIB'] = lib
        break

tl = unittest.TestLoader()
suite = tl.discover("tests")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.errors or result.failures:
    import sys
    sys.exit(1)

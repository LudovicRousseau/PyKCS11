#!/usr/bin/env python3

# use:
# ./run_test.py
# ./run_test.py test_ckbytelist.py

import unittest
import os
import sys

import get_PYKCS11LIB

pattern = "test*.py"
if len(sys.argv) > 1:
    pattern = sys.argv[1]

if __name__ == "__main__":
    lib = get_PYKCS11LIB.get_PYKCS11LIB()
    os.environ["PYKCS11LIB"] = lib

    tl = unittest.TestLoader()
    suite = tl.discover("test", pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.errors or result.failures:
        sys.exit(1)

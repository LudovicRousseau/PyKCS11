#!/usr/bin/env python

# use:
# ./run_test.py
# ./run_test.py test_ckbytelist.py

from __future__ import print_function

import unittest
import os
import sys

pattern = "test*.py"
if len(sys.argv) > 1:
    pattern = sys.argv[1]

def set_PYKCS11LIB():
    if "PYKCS11LIB" in os.environ:
        return

    if "PKCS11SPY" in os.environ:
        # use OpenSC PKCS#11 spy if PKCS11SPY is defined as the PKCS#11 lib
        # to use
        LIBS = [
            "/usr/local/lib/pkcs11-spy.so",  # macOS or local build
            "/usr/lib/x86_64-linux-gnu/pkcs11-spy.so",  # Debian amd64
        ]
    else:
        if sys.maxsize > 2 ** 32:
            # 64-bits
            WINDOWS_SOFTHSM = "c:/SoftHSM2/lib/softhsm2-x64.dll"
        else:
            # 32-bits
            WINDOWS_SOFTHSM = "c:/SoftHSM2/lib/softhsm2.dll"
        # use SoftHSM2 or SoftHSM1
        LIBS = [
            "/usr/local/lib/softhsm/libsofthsm2.so",  # macOS or local build
            "/usr/lib/softhsm/libsofthsm2.so",  # Debian libsofthsm2
            "/usr/lib/softhsm/libsofthsm.so",  # Debian libsofthsm
            "/usr/lib/libsofthsm.so",  # Ubuntu 12.04 libsofthsm
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",  # Ubuntu 16.04 libsofthsm2
            WINDOWS_SOFTHSM,  # Windows
        ]

    for lib in LIBS:
        if os.path.isfile(lib):
            print("Using lib:", lib)
            os.environ["PYKCS11LIB"] = lib
            break

if __name__ == "__main__":
    set_PYKCS11LIB()
    try:
        os.environ["PYKCS11LIB"]
    except KeyError:
        raise Exception("PYKCS11LIB is not defined. No SoftHSM library found?")

    tl = unittest.TestLoader()
    suite = tl.discover("test", pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.errors or result.failures:
        sys.exit(1)

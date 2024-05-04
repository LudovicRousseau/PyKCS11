#!/usr/bin/env python3


import os
import sys


def get_PYKCS11LIB():
    # already configured
    if "PYKCS11LIB" in os.environ:
        return os.environ["PYKCS11LIB"]

    if "PKCS11SPY" in os.environ:
        # use OpenSC PKCS#11 spy if PKCS11SPY is defined as the PKCS#11 lib
        # to use
        LIBS = [
            "/usr/local/lib/pkcs11-spy.so",  # macOS or local build
            "/usr/lib/x86_64-linux-gnu/pkcs11-spy.so",  # Debian amd64
            "/usr/lib64/pkcs11/pkcs11-spy.so",  # Fedora Linux
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
            "/opt/homebrew/lib/softhsm/libsofthsm2.so",  # macOS arm64
            "/usr/lib/softhsm/libsofthsm2.so",  # Debian libsofthsm2
            "/usr/lib/softhsm/libsofthsm.so",  # Debian libsofthsm
            "/usr/lib/libsofthsm.so",  # Ubuntu 12.04 libsofthsm
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",  # Ubuntu 16.04 libsofthsm2
            "/usr/lib64/pkcs11/libsofthsm2.so",  # Fedora Linux
            WINDOWS_SOFTHSM,  # Windows
        ]

    for lib in LIBS:
        if os.path.isfile(lib):
            return lib

    raise Exception("PYKCS11LIB is not defined. No SoftHSM library found?")


if __name__ == "__main__":
    lib = get_PYKCS11LIB()
    print("PYKCS11LIB={}".format(lib))

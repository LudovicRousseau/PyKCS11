#!/usr/bin/env python3

"""
Run unit tests

use:
./run_pytest.py
./run_pytest.py -k ckbytelist
./run_pytest.py --parallel-threads=5 --iterations=5
"""

import os
import sys

import pytest

import get_PYKCS11LIB

if __name__ == "__main__":
    lib = get_PYKCS11LIB.get_PYKCS11LIB()
    os.environ["PYKCS11LIB"] = lib

    # use arguments from the command line
    args = sys.argv[1:]
    # add verbosity
    args.append("--verbose")

    sys.exit(pytest.main(args))

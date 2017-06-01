#!/usr/bin/env python

import unittest
import os

os.environ['PYKCS11LIB'] = "/usr/local/lib/pkcs11/libsofthsm2.so"

tl = unittest.TestLoader()
suite = tl.discover("tests")
unittest.TextTestRunner(verbosity=2).run(suite)

#!/usr/bin/env python

import unittest

tl = unittest.TestLoader()
suite = tl.discover("tests")
unittest.TextTestRunner(verbosity=2).run(suite)

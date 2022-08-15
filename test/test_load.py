# -*- coding: utf-8 -*-

import unittest
from PyKCS11 import PyKCS11
import platform


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()

    def tearDown(self):
        del self.pkcs11

    def test_load(self):
        # Library not found
        lib = "nolib"
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.pkcs11.load(lib)
        the_exception = cm.exception
        self.assertEqual(the_exception.value, -1)
        self.assertEqual(the_exception.text, lib)
        self.assertEqual(str(the_exception), "Load (%s)" % lib)

        # C_GetFunctionList() not found
        if platform.system() == 'Linux':
            # GNU/Linux
            lib = "libc.so.6"
        elif platform.system() == 'Darwin':
            # macOS
            lib = "/usr/lib/libSystem.B.dylib"
        else:
            # Windows
            lib = "WinSCard.dll"

        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.pkcs11.load(lib)
        the_exception = cm.exception
        self.assertEqual(the_exception.value, -4)
        self.assertEqual(the_exception.text, lib)
        self.assertEqual(str(the_exception),
            "C_GetFunctionList() not found (%s)" % lib)

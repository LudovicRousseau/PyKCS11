# -*- coding: utf-8 -*-

import unittest
from PyKCS11 import PyKCS11
import platform
import shutil
import gc
import os

from pathlib import Path
from tempfile import TemporaryDirectory

class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.tmpdir = TemporaryDirectory()
        self.lib1_name = os.environ["PYKCS11LIB"]
        # create a tmp copy of the main lib
        # to use as a different library in tests
        self.lib2_name = str(Path(self.tmpdir.name) /
                             Path(self.lib1_name).name)
        shutil.copy(self.lib1_name, self.tmpdir.name)

    def tearDown(self):
        del self.pkcs11
        if platform.system() != 'Windows':
            self.tmpdir.cleanup()
        del self.tmpdir
        del self.lib1_name
        del self.lib2_name

    def openSession(self, lib):
        slot = lib.getSlotList(tokenPresent=True)[0]
        return lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)

    def test_load(self):
        # create two instances with default library
        lib1 = PyKCS11.PyKCS11Lib().load()
        lib2 = PyKCS11.PyKCS11Lib().load()

        # expect two instances with the same library loaded
        self.assertTrue(hasattr(lib1, "pkcs11dll_filename"))
        self.assertTrue(hasattr(lib2, "pkcs11dll_filename"))
        self.assertEqual(len(lib1._loaded_libs), 1)
        self.assertEqual(len(lib2._loaded_libs), 1)

        self.openSession(lib1)

        # unload the first library
        del lib1
        gc.collect()

        # one instance remaining, the library is still in use
        self.openSession(lib2)
        self.assertEqual(len(lib2._loaded_libs), 1)

    def test_multiple_load(self):
        # load two different libraries
        lib1 = PyKCS11.PyKCS11Lib().load(self.lib1_name)
        lib2 = PyKCS11.PyKCS11Lib().load(self.lib2_name)

        # _loaded_libs is shared across all instances
        # check the value in self.pkcs11
        self.assertEqual(len(self.pkcs11._loaded_libs), 2)
        lib1 = PyKCS11.PyKCS11Lib() # unload lib1
        self.assertEqual(len(self.pkcs11._loaded_libs), 1)
        lib2 = PyKCS11.PyKCS11Lib() # unload lib2
        self.assertEqual(len(self.pkcs11._loaded_libs), 0)

    def test_invalid_load(self):
        # Library not found
        lib = "nolib"
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.pkcs11.load(lib)
        the_exception = cm.exception
        self.assertEqual(the_exception.value, -1)
        self.assertEqual(the_exception.text, lib)
        self.assertEqual(str(the_exception), "Load (%s)" % lib)
        self.assertEqual(len(self.pkcs11._loaded_libs), 0)

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
        self.assertEqual(len(self.pkcs11._loaded_libs), 0)

        # try to load the improper lib another time
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.pkcs11.load(lib)
        the_exception = cm.exception
        self.assertEqual(the_exception.value, -4)
        self.assertEqual(the_exception.text, lib)
        self.assertEqual(str(the_exception),
            "C_GetFunctionList() not found (%s)" % lib)
        self.assertEqual(len(self.pkcs11._loaded_libs), 0)

        # finally, load a valid library
        self.pkcs11.load()
        self.assertEqual(len(self.pkcs11._loaded_libs), 1)

    def test_specific_load(self):
        # load two different libraries sequentially
        self.pkcs11.load(self.lib1_name)
        self.pkcs11.load(self.lib2_name)

        # the second load should've unloaded the first library
        self.assertEqual(len(self.pkcs11._loaded_libs), 1)
        self.assertEqual(self.pkcs11.pkcs11dll_filename, self.lib2_name)

        # reload the first library
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(self.lib1_name)

        # try to open a session
        self.assertIsNotNone(self.openSession(self.pkcs11))

    def test_unload(self):
        self.pkcs11.load().unload()
        # no pkcs11dll_filename should remain after unload
        self.assertFalse(hasattr(self.pkcs11, "pkcs11dll_filename"))

        self.pkcs11.load()
        self.openSession(self.pkcs11)
        # one library has been loaded
        self.assertEqual(len(self.pkcs11._loaded_libs), 1)
        self.assertTrue(hasattr(self.pkcs11, "pkcs11dll_filename"))

        self.pkcs11.unload()
        gc.collect()
        # manually unloaded the library using gc.collect()
        self.assertEqual(len(self.pkcs11._loaded_libs), 0)
        self.assertFalse(hasattr(self.pkcs11, "pkcs11dll_filename"))

import unittest
import PyKCS11


class Testutil(unittest.TestCase):
    def test_empty(self):
        e = PyKCS11.PyKCS11Error(0)
        self.assertEqual(e.value, 0)

    def test_CKR_OK(self):
        e = PyKCS11.PyKCS11Error(PyKCS11.CKR_OK)
        self.assertEqual(e.value, 0)
        self.assertEqual(str(e), "CKR_OK (0x00000000)")

    def test_CKR_PIN_INVALID(self):
        e = PyKCS11.PyKCS11Error(PyKCS11.CKR_PIN_INVALID)
        self.assertEqual(e.value, 0xA1)
        self.assertEqual(str(e), "CKR_PIN_INVALID (0x000000A1)")

    def test_Load(self):
        e = PyKCS11.PyKCS11Error(-1, "Pouet")
        self.assertEqual(e.value, -1)
        self.assertEqual(str(e), "Load (Pouet)")

    def test_raise(self):
        with self.assertRaises(PyKCS11.PyKCS11Error):
            raise PyKCS11.PyKCS11Error(0)

    def test_unknown(self):
        e = PyKCS11.PyKCS11Error(PyKCS11.CKR_VENDOR_DEFINED - 1)
        self.assertEqual(str(e), "Unknown error (0x7FFFFFFF)")

    def test_vendor0(self):
        e = PyKCS11.PyKCS11Error(PyKCS11.CKR_VENDOR_DEFINED, "Pouet")
        self.assertEqual(e.value, PyKCS11.CKR_VENDOR_DEFINED)
        self.assertEqual(str(e), "Vendor error (0x00000000)")

    def test_vendor10(self):
        e = PyKCS11.PyKCS11Error(PyKCS11.CKR_VENDOR_DEFINED + 10)
        self.assertEqual(e.value, PyKCS11.CKR_VENDOR_DEFINED + 10)
        self.assertEqual(str(e), "Vendor error (0x0000000A)")

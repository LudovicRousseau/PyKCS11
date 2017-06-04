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
        self.assertEqual(e.value, 0xa1)
        self.assertEqual(str(e), "CKR_PIN_INVALID (0x000000A1)")

    def test_Load(self):
        e = PyKCS11.PyKCS11Error(-1, "Pouet")
        self.assertEqual(e.value, -1)
        self.assertEqual(str(e), "Load (Pouet)")

    def test_raise(self):
        with self.assertRaises(PyKCS11.PyKCS11Error):
            raise PyKCS11.PyKCS11Error(0)

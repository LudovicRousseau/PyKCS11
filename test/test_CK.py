#! /usr/bin/env python

# execute using:
# python test/test_CK.py

import unittest
import PyKCS11


class TestUtil(unittest.TestCase):
    def test_CKM(self):
        self.assertEqual(PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN, 0x00000000)
        self.assertEqual(
            PyKCS11.CKM[PyKCS11.CKM_RSA_PKCS_KEY_PAIR_GEN], "CKM_RSA_PKCS_KEY_PAIR_GEN"
        )

        self.assertEqual(PyKCS11.CKM_VENDOR_DEFINED, 0x80000000)

    def test_CKR(self):
        self.assertEqual(PyKCS11.CKR_VENDOR_DEFINED, 0x80000000)

    def test_CKH(self):
        self.assertEqual(PyKCS11.CKH_USER_INTERFACE, 3)
        self.assertEqual(PyKCS11.CKH['CKH_USER_INTERFACE'], 3)


if __name__ == "__main__":
    unittest.main()

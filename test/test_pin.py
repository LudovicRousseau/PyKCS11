import unittest
from PyKCS11 import PyKCS11

# use OpenSC PKCS#11 Spy to check what PIN value is sent to the PKCS#11
# library


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )

    def tearDown(self):
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_login(self):
        self.session.login("1234")
        self.session.logout()

    def test_wrong(self):
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.session.login("wrong PIN")

        the_exception = cm.exception
        self.assertEqual(the_exception.value, PyKCS11.CKR_PIN_INCORRECT)
        self.assertEqual(str(the_exception), "CKR_PIN_INCORRECT (0x000000A0)")

    def test_ckbytelist(self):
        pin = PyKCS11.ckbytelist("1234")
        self.session.login(pin)
        self.session.logout()

    def test_binary(self):
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            pin = PyKCS11.ckbytelist([1, 2, 3, 4])
            self.session.login(pin)

        the_exception = cm.exception
        self.assertEqual(the_exception.value, PyKCS11.CKR_PIN_INCORRECT)
        self.assertEqual(str(the_exception), "CKR_PIN_INCORRECT (0x000000A0)")

    def test_null(self):
        # SoftHSM2 does not support pinpad (pin = NULL)
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.session.login(None)

        the_exception = cm.exception
        self.assertEqual(the_exception.value, PyKCS11.CKR_ARGUMENTS_BAD)
        self.assertEqual(str(the_exception), "CKR_ARGUMENTS_BAD (0x00000007)")

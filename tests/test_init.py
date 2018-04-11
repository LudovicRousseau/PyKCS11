import unittest
from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):

    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(self.slot,
                                               PyKCS11.CKF_SERIAL_SESSION |
                                               PyKCS11.CKF_RW_SESSION)

    def tearDown(self):
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_initPin(self):
        # use admin pin
        self.session.login("123456", user_type=PyKCS11.CKU_SO)
        # change PIN
        self.session.initPin("4321")
        self.session.logout()

        # check new PIN
        self.session.login("4321")
        self.session.logout()

        # reset to old PIN
        self.session.login("123456", user_type=PyKCS11.CKU_SO)
        self.session.initPin("1234")
        self.session.logout()

        # check old PIN
        self.session.login("1234")
        self.session.logout()

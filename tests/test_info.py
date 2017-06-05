import unittest
from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):

    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]

    def test_getInfo(self):
        info = self.pkcs11.getInfo()
        text = str(info)
        self.assertIsNotNone(text)

    def test_getSlotInfo(self):
        info = self.pkcs11.getSlotInfo(self.slot)
        text = str(info)
        self.assertIsNotNone(text)

    def test_getTokenInfo(self):
        info = self.pkcs11.getTokenInfo(self.slot)
        text = str(info)
        self.assertIsNotNone(text)

    def test_getSessionInfo(self):
        self.session = self.pkcs11.openSession(self.slot,
                                               PyKCS11.CKF_SERIAL_SESSION)
        info = self.session.getSessionInfo()
        text = str(info)
        self.assertIsNotNone(text)
        self.session.closeSession()

    def test_getMechanismList(self):
        mechanisms = self.pkcs11.getMechanismList(self.slot)
        text = str(mechanisms)
        self.assertIsNotNone(text)

        # info for the first mechanism
        info = self.pkcs11.getMechanismInfo(self.slot, mechanisms[0])
        text = str(info)
        self.assertIsNotNone(text)

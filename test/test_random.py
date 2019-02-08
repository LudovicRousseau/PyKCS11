import unittest
from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(self.slot, PyKCS11.CKF_SERIAL_SESSION)

    def tearDown(self):
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_seedRandom(self):
        seed = [1, 2, 3, 4]
        self.session.seedRandom(seed)

    def test_generateRandom(self):
        rnd = self.session.generateRandom()
        self.assertEqual(len(rnd), 16)

        rnd = self.session.generateRandom(32)
        self.assertEqual(len(rnd), 32)

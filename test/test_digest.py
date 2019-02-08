#! /usr/bin/env python

import unittest
from PyKCS11 import PyKCS11

# SHA1 of "abc"
SHA1_abc = [
    0xA9,
    0x99,
    0x3E,
    0x36,
    0x47,
    0x6,
    0x81,
    0x6A,
    0xBA,
    0x3E,
    0x25,
    0x71,
    0x78,
    0x50,
    0xC2,
    0x6C,
    0x9C,
    0xD0,
    0xD8,
    0x9D,
]


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(self.slot, PyKCS11.CKF_SERIAL_SESSION)

    def tearDown(self):
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_digest(self):
        digest = self.session.digest("abc")
        self.assertSequenceEqual(digest, SHA1_abc)

    def test_digestSession(self):
        digestSession = self.session.digestSession()
        digestSession.update("abc")
        digest = digestSession.final()
        self.assertSequenceEqual(digest, SHA1_abc)


if __name__ == "__main__":
    unittest.main()

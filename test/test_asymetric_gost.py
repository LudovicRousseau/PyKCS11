import unittest
from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion[0]

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login("1234")

    def tearDown(self):
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_gost(self):
        if self.SoftHSMversion < 2:
            self.skipTest("generateKeyPair() only supported by SoftHSM >= 2")

        # values from SoftHSMv2
        param_a = (0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01)
        param_b = (0x06, 0x07, 0x2A, 0x85, 0x03, 0x02, 0x02, 0x1E, 0x01)

        keyID = (0x23,)
        pubTemplate = [
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, "My Public Key"),
            (PyKCS11.CKA_ID, keyID),
            (PyKCS11.CKA_GOSTR3410_PARAMS, param_a),
            (PyKCS11.CKA_GOSTR3411_PARAMS, param_b),
        ]

        privTemplate = [
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ID, keyID),
        ]

        # test generate gost key pair
        gen_mechanism = PyKCS11.Mechanism(PyKCS11.CKM_GOSTR3410_KEY_PAIR_GEN, None)
        try:
            (self.pubKey, self.privKey) = self.session.generateKeyPair(
                pubTemplate, privTemplate, gen_mechanism
            )
        except PyKCS11.PyKCS11Error as e:
            if e.value == PyKCS11.CKR_MECHANISM_INVALID:
                self.skipTest("GOST not supported by SoftHSMv2 on Windows?")
            else:
                raise

        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        # test sign GOSTR3410_WITH_GOSTR3411
        toSign = "Hello world"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_GOSTR3410_WITH_GOSTR3411, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)
        self.assertTrue(result)

        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)

        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

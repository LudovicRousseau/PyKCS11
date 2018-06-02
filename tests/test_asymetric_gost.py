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
        self.session.login("1234")

        # values from SoftHSMv2
        param_a = (0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01)
        param_b = (0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01)

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
            (PyKCS11.CKA_ID, keyID)
        ]

        gen_mechanism = PyKCS11.Mechanism(PyKCS11.CKM_GOSTR3410_KEY_PAIR_GEN,
                                          None)
        try:
            (self.pubKey, self.privKey) = self.session.generateKeyPair(pubTemplate,
                    privTemplate, gen_mechanism)

            self.assertIsNotNone(self.pubKey)
            self.assertIsNotNone(self.privKey)

            self.gost = True
        except PyKCS11.PyKCS11Error as e:
            self.gost = False
            # GOSTR3410 is not yet supported by SoftHSM1
            if not e.value == PyKCS11.CKR_MECHANISM_INVALID:
                raise

    def tearDown(self):
        if self.gost:
            self.session.destroyObject(self.pubKey)
            self.session.destroyObject(self.privKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_sign_GOSTR3410_WITH_GOSTR3411(self):
        toSign = "Hello world"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_GOSTR3410_WITH_GOSTR3411, None)

        # sign/verify
        if self.gost:
            signature = self.session.sign(self.privKey, toSign, mecha)

            result = self.session.verify(self.pubKey, toSign, signature,
                                         mecha)
            self.assertTrue(result)

    def test_pubKey(self):
        # test CK_OBJECT_HANDLE.__repr__()
        if self.gost:
            text = str(self.pubKey)
            self.assertIsNotNone(text)

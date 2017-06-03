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

    def tearDown(self):
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_sign(self):
        pubTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_MODULUS_BITS, 0x0400),
            (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, "My Public Key"),
            (PyKCS11.CKA_ID, (0x22,))
        ]

        privTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ID, (0x22,))
        ]

        (pubKey, privKey) = self.session.generateKeyPair(pubTemplate,
                                                         privTemplate)
        self.assertIsNotNone(pubKey)
        self.assertIsNotNone(privKey)

        keyID = (0x22,)
        toSign = "Hello world"

        # get the first private key with given KeyID
        privKey = self.session.findObjects([(PyKCS11.CKA_CLASS,
                PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, keyID)])[0]
        signature = self.session.sign(privKey, toSign,
                PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))

        # get the first public key with given KeyID
        pubKey = self.session.findObjects([(PyKCS11.CKA_CLASS,
                PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, keyID)])[0]
        result = self.session.verify(pubKey, toSign, signature,
                PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))

        self.assertTrue(result)

        dataIn = "Hello world"
        encrypted = self.session.encrypt(pubKey, dataIn)
        decrypted = self.session.decrypt(privKey, encrypted)

        # convert in a string
        text = "".join(map(chr, decrypted))

        self.assertEqual(dataIn, text)

        self.session.destroyObject(pubKey)
        self.session.destroyObject(privKey)

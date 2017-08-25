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

        keyID = (0x22,)
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
            (PyKCS11.CKA_ID, keyID)
        ]

        privTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ID, keyID)
        ]

        (self.pubKey, self.privKey) = self.session.generateKeyPair(pubTemplate, privTemplate)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

    def tearDown(self):
        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_sign_PKCS(self):
        toSign = "Hello world"

        # sign/verify
        signature = self.session.sign(self.privKey, toSign,
                PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))

        result = self.session.verify(self.pubKey, toSign, signature,
                PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))

        self.assertTrue(result)

    def test_sign_X509(self):
        toSign = "Hello world"

        # sign/verify
        try:
            signature = self.session.sign(self.privKey, toSign,
                    PyKCS11.Mechanism(PyKCS11.CKM_RSA_X_509, None))

            result = self.session.verify(self.pubKey, toSign, signature,
                    PyKCS11.Mechanism(PyKCS11.CKM_RSA_X_509, None))

            self.assertTrue(result)
        except PyKCS11.PyKCS11Error as e:
            # RSA X509 is not supported by SoftHSM1
            if not e.value == PyKCS11.CKR_MECHANISM_INVALID:
                raise

    def test_encrypt_PKCS(self):
        # encrypt/decrypt using CMK_RSA_PKCS (default)
        dataIn = "Hello world"
        encrypted = self.session.encrypt(self.pubKey, dataIn)
        decrypted = self.session.decrypt(self.privKey, encrypted)

        # convert in a string
        text = "".join(map(chr, decrypted))

        self.assertEqual(dataIn, text)

    def test_encrypt_X509(self):
        # encrypt/decrypt using CKM_RSA_X_509
        dataIn = "Hello world!"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_RSA_X_509, None)
        try:
            encrypted = self.session.encrypt(self.pubKey, dataIn, mecha=mecha)
            decrypted = self.session.decrypt(self.privKey, encrypted, mecha=mecha)

            # remove padding NUL bytes
            padding_length = 0
            for e in decrypted:
                if e != 0:
                    break
                padding_length += 1
            decrypted = list(decrypted)[padding_length:]

            # convert in a string
            text = "".join(map(chr, decrypted))

            self.assertEqual(dataIn, text)
        except PyKCS11.PyKCS11Error as e:
            # RSA X509 is not supported by SoftHSM1
            if not e.value == PyKCS11.CKR_MECHANISM_INVALID:
                raise

    def test_RSA_OAEP(self):
        # RSA OAEP
        plainText = "A test string"

        mech = PyKCS11.RSAOAEPMechanism(PyKCS11.CKM_SHA_1, PyKCS11.CKG_MGF1_SHA1)
        try:
            cipherText = self.session.encrypt(self.pubKey, plainText, mech)
            decrypted = self.session.decrypt(self.privKey, cipherText, mech)

            text = "".join(map(chr, decrypted))

            self.assertEqual(text, plainText)
        except PyKCS11.PyKCS11Error as e:
            # RSA OAEP is not supported by SoftHSM1
            if not e.value == PyKCS11.CKR_MECHANISM_INVALID:
                raise

    def test_RSA_PSS(self):
        # RSA PSS
        plainText = "A test string"

        mech = PyKCS11.RSA_PSS_Mechanism(PyKCS11.CKM_SHA384, PyKCS11.CKG_MGF1_SHA384, 48)
        try:
            cipherText = self.session.encrypt(self.pubKey, plainText, mech)
            decrypted = self.session.decrypt(self.privKey, cipherText, mech)
            text = "".join(map(chr, decrypted))

            self.assertEqual(text, plainText)
        except PyKCS11.PyKCS11Error as e:
            # RSA PSS is not yet supported by SoftHSM2
            if not e.value == PyKCS11.CKR_MECHANISM_INVALID:
                raise

        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)

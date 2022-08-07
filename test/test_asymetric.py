import unittest
from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        # get SoftHSM major version
        info = self.pkcs11.getInfo()
        self.SoftHSMversion = info.libraryVersion[0]
        self.manufacturer = info.manufacturerID

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
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
            (PyKCS11.CKA_ID, keyID),
        ]

        privTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ID, keyID),
        ]

        (self.pubKey, self.privKey) = self.session.generateKeyPair(
            pubTemplate, privTemplate
        )
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

    def tearDown(self):
        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_sign_integer(self):
        toSign = 1234567890
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

        # sign/verify
        try:
            self.session.sign(self.privKey, toSign, mecha)
        except PyKCS11.PyKCS11Error as e:
            self.assertEqual(e.value, -3)

    def test_sign_PKCS(self):
        toSign = "Hello world"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)

    def test_sign_PKCS_SHA256(self):
        toSign = "Hello world"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)

    def test_sign_X509(self):
        toSign = "Hello world"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_RSA_X_509, None)

        if self.SoftHSMversion < 2:
            self.skipTest("RSA X.509 only supported by SoftHSM >= 2")

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)

    def test_encrypt_PKCS(self):
        # encrypt/decrypt using CMK_RSA_PKCS (default)
        dataIn = "Hello world"
        encrypted = self.session.encrypt(self.pubKey, dataIn)
        decrypted = self.session.decrypt(self.privKey, encrypted)

        # convert in a string
        text = "".join(map(chr, decrypted))

        self.assertEqual(dataIn, text)

    def test_encrypt_X509(self):
        if self.SoftHSMversion < 2:
            self.skipTest("RSA X.509 only supported by SoftHSM >= 2")

        # encrypt/decrypt using CKM_RSA_X_509
        dataIn = "Hello world!"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_RSA_X_509, None)
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

    def test_RSA_OAEP(self):
        if self.SoftHSMversion < 2:
            self.skipTest("RSA OAEP only supported by SoftHSM >= 2")

        # RSA OAEP
        plainText = "A test string"

        mech = PyKCS11.RSAOAEPMechanism(PyKCS11.CKM_SHA_1, PyKCS11.CKG_MGF1_SHA1)
        cipherText = self.session.encrypt(self.pubKey, plainText, mech)
        decrypted = self.session.decrypt(self.privKey, cipherText, mech)

        text = "".join(map(chr, decrypted))

        self.assertEqual(text, plainText)

    def test_RSA_OAEPwithAAD(self):
        # AAD is "Additional Authentication Data"
        # (pSourceData of CK_RSA_PKCS_OAEP_PARAMS struct)
        if self.SoftHSMversion < 2:
            self.skipTest("RSA OAEP only supported by SoftHSM >= 2")

        if self.manufacturer.startswith("SoftHSM"):
            # SoftHSM indicates in syslog:
            #  "SoftHSM.cpp(12412): pSourceData must be NULL"
            # and returns CKR_ARGUMENTS_BAD
            self.skipTest("'AAD' not (yet) supported.")

        plainText = "A test string"

        # RSA OAEP
        aad = "sample aad".encode("utf-8")
        mech = PyKCS11.RSAOAEPMechanism(PyKCS11.CKM_SHA_1, PyKCS11.CKG_MGF1_SHA1, aad)
        cipherText = self.session.encrypt(self.pubKey, plainText, mech)
        decrypted = self.session.decrypt(self.privKey, cipherText, mech)

        text = bytes(decrypted).decode("utf-8")

        self.assertEqual(text, plainText)

    def test_RSA_PSS_SHA1(self):
        if self.SoftHSMversion < 2:
            self.skipTest("RSA PSS only supported by SoftHSM >= 2")

        # RSA PSS
        toSign = "test_RSA_sign_PSS SHA1"

        mech = PyKCS11.RSA_PSS_Mechanism(
            PyKCS11.CKM_SHA1_RSA_PKCS_PSS,
            PyKCS11.CKM_SHA_1,
            PyKCS11.CKG_MGF1_SHA1,
            20 # size of SHA1 result
        )
        signature = self.session.sign(self.privKey, toSign, mech)
        result = self.session.verify(self.pubKey, toSign, signature, mech)

        self.assertTrue(result)

    def test_RSA_PSS_SHA256(self):
        if self.SoftHSMversion < 2:
            self.skipTest("RSA PSS only supported by SoftHSM >= 2")

        # RSA PSS
        toSign = "test_RSA_sign_PSS SHA256"

        mech = PyKCS11.RSA_PSS_Mechanism(
            PyKCS11.CKM_SHA256_RSA_PKCS_PSS,
            PyKCS11.CKM_SHA256,
            PyKCS11.CKG_MGF1_SHA256,
            32 # size of SHA256 result
        )
        signature = self.session.sign(self.privKey, toSign, mech)
        result = self.session.verify(self.pubKey, toSign, signature, mech)

        self.assertTrue(result)

    def test_pubKey(self):
        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)

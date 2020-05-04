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

    def test_wrapKey(self):
        keyID = (0x01,)
        AESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_LABEL, "TestAESKey"),
            (PyKCS11.CKA_ID, keyID),
        ]

        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        self.wrapKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.wrapKey)

        keyID = (0x02,)
        # make the key extractable
        AESKeyTemplate.append((PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE))

        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

        # buffer of 32 bytes 0x42
        DataIn = [42] * 32

        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)
        DataOut = self.session.encrypt(self.AESKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(self.AESKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can encrypt/decrypt with the AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # wrap using CKM_AES_KEY_WRAP
        mechanismWrap = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_WRAP)
        wrapped = self.session.wrapKey(self.wrapKey, self.AESKey, mechanismWrap)
        self.assertIsNotNone(wrapped)

        # destroy the original key
        self.session.destroyObject(self.AESKey)

        # unwrap
        template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
        ]
        unwrapped = self.session.unwrapKey(
            self.wrapKey, wrapped, template, mechanismWrap
        )
        self.assertIsNotNone(unwrapped)

        DataCheck = self.session.decrypt(unwrapped, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can decrypt with the unwrapped AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # cleanup
        self.session.destroyObject(unwrapped)

        self.session.destroyObject(self.wrapKey)

    def test_wrapKey_OAEP(self):
        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

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

        self.pubKey, self.privKey = self.session.generateKeyPair(
            pubTemplate, privTemplate
        )
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        keyID = (0x02,)
        AESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_LABEL, "TestAESKey"),
            (PyKCS11.CKA_ID, keyID),
        ]

        # make the key extractable
        AESKeyTemplate.append((PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE))

        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

        # buffer of 32 bytes 0x42
        DataIn = [42] * 32

        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)
        DataOut = self.session.encrypt(self.AESKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(self.AESKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can encrypt/decrypt with the AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # wrap using CKM_RSA_PKCS_OAEP + CKG_MGF1_SHA1
        mechanismWrap = PyKCS11.RSAOAEPMechanism(
            PyKCS11.CKM_SHA_1, PyKCS11.CKG_MGF1_SHA1
        )
        wrapped = self.session.wrapKey(self.pubKey, self.AESKey, mechanismWrap)
        self.assertIsNotNone(wrapped)

        # destroy the original key
        self.session.destroyObject(self.AESKey)

        # unwrap
        template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
        ]
        unwrapped = self.session.unwrapKey(
            self.privKey, wrapped, template, mechanismWrap
        )
        self.assertIsNotNone(unwrapped)

        DataCheck = self.session.decrypt(unwrapped, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can decrypt with the unwrapped AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # cleanup
        self.session.destroyObject(unwrapped)

        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

    def test_wrapKey_UNWRAP_TEMPLATE(self):
        keyID = (0x01,)
        pubTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_LABEL, "RSA Public Key"),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_MODULUS_BITS, 2048),
            (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (PyKCS11.CKA_ID, keyID),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        ]

        unwrap_template = [
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_FALSE),
        ]

        privTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, "RSA Private Key"),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ID, keyID),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP_TEMPLATE, unwrap_template),
        ]

        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        self.pubKey, self.privKey = self.session.generateKeyPair(pubTemplate,
                privTemplate)
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        keyID = (0x02,)
        AESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_LABEL, "TestAESKey"),
            (PyKCS11.CKA_ID, keyID),
        ]

        # make the key extractable
        AESKeyTemplate.append((PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE))

        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

        # buffer of 32 bytes 0x42
        DataIn = [42] * 32

        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)
        DataOut = self.session.encrypt(self.AESKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(self.AESKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can encrypt/decrypt with the AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        # wrap
        mechanismWrap = PyKCS11.RSAOAEPMechanism(
            PyKCS11.CKM_SHA_1, PyKCS11.CKG_MGF1_SHA1
        )
        wrapped = self.session.wrapKey(self.pubKey, self.AESKey, mechanismWrap)
        self.assertIsNotNone(wrapped)

        # destroy the original key
        self.session.destroyObject(self.AESKey)

        # unwrap
        template = [
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_FALSE),
        ]
        unwrapped = self.session.unwrapKey(
            self.privKey, wrapped, template, mechanismWrap
        )
        self.assertIsNotNone(unwrapped)

        DataCheck = self.session.decrypt(unwrapped, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        # check we can decrypt with the unwrapped AES key
        self.assertSequenceEqual(DataIn, DataCheck)

        attributes = self.session.getAttributeValue(unwrapped, [PyKCS11.CKA_EXTRACTABLE])
        self.assertSequenceEqual(attributes, [False])

        # cleanup
        self.session.destroyObject(unwrapped)

        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

import unittest
from asn1crypto.keys import ECDomainParameters, NamedCurve
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

        # Select the curve to be used for the keys
        curve = u"secp256r1"

        # Setup the domain parameters, unicode conversion needed
        # for the curve string
        domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
        self.ecParams = domain_params.dump()

        keyID = (0x01,)
        baseKeyPubTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_EC_PARAMS, self.ecParams),
            (PyKCS11.CKA_LABEL, "TestBaseKeyP256"),
            (PyKCS11.CKA_ID, keyID),
        ]
        baseKeyPvtTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, "TestBaseKeyP256"),
            (PyKCS11.CKA_ID, keyID),
            (PyKCS11.CKA_DERIVE, PyKCS11.CK_TRUE),
        ]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_EC_KEY_PAIR_GEN, None)
        self.baseEcPubKey, self.baseEcPvtKey = self.session.generateKeyPair(baseKeyPubTemplate, baseKeyPvtTemplate, mechanism)
        self.assertIsNotNone(self.baseEcPubKey)
        self.assertIsNotNone(self.baseEcPvtKey)

        # Known base symmetric key
        knownAESKeyValue = bytes([0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB,
                                        0xCC, 0xCC, 0xCC, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD])

        keyID = (0x11,)
        wrapKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VALUE_LEN, 16),
            (PyKCS11.CKA_LABEL, "wrap"),
            (PyKCS11.CKA_ID, keyID),
        ]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN, None)
        AESKey = self.session.generateKey(wrapKeyTemplate, mechanism)
        self.assertIsNotNone(AESKey)

        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB, None)
        wrappedKey = self.session.encrypt(AESKey, knownAESKeyValue, mechanism)
        self.assertIsNotNone(wrappedKey)
        keyID = (0x02,)
        baseAESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_DERIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VALUE_LEN, 16),
            (PyKCS11.CKA_LABEL, "TestBaseAESKey"),
            (PyKCS11.CKA_ID, keyID),
        ]
        self.baseAESKey = self.session.unwrapKey(AESKey, wrappedKey, baseAESKeyTemplate, mechanism)
        self.assertIsNotNone(self.baseAESKey)
        self.session.destroyObject(AESKey)

    def tearDown(self):
        self.session.destroyObject(self.baseEcPubKey)
        self.session.destroyObject(self.baseEcPvtKey)
        self.session.destroyObject(self.baseAESKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_deriveKey_ECDH1_DERIVE(self):
        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        keyID = (0x22,)
        pubTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_EC_PARAMS, self.ecParams),
            (PyKCS11.CKA_LABEL, "testKeyP256"),
            (PyKCS11.CKA_ID, keyID),
        ]
        pvtTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, "testKeyP256"),
            (PyKCS11.CKA_ID, keyID),
            (PyKCS11.CKA_DERIVE, PyKCS11.CK_TRUE),
        ]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_EC_KEY_PAIR_GEN, None)
        pubKey, pvtKey = self.session.generateKeyPair(pubTemplate, pvtTemplate, mechanism)
        self.assertIsNotNone(pubKey)
        self.assertIsNotNone(pvtKey)

        keyID = (0x33,)
        derivedAESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 24),
            (PyKCS11.CKA_LABEL, "derivedAESKey"),
            (PyKCS11.CKA_ID, keyID),
        ]

        # derive key 1 : self.basePvtKey + pubKey
        attrs = self.session.getAttributeValue(pubKey, [PyKCS11.CKA_EC_POINT], True)
        mechanism = PyKCS11.ECDH1_DERIVE_Mechanism(bytes(attrs[0]))
        derivedKey = self.session.deriveKey(self.baseEcPvtKey, derivedAESKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey)

        # derive key 2 : pvtKey + self.basePubKey
        attrs = self.session.getAttributeValue(self.baseEcPubKey, [PyKCS11.CKA_EC_POINT], True)
        mechanism = PyKCS11.ECDH1_DERIVE_Mechanism(bytes(attrs[0]))
        derivedKey2 = self.session.deriveKey(pvtKey, derivedAESKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey2)

        DataIn = "Sample data to test ecdh1 derive".encode("utf-8")
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, "1234567812345678")
        DataOut = self.session.encrypt(derivedKey, DataIn, mechanism)
        DataCheck = self.session.decrypt(derivedKey2, DataOut, mechanism)

        # match check values
        self.assertSequenceEqual(DataIn, DataCheck)

        # cleanup
        self.session.destroyObject(derivedKey)
        self.session.destroyObject(derivedKey2)
        self.session.destroyObject(pubKey)
        self.session.destroyObject(pvtKey)

    def test_deriveKey_CONCATENATE_BASE_AND_DATA(self):
        knownCheckValue = (0x5A, 0x71, 0x81)

        # to derive key
        derivationData = PyKCS11.ckbytelist([42] * 16)
        # to calculate key check value
        data = [0] * 16
        # known key check value with know base key and derivation data
        keyID = (0x22,)
        derivedAESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_LABEL, "derivedAES256Key"),
            (PyKCS11.CKA_ID, keyID),
        ]

        if self.manufacturer.startswith("SoftHSM"):
            self.skipTest("SoftHSMv2 does not support CKM_CONCATENATE_BASE_AND_DATA.")

        # mechanism = PyKCS11.Mechanism(PyKCS11.CKM_CONCATENATE_BASE_AND_DATA, params)
        params = PyKCS11.LowLevel.CK_KEY_DERIVATION_STRING_DATA()
        params.pData = derivationData
        params.ulLen = len(derivationData)
        mechanism = PyKCS11.LowLevel.CK_MECHANISM()
        mechanism.mechanism = PyKCS11.CKM_CONCATENATE_BASE_AND_DATA
        mechanism.pParameter = params
        mechanism.ulParameterLen = PyKCS11.LowLevel.CK_KEY_DERIVATION_STRING_DATA_LENGTH
        derivedKey = self.session.deriveKey(self.baseAESKey, derivedAESKeyTemplate, mechanism)

        # generate key check value
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB, None)
        checkValue = self.session.encrypt(derivedKey, data, mechanism)

        # match check values
        self.assertSequenceEqual(knownCheckValue, checkValue[0:3]) # ZL6

        # cleanup
        self.session.destroyObject(derivedKey)

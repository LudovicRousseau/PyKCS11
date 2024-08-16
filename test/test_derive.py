import unittest
from asn1crypto.keys import ECDomainParameters, NamedCurve
from PyKCS11 import PyKCS11

class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        # get SoftHSM major version
        info = self.pkcs11.getInfo()
        self.SoftHSMversion = info.libraryVersion
        self.manufacturer = info.manufacturerID

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login("1234")

        # common templates used in derive test cases
        self.aesKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, "DeriveTestBaseAes256Key"),
            (PyKCS11.CKA_DERIVE, PyKCS11.CK_TRUE),
        ]

        self.genericKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_GENERIC_SECRET),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, "DeriveTestGenericKey"),
        ]

        # generate a common symmetric base key for tests
        keyID = (0x01,)
        baseKeyTemplate = self.aesKeyTemplate + [(PyKCS11.CKA_ID, keyID)]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN, None)
        self.baseKey = self.session.generateKey(baseKeyTemplate, mechanism)
        self.assertIsNotNone(self.baseKey)

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

    def tearDown(self):
        self.session.destroyObject(self.baseEcPubKey)
        self.session.destroyObject(self.baseEcPvtKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.unload()
        del self.pkcs11

    def getCkaValue(self, key):
        return list(
            self.session.getAttributeValue(
            key, [PyKCS11.CKA_VALUE])[0]
        )

    def test_deriveKey_ECDH1_DERIVE(self):
        if self.SoftHSMversion[0] < 2:
            self.skipTest("generateKeyPair() only supported by SoftHSM >= 2")

        keyID = (0x11,)
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

        keyID = (0x22,)
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

    def test_deriveKey_CKM_CONCATENATE_BASE_AND_KEY(self):
        # This mechanism is not supported in the current release of SoftHSM (2.6.1), however available in develop branch,
        # see https://github.com/opendnssec/SoftHSMv2/commit/fa595c07a185656382c18ea2a6a12cad825d48b4
        if self.SoftHSMversion <= (2,6):
            self.skipTest("CKM_CONCATENATE_BASE_AND_KEY is not supported by SoftHSM <= 2.6")

        # generate a key to concatenate with
        keyID = (0x11,)
        concatenateKeyTemplate = self.aesKeyTemplate + [(PyKCS11.CKA_ID, keyID)]
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_KEY_GEN, None)
        concKey = self.session.generateKey(concatenateKeyTemplate, mechanism)
        self.assertIsNotNone(concKey)

        # concatenate two keys
        keyID = (0x22,)
        derivedKeyTemplate = self.genericKeyTemplate + [
            (PyKCS11.CKA_VALUE_LEN, 64),
            (PyKCS11.CKA_ID, keyID)
        ]
        mechanism = PyKCS11.CONCATENATE_BASE_AND_KEY_Mechanism(concKey)
        derivedKey = self.session.deriveKey(
            self.baseKey, derivedKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey)

        # check derived key's value
        baseKeyValue = self.getCkaValue(self.baseKey)
        concKeyValue = self.getCkaValue(concKey)
        derivedKeyValue = self.getCkaValue(derivedKey)

        # match: check values
        self.assertSequenceEqual(baseKeyValue + concKeyValue, derivedKeyValue)

        # cleanup
        self.session.destroyObject(derivedKey)
        self.session.destroyObject(concKey)

    def test_deriveKey_CKM_CONCATENATE_BASE_AND_DATA(self):
        # This mechanism is not supported in the current release of SoftHSM (2.6.1), however available in develop branch,
        # see https://github.com/opendnssec/SoftHSMv2/commit/dba00d73e1b69f65b68397d235e7f73bbf59ab6a
        if self.SoftHSMversion <= (2,6):
            self.skipTest("CKM_CONCATENATE_BASE_AND_DATA is not supported by SoftHSM <= 2.6")

        # generate data to concatenate with
        concData = list(self.session.generateRandom(32))

        # concatenate key with data
        keyID = (0x22,)
        derivedKeyTemplate = self.genericKeyTemplate + [
            (PyKCS11.CKA_VALUE_LEN, 64),
            (PyKCS11.CKA_ID, keyID)
        ]
        mechanism = PyKCS11.CONCATENATE_BASE_AND_DATA_Mechanism(concData)
        derivedKey = self.session.deriveKey(
            self.baseKey, derivedKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey)

        # check derived key's value
        baseKeyValue = self.getCkaValue(self.baseKey)
        derivedKeyValue = self.getCkaValue(derivedKey)

        # match: check values
        self.assertSequenceEqual(baseKeyValue + concData, derivedKeyValue)

        # cleanup
        self.session.destroyObject(derivedKey)

    def test_deriveKey_CKM_CONCATENATE_DATA_AND_BASE(self):
        # This mechanism is not supported in the current release of SoftHSM (2.6.1), however available in develop branch,
        # see https://github.com/opendnssec/SoftHSMv2/commit/fae0d9f769ac30d25f563c5fc6c417e9199e4403
        if self.SoftHSMversion <= (2,6):
            self.skipTest("CKM_CONCATENATE_DATA_AND_BASE is not supported by SoftHSM <= 2.6")

        # generate data to concatenate with
        concData = list(self.session.generateRandom(32))

        # concatenate data with key
        keyID = (0x22,)
        derivedKeyTemplate = self.genericKeyTemplate + [
            (PyKCS11.CKA_VALUE_LEN, 64),
            (PyKCS11.CKA_ID, keyID)
        ]
        mechanism = PyKCS11.CONCATENATE_DATA_AND_BASE_Mechanism(concData)
        derivedKey = self.session.deriveKey(
            self.baseKey, derivedKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey)

        # check derived key's value
        baseKeyValue = self.getCkaValue(self.baseKey)
        derivedKeyValue = self.getCkaValue(derivedKey)

        # match: check values
        self.assertSequenceEqual(concData + baseKeyValue, derivedKeyValue)

        # cleanup
        self.session.destroyObject(derivedKey)

    def test_deriveKey_CKM_XOR_BASE_AND_DATA(self):
        if self.manufacturer.startswith("SoftHSM"):
            self.skipTest("SoftHSM does not support CKM_XOR_BASE_AND_DATA")

        # generate data to xor with
        xorData = list(self.session.generateRandom(32))

        # xor key with data
        keyID = (0x22,)
        derivedKeyTemplate = self.genericKeyTemplate + [
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_ID, keyID)
        ]
        mechanism = PyKCS11.XOR_BASE_AND_DATA_Mechanism(xorData)
        derivedKey = self.session.deriveKey(
            self.baseKey, derivedKeyTemplate, mechanism)
        self.assertIsNotNone(derivedKey)

        # check derived key's value
        baseKeyValue = self.getCkaValue(self.baseKey)
        derivedKeyValue = self.getCkaValue(derivedKey)
        expectedValue = map(lambda x, y: x ^ y, baseKeyValue, xorData)

        # match: check values
        self.assertSequenceEqual(list(expectedValue), derivedKeyValue)

        # cleanup
        self.session.destroyObject(derivedKey)

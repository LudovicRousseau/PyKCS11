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

    def tearDown(self):
        self.session.destroyObject(self.baseEcPubKey)
        self.session.destroyObject(self.baseEcPvtKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_deriveKey_ECDH1_DERIVE(self):
        if self.SoftHSMversion < 2:
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

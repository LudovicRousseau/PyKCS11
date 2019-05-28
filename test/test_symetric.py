from __future__ import print_function
import unittest
from PyKCS11 import PyKCS11


class TestUtil(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login("1234")

    def tearDown(self):
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_symetric(self):
        # AES CBC with IV
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, "1234567812345678")
        self.assertIsNotNone(mechanism)

        if self.SoftHSMversion < (2,0):
            self.skipTest("generateKey() only supported by SoftHSM >= 2.0")

        keyID = (0x01,)
        AESKeyTemplate = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_LABEL, "TestAESKey"),
            (PyKCS11.CKA_ID, keyID),
        ]

        AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(AESKey)

        # buffer of 32 bytes 0x00
        DataIn = [0] * 32
        # print("DataIn:", DataIn)

        # AES CBC with IV
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, "1234567812345678")

        # find the first secret key
        symKey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY), (PyKCS11.CKA_ID, keyID)]
        )[0]

        DataOut = self.session.encrypt(symKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(symKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        self.assertSequenceEqual(DataIn, DataCheck)

        # AES ECB with previous IV as Data
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB)

        # same as '1234567812345678' (the IV) but as a list
        DataECBIn = [49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56]
        # print("DataECBIn:", DataECBIn)
        DataECBOut = self.session.encrypt(symKey, DataECBIn, mechanism)
        # print("DataECBOut:", DataECBOut)

        DataECBCheck = self.session.decrypt(symKey, DataECBOut, mechanism)
        # print("DataECBCheck:", DataECBCheck)

        self.assertSequenceEqual(DataECBIn, DataECBCheck)

        # check the AES CBC computation is the same as the AES ECB
        # 1st block
        self.assertSequenceEqual(DataOut[:16], DataECBOut)

        # since the input is full of 0 we just pass the previous output
        DataECBOut2 = self.session.encrypt(symKey, DataECBOut, mechanism)
        # print("DataECBOut2", DataECBOut2)

        # 2nd block
        self.assertSequenceEqual(DataOut[16:], DataECBOut2)

        #
        # test CK_GCM_PARAMS
        #

        if self.SoftHSMversion <= (2,2):
            self.skipTest("CKM_AES_GCM only supported by SoftHSM > 2.2")

        AES_GCM_IV_SIZE = 12
        AES_GCM_TAG_SIZE = 16
        iv = [42] * AES_GCM_IV_SIZE
        aad = "plaintext aad"
        tagBits = AES_GCM_TAG_SIZE * 8
        mechanism = PyKCS11.AES_GCM_Mechanism(iv, aad, tagBits)

        DataOut = self.session.encrypt(symKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(symKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        self.assertSequenceEqual(DataIn, DataCheck)

        self.session.destroyObject(AESKey)

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

    def test_mechanism(self):
        # AES CBC with IV
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, '1234567812345678')
        self.assertIsNotNone(mechanism)

    def test_sign(self):
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
                (PyKCS11.CKA_ID, keyID)
                ]

        try:
            AESKey = self.session.generateKey(AESKeyTemplate)
        except PyKCS11.PyKCS11Error as e:
            # generateKey() is not support by SoftHSM1
            if str(e) == "CKR_FUNCTION_NOT_SUPPORTED (0x00000054)":
                return
            else:
                raise
        self.assertIsNotNone(AESKey)

        # buffer of 32 bytes 0x00
        DataIn = [0] * 32

        # AES CBC with IV
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, '1234567812345678')

        # find the first secret key
        symKey = self.session.findObjects([(PyKCS11.CKA_CLASS,
            PyKCS11.CKO_SECRET_KEY), (PyKCS11.CKA_ID, keyID)])[0]

        DataOut = self.session.encrypt(symKey, DataIn, mechanism)

        DataCheck = self.session.decrypt(symKey, DataOut, mechanism)

        self.assertSequenceEqual(DataIn, DataCheck)

        self.session.destroyObject(AESKey)

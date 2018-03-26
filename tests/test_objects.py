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
                (PyKCS11.CKA_ID, (0x01,))
                ]

        self.AESKey = None
        try:
            AESKey = self.session.generateKey(AESKeyTemplate)
        except PyKCS11.PyKCS11Error as e:
            # generateKey() is not support by SoftHSM1
            if e.value == PyKCS11.CKR_FUNCTION_NOT_SUPPORTED:
                return
            else:
                raise
        self.assertIsNotNone(AESKey)
        self.AESKey = AESKey

    def tearDown(self):
        if self.AESKey is not None:
            self.session.destroyObject(self.AESKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_Objecthandle(self):
        if self.AESKey is None:
            return

        # find the first secret key
        symKey = self.session.findObjects([(PyKCS11.CKA_CLASS,
                                            PyKCS11.CKO_SECRET_KEY)])[0]

        text = str(symKey)
        self.assertIsNotNone(text)

    def test_CreateObject(self):
        template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_DATA),
                (PyKCS11.CKA_LABEL, "data"),
                ]
        try:
            handle = self.session.createObject(template)
        except PyKCS11.PyKCS11Error as e:
            # createObject() is not fully support by SoftHSM1
            if e.value == PyKCS11.CKR_ATTRIBUTE_VALUE_INVALID:
                return

        self.session.destroyObject(handle)

    def test_getAttributeValue(self):
        if self.AESKey is None:
            return

        # attributes as define by AESKeyTemplate
        all_attributes = [PyKCS11.CKA_CLASS, PyKCS11.CKA_KEY_TYPE,
                          PyKCS11.CKA_TOKEN, PyKCS11.CKA_LABEL,
                          PyKCS11.CKA_ID]

        values = self.session.getAttributeValue(self.AESKey, all_attributes)
        self.assertEqual(values, [PyKCS11.CKO_SECRET_KEY,
                                  PyKCS11.CKK_AES, PyKCS11.CK_TRUE,
                                  "TestAESKey", (0x01,)])

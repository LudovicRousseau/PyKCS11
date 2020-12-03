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

    def test_Objects(self):
        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

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
            (PyKCS11.CKA_ID, (0x01,)),
        ]

        # generate AES key
        AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(AESKey)

        # find the first secret key
        symKey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY)]
        )[0]

        # test object handle
        text = str(symKey)
        self.assertIsNotNone(text)

        # test createObject()
        template = [(PyKCS11.CKA_CLASS, PyKCS11.CKO_DATA), (PyKCS11.CKA_LABEL, "data")]
        handle = self.session.createObject(template)
        self.assertIsNotNone(handle)

        self.session.destroyObject(handle)

        # test getAttributeValue

        # attributes as define by AESKeyTemplate
        all_attributes = [
            PyKCS11.CKA_CLASS,
            PyKCS11.CKA_KEY_TYPE,
            PyKCS11.CKA_TOKEN,
            PyKCS11.CKA_LABEL,
            PyKCS11.CKA_ID,
        ]

        values = self.session.getAttributeValue(AESKey, all_attributes)
        self.assertEqual(
            values,
            [
                PyKCS11.CKO_SECRET_KEY,
                PyKCS11.CKK_AES,
                PyKCS11.CK_TRUE,
                "TestAESKey",
                (0x01,),
            ],
        )

        self.session.destroyObject(AESKey)

        template = [(PyKCS11.CKA_HW_FEATURE_TYPE, PyKCS11.CKH_USER_INTERFACE)]
        o = self.session.findObjects(template)

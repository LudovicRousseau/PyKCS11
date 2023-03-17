import unittest
from PyKCS11 import PyKCS11

# those shortcuts make the testing code more readable
CK_FALSE = PyKCS11.CK_FALSE
CK_TRUE = PyKCS11.CK_TRUE


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

    def test_objects(self):
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

        # clean up
        self.session.destroyObject(AESKey)

        template = [(PyKCS11.CKA_HW_FEATURE_TYPE, PyKCS11.CKH_USER_INTERFACE)]
        o = self.session.findObjects(template)


class TestGetSetAttributeValues(unittest.TestCase):

    def setUp(self) -> None:

        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        # get SoftHSM major version
        self.SoftHSMversion = self.pkcs11.getInfo().libraryVersion[0]
        if self.SoftHSMversion < 2:
            self.skipTest("generateKey() only supported by SoftHSM >= 2")

        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]

        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login("1234")

        AESKeyTemplate = [
            (PyKCS11.CKA_CLASS,     PyKCS11.CKO_SECRET_KEY),
            (PyKCS11.CKA_KEY_TYPE,  PyKCS11.CKK_AES),
            (PyKCS11.CKA_TOKEN,     CK_TRUE),
            (PyKCS11.CKA_PRIVATE,   CK_FALSE),
            (PyKCS11.CKA_ENCRYPT,   CK_TRUE),
            (PyKCS11.CKA_DECRYPT,   CK_TRUE),
            (PyKCS11.CKA_SIGN,      CK_FALSE),
            (PyKCS11.CKA_VERIFY,    CK_FALSE),
            (PyKCS11.CKA_VALUE_LEN, 32),
            (PyKCS11.CKA_LABEL,     "TestAESKey"),
            (PyKCS11.CKA_ID,        (0x01,)),
        ]

        # generate AES key
        self.AESKey = self.session.generateKey(AESKeyTemplate)
        self.assertIsNotNone(self.AESKey)

    def tearDown(self):
        self.session.destroyObject(self.AESKey)
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_getAttributeValue(self):

        # attributes as defined by AESKeyTemplate in setUp
        all_attributes = [
            PyKCS11.CKA_CLASS,
            PyKCS11.CKA_KEY_TYPE,
            PyKCS11.CKA_TOKEN,
            PyKCS11.CKA_LABEL,
            PyKCS11.CKA_ID,
        ]

        values = self.session.getAttributeValue(self.AESKey, all_attributes)
        self.assertEqual(
            values,
            [
                PyKCS11.CKO_SECRET_KEY,
                PyKCS11.CKK_AES,
                CK_TRUE,
                "TestAESKey",
                (0x01,),
            ],
        )

    def test_setAttributeValue_with_single_binary_attribute(self):
        # test setAttributeValue with a binary attribute
        _ATTR = PyKCS11.CKA_SIGN  # which attribute to test with. use a binary attribute

        old_state = self.session.getAttributeValue(self.AESKey, [_ATTR])[0]
        new_state = CK_TRUE if old_state == CK_FALSE else CK_FALSE  # switch the state

        rv = self.session.setAttributeValue(self.AESKey, [(_ATTR, new_state)])
        assert rv is None

        # test to see if object is really modified
        test_state = self.session.getAttributeValue(self.AESKey, [_ATTR])[0]
        assert test_state == new_state
        assert test_state != old_state

    def test_setAttributeValue_with_a_list_of_attributes(self):

        # which binary attributes to flip?
        attributes_to_switch = [
            PyKCS11.CKA_SIGN, PyKCS11.CKA_ENCRYPT, PyKCS11.CKA_DECRYPT,
            PyKCS11.CKA_VERIFY, PyKCS11.CKA_WRAP, PyKCS11.CKA_UNWRAP
        ]

        old_attributes = self.session.getAttributeValue(self.AESKey, attributes_to_switch)

        flipped_attributes = []
        for i, attr in enumerate(attributes_to_switch):
            new_value = CK_TRUE if old_attributes[i] == CK_FALSE else CK_FALSE
            flipped_attributes.append((attributes_to_switch[i], new_value))

        rv = self.session.setAttributeValue(self.AESKey, flipped_attributes)
        assert rv is None

        new_attributes = self.session.getAttributeValue(self.AESKey, attributes_to_switch)
        for new, old in zip(new_attributes, old_attributes):
            assert new != old
            assert (new == CK_TRUE and old == CK_FALSE) or (new == CK_FALSE and old == CK_TRUE)

    def test_setAttributeValue_with_label_attribute(self):
        # test setAttributeValue with the text field `CKA_Label` by appending some text

        old_label = self.session.getAttributeValue(self.AESKey, [PyKCS11.CKA_LABEL])[0]
        new_label = old_label + "-mod"
        self.session.setAttributeValue(self.AESKey, [(PyKCS11.CKA_LABEL, new_label)])
        test_label = self.session.getAttributeValue(self.AESKey, [PyKCS11.CKA_LABEL])[0]

        assert new_label != old_label
        assert test_label == new_label
        assert test_label != old_label

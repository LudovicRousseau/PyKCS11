# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

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

        self.aesKeyTemplate = [
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
        ]

        self.aesBlockSize = 16

    def tearDown(self):
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_symetric(self):
        # AES CBC with IV
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, "1234567812345678")
        self.assertIsNotNone(mechanism)

        if self.SoftHSMversion < (2, 0):
            self.skipTest("generateKey() only supported by SoftHSM >= 2.0")

        keyID = (0x01,)
        AESKeyTemplate = self.aesKeyTemplate + [(PyKCS11.CKA_ID, keyID)]

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

        # AES CTR with IV
        mechanism = PyKCS11.AES_CTR_Mechanism(128, "1234567812345678")

        DataOut = self.session.encrypt(symKey, DataIn, mechanism)
        # print("DataOut", DataOut)

        DataCheck = self.session.decrypt(symKey, DataOut, mechanism)
        # print("DataCheck:", DataCheck)

        self.assertSequenceEqual(DataIn, DataCheck)

        #
        # test CK_GCM_PARAMS
        #

        if self.SoftHSMversion <= (2, 2):
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

    def test_multi_part_symmetric(self):
        iv = self.session.generateRandom(self.aesBlockSize)

        aesMechanisms = {
            "CKM_AES_ECB": PyKCS11.Mechanism(PyKCS11.CKM_AES_ECB),
            "CKM_AES_CBC": PyKCS11.Mechanism(PyKCS11.CKM_AES_CBC, iv),
            "CKM_AES_CTR": PyKCS11.AES_CTR_Mechanism(128, iv),
        }

        keyID = (0x02,)
        aesKey = self.session.generateKey(
            self.aesKeyTemplate + [(PyKCS11.CKA_ID, keyID)]
        )
        self.assertIsNotNone(aesKey)

        for mechName in aesMechanisms:
            with self.subTest(mechName=mechName):
                if not mechName in self.pkcs11.getMechanismList(self.slot):
                    self.skipTest(f"{mechName} is not supported by the token")
                self._run_multipart_encrypt_decrypt(aesMechanisms[mechName], aesKey)

        self.session.destroyObject(aesKey)

    def _run_multipart_encrypt_decrypt(self, mechanism, key):
        self.assertIsNotNone(mechanism)

        self.session.encryptInit(mechanism, key)

        data = self.session.generateRandom(self.aesBlockSize * 8)

        encData = []
        dataPos = 0
        # encrypt data using parts of different length,
        # but each of them must be a multiple of the block size
        for m in [1, 2, 3, 4]:  # total 8 blocks
            dataPart = list(data[dataPos : dataPos + m * self.aesBlockSize])
            encData += self.session.encryptUpdate(dataPart)
            dataPos += m * self.aesBlockSize
        encData += self.session.encryptFinal()

        self.session.decryptInit(mechanism, key)

        decData = []
        dataPos = 0
        for m in [3, 1, 2, 4]:  # total 8 blocks
            encPart = list(encData[dataPos : dataPos + m * self.aesBlockSize])
            decData += self.session.decryptUpdate(encPart)
            dataPos += m * self.aesBlockSize
        decData += self.session.decryptFinal()

        self.assertSequenceEqual(data, decData)

        # initiate another encryption to check that
        # the previous operation has been terminated
        self.session.encryptInit(mechanism, key)
        self.session.encryptFinal()

    def test_multi_part_aead(self):
        if "CKM_AES_GCM" not in self.pkcs11.getMechanismList(self.slot):
            self.skipTest("CKM_AES_GCM is not supported by the token")

        keyID = (0x03,)
        aesKey = self.session.generateKey(
            self.aesKeyTemplate + [(PyKCS11.CKA_ID, keyID)]
        )
        self.assertIsNotNone(aesKey)

        AES_GCM_IV_SIZE = 12
        AES_GCM_TAG_SIZE = 16
        iv = self.session.generateRandom(AES_GCM_IV_SIZE)
        aad = "plaintext aad"
        tagBits = AES_GCM_TAG_SIZE * 8
        mechanism = PyKCS11.AES_GCM_Mechanism(iv, aad, tagBits)

        self.session.encryptInit(mechanism, aesKey)

        data = self.session.generateRandom()

        encData = self.session.encryptUpdate(data)
        tag = self.session.encryptFinal()
        self.assertTrue(tag)

        self.session.decryptInit(mechanism, aesKey)

        decData = self.session.decryptUpdate(encData)

        # check: since CKM_AES_GCM is an AEAD cipher, no data should be returned until decryptFinal()
        # see https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061258
        self.assertFalse(decData)

        decData += self.session.decryptUpdate(tag)
        self.assertFalse(decData)
        decData += self.session.decryptFinal()

        self.assertSequenceEqual(data, list(decData))
        self.session.destroyObject(aesKey)

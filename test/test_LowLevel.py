import unittest
from PyKCS11 import ckbytelist
import PyKCS11.LowLevel
import os
import platform
import run_test


class TestUtil(unittest.TestCase):
    def setUp(self):
        run_test.set_PYKCS11LIB()

    def test_LowLevel(self):
        a = PyKCS11.LowLevel.CPKCS11Lib()
        self.assertIsNotNone(a)

        # File not found
        self.assertEqual(a.Load("NoFile"), -1)

        # C_GetFunctionList() not found
        if platform.system() == 'Linux':
            # GNU/Linux
            lib = "libc.so.6"
        elif platform.system() == 'Darwin':
            # macOS
            lib = "/usr/lib/libSystem.B.dylib"
        else:
            # Windows
            lib = "WinSCard.dll"
        self.assertEqual(a.Load(lib), -4)

        info = PyKCS11.LowLevel.CK_INFO()
        self.assertIsNotNone(info)

        slotInfo = PyKCS11.LowLevel.CK_SLOT_INFO()
        self.assertIsNotNone(slotInfo)

        lib = os.getenv("PYKCS11LIB")
        if lib is None:
            raise (Exception("Define PYKCS11LIB"))

        session = PyKCS11.LowLevel.CK_SESSION_HANDLE()
        self.assertIsNotNone(session)

        sessionInfo = PyKCS11.LowLevel.CK_SESSION_INFO()
        self.assertIsNotNone(sessionInfo)

        tokenInfo = PyKCS11.LowLevel.CK_TOKEN_INFO()
        self.assertIsNotNone(tokenInfo)

        slotList = PyKCS11.LowLevel.ckintlist()
        self.assertIsNotNone(slotList)

        a.Load(lib)

        self.assertEqual(a.C_GetInfo(info), PyKCS11.LowLevel.CKR_OK)
        manufacturerID = info.GetManufacturerID()
        self.assertEqual(manufacturerID, "SoftHSM".ljust(32))
        del info

        a.C_GetSlotList(0, slotList)
        slot = slotList[0]

        self.assertEqual(a.C_GetSlotInfo(slot, slotInfo), PyKCS11.LowLevel.CKR_OK)

        self.assertEqual(
            a.C_OpenSession(
                slot,
                PyKCS11.LowLevel.CKF_SERIAL_SESSION | PyKCS11.LowLevel.CKF_RW_SESSION,
                session,
            ),
            PyKCS11.LowLevel.CKR_OK,
        )
        self.assertEqual(
            a.C_GetSessionInfo(session, sessionInfo), PyKCS11.LowLevel.CKR_OK
        )

        self.assertEqual(a.C_GetTokenInfo(slot, tokenInfo), PyKCS11.LowLevel.CKR_OK)
        label = tokenInfo.GetLabel()
        manufacturerID = tokenInfo.GetManufacturerID()
        flags = tokenInfo.flags
        model = tokenInfo.GetModel()

        pin = ckbytelist("1234")
        self.assertEqual(
            a.C_Login(session, PyKCS11.LowLevel.CKU_USER, pin), PyKCS11.LowLevel.CKR_OK
        )
        self.assertEqual(a.C_Logout(session), PyKCS11.LowLevel.CKR_OK)
        self.assertEqual(a.C_CloseSession(session), PyKCS11.LowLevel.CKR_OK)

        self.assertEqual(
            a.C_OpenSession(slotList[0], PyKCS11.LowLevel.CKF_SERIAL_SESSION, session),
            PyKCS11.LowLevel.CKR_OK,
        )
        self.assertEqual(
            a.C_Login(session, PyKCS11.LowLevel.CKU_USER, pin), PyKCS11.LowLevel.CKR_OK
        )

        SearchResult = PyKCS11.LowLevel.ckobjlist(10)
        SearchTemplate = PyKCS11.LowLevel.ckattrlist(2)
        SearchTemplate[0].SetNum(
            PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE
        )
        SearchTemplate[1].SetBool(PyKCS11.LowLevel.CKA_TOKEN, True)

        self.assertEqual(
            a.C_FindObjectsInit(session, SearchTemplate), PyKCS11.LowLevel.CKR_OK
        )
        self.assertEqual(
            a.C_FindObjects(session, SearchResult), PyKCS11.LowLevel.CKR_OK
        )
        self.assertEqual(a.C_FindObjectsFinal(session), PyKCS11.LowLevel.CKR_OK)

        for x in SearchResult:
            print("object: " + hex(x.value()))
            valTemplate = PyKCS11.LowLevel.ckattrlist(2)
            valTemplate[0].SetType(PyKCS11.LowLevel.CKA_LABEL)
            # valTemplate[0].Reserve(128)
            valTemplate[1].SetType(PyKCS11.LowLevel.CKA_CLASS)
            # valTemplate[1].Reserve(4)
            print(
                "C_GetAttributeValue(): "
                + hex(a.C_GetAttributeValue(session, x, valTemplate))
            )
            print(
                "CKA_LABEL Len: ",
                valTemplate[0].GetLen(),
                " CKA_CLASS Len: ",
                valTemplate[1].GetLen(),
            )
            print(
                "C_GetAttributeValue(): "
                + hex(a.C_GetAttributeValue(session, x, valTemplate))
            )
            print("\tCKO_CERTIFICATE: " + valTemplate[0].GetString())
            print("\tCKA_TOKEN: " + str(valTemplate[1].GetNum()))

        self.assertEqual(a.C_Logout(session), PyKCS11.LowLevel.CKR_OK)
        self.assertEqual(a.C_CloseSession(session), PyKCS11.LowLevel.CKR_OK)
        self.assertEqual(a.C_Finalize(), PyKCS11.LowLevel.CKR_OK)
        a.Unload()


if __name__ == "__main__":
    unittest.main()

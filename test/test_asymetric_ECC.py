# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import binascii
import unittest

from asn1crypto.core import OctetString
from asn1crypto.keys import ECDomainParameters, NamedCurve, PrivateKeyAlgorithmId

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

        # Select the curve to be used for the keys
        curve = "secp256r1"

        # Setup the domain parameters, unicode conversion needed
        # for the curve string
        domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
        ec_params = domain_params.dump()

        keyID = (0x22,)
        label = "test"

        ec_public_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_EC_PARAMS, ec_params),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_ID, keyID),
        ]

        ec_priv_tmpl = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_ECDSA),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_ID, keyID),
        ]

        if self.SoftHSMversion < 2:
            self.skipTest("ECDSA only supported by SoftHSM >= 2")

        (self.pubKey, self.privKey) = self.session.generateKeyPair(
            ec_public_tmpl, ec_priv_tmpl, mecha=PyKCS11.MechanismECGENERATEKEYPAIR
        )
        self.assertIsNotNone(self.pubKey)
        self.assertIsNotNone(self.privKey)

        # test CK_OBJECT_HANDLE.__repr__()
        text = str(self.pubKey)
        self.assertIsNotNone(text)

    def tearDown(self):
        self.session.destroyObject(self.pubKey)
        self.session.destroyObject(self.privKey)

        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        del self.pkcs11

    def test_sign_integer(self):
        toSign = 1234567890
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)

        # sign/verify
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.session.sign(self.privKey, toSign, mecha)
        # should return PyKCS11.PyKCS11Error: Unknown format (<class 'int'>)
        self.assertEqual(cm.exception.value, -3)

    def test_sign_text(self):
        toSign = "Hello World!"
        mecha = PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None)

        # sign/verify
        signature = self.session.sign(self.privKey, toSign, mecha)

        result = self.session.verify(self.pubKey, toSign, signature, mecha)

        self.assertTrue(result)


class TestEDDSA(unittest.TestCase):
    def setUp(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load()

        self.manufacturer = self.pkcs11.getInfo().manufacturerID
        self.slot = self.pkcs11.getSlotList(tokenPresent=True)[0]

        for m in ["CKM_EC_EDWARDS_KEY_PAIR_GEN", "CKM_EDDSA"]:
            if not m in self.pkcs11.getMechanismList(self.slot):
                self.pkcs11.unload()
                self.skipTest(f"{m} is not supported by the token")

        self.session = self.pkcs11.openSession(
            self.slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login("1234")

        self.ec_base_tmpl = [
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC_EDWARDS),
            (PyKCS11.CKA_LABEL, "test"),
            (PyKCS11.CKA_ID, (0x33,)),
        ]

        self.ec_public_tmpl = self.ec_base_tmpl + [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        ]

        self.ec_priv_tmpl = self.ec_base_tmpl + [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        ]

        # see https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061191
        self.schemes = {
            # scheme     : ("curve", phFlag)
            "Ed25519": ("ed25519", None),
            "Ed25519ctx": ("ed25519", False),
            "Ed25519ph": ("ed25519", True),
            "Ed448": ("ed448", False),
            "Ed448ph": ("ed448", True),
        }

    def tearDown(self):
        self.session.logout()
        self.pkcs11.closeAllSessions(self.slot)
        self.pkcs11.unload()
        del self.pkcs11

    def _get_eddsa_mechanism(self, phf=None, ctx=None):
        if phf is None:
            return PyKCS11.EDDSA_Mechanism()
        elif ctx is None:
            return PyKCS11.EDDSA_Mechanism(phFlag=phf)
        else:
            return PyKCS11.EDDSA_Mechanism(phFlag=phf, contextData=ctx)

    def _generate_edwards_key_pair(self, curve):
        # Setup the domain parameters, unicode conversion needed
        # for the curve string
        ec_params = PrivateKeyAlgorithmId(curve).dump()
        ec_public_tmpl = self.ec_public_tmpl + [(PyKCS11.CKA_EC_PARAMS, ec_params)]

        (pubKey, privKey) = self.session.generateKeyPair(
            ec_public_tmpl,
            self.ec_priv_tmpl,
            mecha=PyKCS11.Mechanism(PyKCS11.CKM_EC_EDWARDS_KEY_PAIR_GEN, None),
        )
        self.assertIsNotNone(pubKey)
        self.assertIsNotNone(privKey)

        # test CK_OBJECT_HANDLE.__repr__()
        text = str(pubKey)
        self.assertIsNotNone(text)
        return (pubKey, privKey)

    def test_sign_integer(self):
        toSign = 1234567890
        mecha = PyKCS11.EDDSA_Mechanism()
        (pubKey, privKey) = self._generate_edwards_key_pair("ed25519")

        # sign/verify
        with self.assertRaises(PyKCS11.PyKCS11Error) as cm:
            self.session.sign(privKey, toSign, mecha)
        # should return PyKCS11.PyKCS11Error: Unknown format (<class 'int'>)
        self.assertEqual(cm.exception.value, -3)

        self.session.destroyObject(pubKey)
        self.session.destroyObject(privKey)

    def test_sign_text(self):
        toSign = ctxData = "Hello World!"
        schemes = [
            # Ed25519
            ("ed25519", None, None),
            # Ed25519ctx
            ("ed25519", False, None),
            ("ed25519", False, ctxData),
            # Ed25519ph
            ("ed25519", True, None),
            ("ed25519", True, ctxData),
            # Ed448
            ("ed448", False, None),
            ("ed448", False, ctxData),
            # Ed448ph
            ("ed448", True, None),
            ("ed448", True, ctxData),
        ]

        for curve, phflag, context in schemes:
            with self.subTest(curve=curve, phflag=phflag, context=context):
                mech = self._get_eddsa_mechanism(phflag, context)
                (pubKey, privKey) = self._generate_edwards_key_pair(curve)
                # sign/verify
                signature = self.session.sign(privKey, toSign, mech)

                self.assertTrue(self.session.verify(pubKey, toSign, signature, mech))

                self.session.destroyObject(pubKey)
                self.session.destroyObject(privKey)

    def test_sign_test_vectors(self):
        # test vectors from RFC 8032, Sec. 7
        test_vectors = [
            # Ed25519
            {
                "scheme": "Ed25519",
                "secret": "c5aa8df43f9f837bedb7442f31dcb7b1"
                "66d38535076f094b85ce3a2e0b4458f7",
                "public": "fc51cd8e6218a1a38da47ed00230f058"
                "0816ed13ba3303ac5deb911548908025",
                "message": "af82",
                "signature": "6291d657deec24024827e69c3abe01a3"
                "0ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc659"
                "4a7c15e9716ed28dc027beceea1ec40a",
            },
            # Ed25519ctx
            {
                "scheme": "Ed25519ctx",
                "secret": "0305334e381af78f141cb666f6199f57"
                "bc3495335a256a95bd2a55bf546663f6",
                "public": "dfc9425e4f968f7f0c29f0259cf5f9ae"
                "d6851c2bb4ad8bfb860cfee0ab248292",
                "message": "f726936d19c800494e3fdaff20b276a8",
                "context": "666f6f",
                "signature": "55a4cc2f70a54e04288c5f4cd1e45a7b"
                "b520b36292911876cada7323198dd87a"
                "8b36950b95130022907a7fb7c4e9b2d5"
                "f6cca685a587b4b21f4b888e4e7edb0d",
            },
            # Ed25519ph
            {
                "scheme": "Ed25519ph",
                "secret": "833fe62409237b9d62ec77587520911e"
                "9a759cec1d19755b7da901b96dca3d42",
                "public": "ec172b93ad5e563bf4932c70e1245034"
                "c35467ef2efd4d64ebf819683467e2bf",
                "message": "616263",
                "signature": "98a70222f0b8121aa9d30f813d683f80"
                "9e462b469c7ff87639499bb94e6dae41"
                "31f85042463c2a355a2003d062adf5aa"
                "a10b8c61e636062aaad11c2a26083406",
            },
            # Ed448
            {
                "scheme": "Ed448",
                "secret": "c4eab05d357007c632f3dbb48489924d"
                "552b08fe0c353a0d4a1f00acda2c463a"
                "fbea67c5e8d2877c5e3bc397a659949e"
                "f8021e954e0a12274e",
                "public": "43ba28f430cdff456ae531545f7ecd0a"
                "c834a55d9358c0372bfa0c6c6798c086"
                "6aea01eb00742802b8438ea4cb82169c"
                "235160627b4c3a9480",
                "message": "03",
                "context": "666f6f",
                "signature": "d4f8f6131770dd46f40867d6fd5d5055"
                "de43541f8c5e35abbcd001b32a89f7d2"
                "151f7647f11d8ca2ae279fb842d60721"
                "7fce6e042f6815ea000c85741de5c8da"
                "1144a6a1aba7f96de42505d7a7298524"
                "fda538fccbbb754f578c1cad10d54d0d"
                "5428407e85dcbc98a49155c13764e66c"
                "3c00",
            },
            # Ed448ph
            {
                "scheme": "Ed448ph",
                "secret": "833fe62409237b9d62ec77587520911e"
                "9a759cec1d19755b7da901b96dca3d42"
                "ef7822e0d5104127dc05d6dbefde69e3"
                "ab2cec7c867c6e2c49",
                "public": "259b71c19f83ef77a7abd26524cbdb31"
                "61b590a48f7d17de3ee0ba9c52beb743"
                "c09428a131d6b1b57303d90d8132c276"
                "d5ed3d5d01c0f53880",
                "message": "616263",
                "context": "666f6f",
                "signature": "c32299d46ec8ff02b54540982814dce9"
                "a05812f81962b649d528095916a2aa48"
                "1065b1580423ef927ecf0af5888f90da"
                "0f6a9a85ad5dc3f280d91224ba9911a3"
                "653d00e484e2ce232521481c8658df30"
                "4bb7745a73514cdb9bf3e15784ab7128"
                "4f8d0704a608c54a6b62d97beb511d13"
                "2100",
            },
        ]

        def verify_test_vector(t):
            curve = self.schemes[t["scheme"]][0]
            phflag = self.schemes[t["scheme"]][1]
            ec_params = PrivateKeyAlgorithmId(curve).dump()
            ec_point = OctetString(binascii.unhexlify(t["public"])).dump()

            ec_public_tmpl = self.ec_public_tmpl + [
                (PyKCS11.CKA_EC_PARAMS, ec_params),
                (PyKCS11.CKA_EC_POINT, ec_point),
            ]
            ec_priv_tmpl = self.ec_priv_tmpl + [
                (PyKCS11.CKA_EC_PARAMS, ec_params),
                (PyKCS11.CKA_VALUE, binascii.unhexlify(t["secret"])),
            ]

            prk = self.session.createObject(ec_priv_tmpl)
            pbk = self.session.createObject(ec_public_tmpl)

            if "context" in t:
                context = binascii.unhexlify(t["context"])
                mech = self._get_eddsa_mechanism(phflag, context)
            else:
                mech = self._get_eddsa_mechanism(phflag)

            message = binascii.unhexlify(t["message"])
            signature = self.session.sign(prk, message, mech)
            signatureStr = binascii.hexlify(bytes(signature)).decode("ascii")
            self.assertSequenceEqual(signatureStr, t["signature"])
            self.assertTrue(self.session.verify(pbk, message, signature, mech))

            self.session.destroyObject(prk)
            self.session.destroyObject(pbk)

        for t in test_vectors:
            with self.subTest(t=t):
                if (
                    self.manufacturer.startswith("SoftHSM")
                    and not "Ed25519" == t["scheme"]
                ):
                    # SoftHSM just silently ignores CK_EDDSA_PARAMS,
                    # which means that the only supported scheme is Ed25519
                    self.skipTest(
                        f"SoftHSM does not support {t['scheme']} signature scheme"
                    )
                verify_test_vector(t)

#!/usr/bin/env python

from PyKCS11 import *
import binascii

pkcs11 = PyKCS11Lib()
pkcs11.load("p11.framework/p11")

# get 3rd slot
slot = pkcs11.getSlotList()[2]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("22222222")

# key ID in hex (has to be tuple, that's why trailing comma)
keyID = (0x44,)

# "Hello world" in hex
toSign = "48656c6c6f20776f726c640d0a"

# find private key and compute signature
privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)])[0];
signature = session.sign(privKey, binascii.unhexlify(toSign), Mechanism(CKM_SHA1_RSA_PKCS, None))
print "\nsignature: " + binascii.hexlify(bytearray(signature))

# logout
session.logout()
session.closeSession()

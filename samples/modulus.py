#!/usr/bin/env python

from PyKCS11 import *
import binascii

pkcs11 = PyKCS11Lib()
pkcs11.load("p11.framework/p11")

# get 2nd slot
slot = pkcs11.getSlotList()[1]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("11111111")

# key ID in hex (has to be tuple, that's why trailing comma)
keyID = (0x11,)

# find public key and print modulus
pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, keyID)])[0]
modulus = session.getAttributeValue(pubKey, [CKA_MODULUS])[0]
print "\nmodulus: " + binascii.hexlify(bytearray(modulus))

# logout
session.logout()
session.closeSession()

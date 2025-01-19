#!/usr/bin/env python3

#   Copyright (C) 2015 Roman Pasechnik
#   Copyright (C) 2018 Ludovic Rousseau
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

import binascii

from PyKCS11 import *

pkcs11 = PyKCS11Lib()
pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib

# get 1st slot
slot = pkcs11.getSlotList(tokenPresent=True)[0]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1234")

# message to sign
toSign = "Hello World!"
mechanism = Mechanism(CKM_SHA256_RSA_PKCS, None)

# find first private key and compute signature
privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])[0]
signature = session.sign(privKey, toSign, mechanism)
print(f"\nsignature: {binascii.hexlify(bytearray(signature))}")

# find first public key and verify signature
pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]
result = session.verify(pubKey, toSign, signature, mechanism)
print("\nVerified:", result)

# logout
session.logout()
session.closeSession()

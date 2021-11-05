#!/usr/bin/env python3

#   Copyright (C) 2015 Roman Pasechnik
#   Copyright (C) 2018 Ludovic Rousseau
#   Copyright (C) 2019 Atte Pellikka
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

from __future__ import print_function

from PyKCS11 import *
import binascii

pkcs11 = PyKCS11Lib()
pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib

# get 1st slot
slot = pkcs11.getSlotList(tokenPresent=True)[0]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1234")

priv_search_tmpl = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_ECDSA)]
pub_search_tmpl = [(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_ECDSA)]

# "Hello world" in hex
toSign = "48656c6c6f20776f726c640d0a"
mechanism = Mechanism(CKM_ECDSA, None)

# find first private key and compute signature
privKey = session.findObjects(priv_search_tmpl)[0]
signature = session.sign(privKey, binascii.unhexlify(toSign), mechanism)
print("\nsignature: {}".format(binascii.hexlify(bytearray(signature))))

# find first public key and verify signature
pubKey = session.findObjects(pub_search_tmpl)[0]
result = session.verify(pubKey, binascii.unhexlify(toSign), signature, mechanism)
print("\nVerified:", result)

# logout
session.logout()
session.closeSession()

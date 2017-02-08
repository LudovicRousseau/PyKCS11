#!/usr/bin/env python

#   Copyright (C) 2015 Roman Pasechnik
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

# get 2nd slot
slot = pkcs11.getSlotList()[1]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1234")

# "Hello world" in hex
message = "48656c6c6f20776f726c640d0a"

# get first public and private keys
pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY)])[0]
privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])[0]
enc = session.encrypt(pubKey, binascii.unhexlify(message))
dec = session.decrypt(privKey, enc)

print("\nmessage: " + message)
print("\nencrypted: " + binascii.hexlify(bytearray(enc)))
print("\ndecrypted: " + bytearray(dec))

# logout
session.logout()
session.closeSession()

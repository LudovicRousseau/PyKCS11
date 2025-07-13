#!/usr/bin/env python3

"""
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
"""

import PyKCS11

# the key_id has to be the same for both objects
key_id = (0x22,)

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib

# get 1st slot
slot = pkcs11.getSlotList(tokenPresent=True)[0]

session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
session.login("1234")

pubTemplate = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    (PyKCS11.CKA_MODULUS_BITS, 0x0400),
    (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
    (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_LABEL, "My Public Key"),
    (PyKCS11.CKA_ID, key_id),
]

privTemplate = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_ID, key_id),
]

(pubKey, privKey) = session.generateKeyPair(pubTemplate, privTemplate)

# logout
session.logout()
session.closeSession()

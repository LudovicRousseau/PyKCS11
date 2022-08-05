#!/usr/bin/env python3

#   Copyright (C) 2019 Atte Pellikka <atte.pellikka@gmail.com>
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

from PyKCS11 import *
from asn1crypto.keys import ECDomainParameters, NamedCurve

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load()

slot = pkcs11.getSlotList(tokenPresent=True)[0]

session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
session.login("1234")

key_id = (0x22,)
label = "test"

# Select the curve to be used for the keys
curve = u"secp256r1"

# Setup the domain parameters, unicode conversion needed for the curve string
domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
ec_params = domain_params.dump()

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
    (PyKCS11.CKA_ID, key_id),
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
    (PyKCS11.CKA_ID, key_id),
]

(pub_key, priv_key) = session.generateKeyPair(
    ec_public_tmpl, ec_priv_tmpl, mecha=PyKCS11.MechanismECGENERATEKEYPAIR
)

session.logout()
session.closeSession()

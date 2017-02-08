#!/usr/bin/env python

#   contributed by Alex Railean, a dot railean at dekart.com
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

pkcs11 = PyKCS11Lib()
pkcs11.load()  # define environment variable PYKCS11LIB=YourPKCS11Lib

slot = 0  # adjust this if you have more readers
session = pkcs11.openSession(slot, PyKCS11.CKF_RW_SESSION)

pin = '1111'
session.login(pin, PyKCS11.CKU_USER)


# ############   key-pair generation    ##########################
# The first step in the process is to create the key-templates. See PKCS#11
# `10.8 Public key objects` to learn which attributes are available. Section
# 10.9 covers private keys.
label = 'pkcs_is_fun'  # just a label for identifying objects
key_length = 2048  # key-length in bits

# the key_id has to be the same for both objects, it will also be necessary
# when importing the certificate, to ensure it is linked with these keys.
key_id = '\x01'

public_template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
    (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
    (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_LABEL, label),
    (PyKCS11.CKA_MODULUS_BITS, key_length),
    (PyKCS11.CKA_ID, key_id),
]


private_template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_LABEL, label),
    (PyKCS11.CKA_ID, key_id),
    ]

session.generateKeyPair(public_template, private_template)
# ############# the keys were generated and stored on the card ###############


# At this point your keys are in the card, the private key is marked as
# non-exportable.
# To add a certificate, you have to prepare a CSR in PKCS#10 format and sign
# it with the key.
# It can be done with OpenSSL by typing the commands below in a terminal
# 1. openssl
# 2. engine dynamic -pre SO_PATH:/usr/lib/engines/engine_pkcs11.so -pre ID:pkcs11 -pre LIST_ADD:1 -pre LOAD -pre MODULE_PATH:libacospkcs11.so
# 3. req -engine pkcs11 -keyform engine -key 0:1 -new -text -out /tmp/newcert.csr -subj "/O=users/CN=Test User"
# Note that `-key 0:1` means "use slot 0, with key id 1"
# The CSR will be printed to stdout and saved to /tmp/newcert.csr


# The CSR is sent to a CA, which will issue a certificate and send it back.
# Once you have the certificate, it has to be converted to BER (if it isn't
# already). It will be assumed that the raw data of the certificate are in
# `cert`.

cert = 'replace this with the raw certificate itself'


# keep in mind that certain elements, such as the subject, must not be
# passed as a string, but as an ASN1-encoded structure. Consider using
# pyasn1 to do that, see http://pyasn1.sourceforge.net/
cert_template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
    (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
    (PyKCS11.CKA_LABEL, label),
    (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
    (PyKCS11.CKA_TRUSTED, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
    (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_MODIFIABLE, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_VALUE, cert),  # must be BER-encoded

    (PyKCS11.CKA_SUBJECT, subject),  # must be set and DER, see Table 24, X.509 Certificate Object Attributes
    (PyKCS11.CKA_ID, key_id)  # must be set, and DER see Table 24, X.509 Certificate Object Attributes
    ]


# logout
session.logout()
session.closeSession()


# At this point the certificate is on the card too. Some GUI tools
# might display it as invalid, in that case make sure that the
# entire certificate chain is available in the certificate store.

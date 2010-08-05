#!/usr/bin/env python

#   Copyright (C) 2006-2008 Ludovic Rousseau (ludovic.rousseau@free.fr)
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

import PyKCS11
import getopt
import sys
import platform

# from http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812
# Title: Hex dumper
# Submitter: Sebastien Keim (other recipes)
# Last Updated: 2002/08/05
# Version no: 1.0


def hexx(intval):
    x = hex(intval)[2:]
    if (x[-1:].upper() == 'L'):
        x = x[:-1]
    if len(x) % 2 != 0:
        return "0%s" % x
    return x


def dump(src, length=8):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    N = 0
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
        N += length
    return result


def usage():
    print "Usage:", sys.argv[0],
    print "[-p pin][--pin=pin]",
    print "[-c lib][--lib=lib]",
    print "[-S][--sign]",
    print "[-d][--decrypt]",
    print "[-h][--help]",

try:
    opts, args = getopt.getopt(sys.argv[1:], "p:c:Sd:h", ["pin=", "lib=", "sign", "decrypt", "help"])
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)

pin_available = False
decrypt = sign = False
lib = None
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-p", "--pin"):
        pin = a
        pin_available = True
    elif o in ("-c", "--lib"):
        lib = a
        print "using PKCS11 lib:", lib
    elif o in ("-S", "--sign"):
        sign = True
    elif o in ("-d", "--decrypt"):
        decrypt = True

red = blue = magenta = normal = ""
if sys.stdout.isatty() and platform.system().lower() != 'windows':
    red = "\x1b[01;31m"
    blue = "\x1b[34m"
    magenta = "\x1b[35m"
    normal = "\x1b[0m"

format_long = magenta + "  %s:" + blue + " %s (%s)" + normal
format_binary = magenta + "  %s:" + blue + " %d bytes" + normal
format_normal = magenta + "  %s:" + blue + " %s" + normal

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
info = pkcs11.getInfo()
print "Library manufacturerID: " + info.manufacturerID

slots = pkcs11.getSlotList()
print "Available Slots:", len(slots)

for s in slots:
    try:
        i = pkcs11.getSlotInfo(s)
        print "Slot no:", s
        print format_normal % ("slotDescription", i.slotDescription.strip())
        print format_normal % ("manufacturerID", i.manufacturerID.strip())

        t = pkcs11.getTokenInfo(s)
        print "TokenInfo"
        print format_normal % ("label", t.label.strip())
        print format_normal % ("manufacturerID", t.manufacturerID.strip())
        print format_normal % ("model", t.model.strip())

        session = pkcs11.openSession(s)
        print "Opened session 0x%08X" % session.session.value()
        if pin_available:
            try:
                session.login(pin=pin)
            except:
                print "login failed, exception:", str(sys.exc_info()[1])

        objects = session.findObjects()
        print
        print "Found %d objects: %s" % (len(objects), [x.value() for x in objects])

        all_attributes = PyKCS11.CKA.keys()
        # remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
        # their values and will get an exception instead
        all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
        all_attributes.remove(PyKCS11.CKA_PRIME_1)
        all_attributes.remove(PyKCS11.CKA_PRIME_2)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
        all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
        all_attributes.remove(PyKCS11.CKA_COEFFICIENT)
        # only use the integer values and not the strings like 'CKM_RSA_PKCS'
        all_attributes = [e for e in all_attributes if isinstance(e, int)]

        for o in objects:
            print
            print (red + "==================== Object: %d ====================" + normal) % o.value()
            attributes = session.getAttributeValue(o, all_attributes)
            attrDict = dict(zip(all_attributes, attributes))
            if attrDict[PyKCS11.CKA_CLASS] == PyKCS11.CKO_PRIVATE_KEY \
               and attrDict[PyKCS11.CKA_KEY_TYPE] == PyKCS11.CKK_RSA:
                m = attrDict[PyKCS11.CKA_MODULUS]
                e = attrDict[PyKCS11.CKA_PUBLIC_EXPONENT]
                if m and e:
                    mx = eval('0x%s' % ''.join(chr(c) for c in m).encode('hex'))
                    ex = eval('0x%s' % ''.join(chr(c) for c in e).encode('hex'))
                if sign:
                    try:
                        toSign = "12345678901234567890"  # 20 bytes, SHA1 digest
                        print "* Signing with object 0x%08X following data: %s" % (o.value(), toSign)
                        signature = session.sign(o, toSign)
                        s = ''.join(chr(c) for c in signature).encode('hex')
                        sx = eval('0x%s' % s)
                        print "Signature:"
                        print dump(''.join(map(chr, signature)), 16)
                        if m and e:
                            print "Verifying using following public key:"
                            print "Modulus:"
                            print dump(''.join(map(chr, m)), 16)
                            print "Exponent:"
                            print dump(''.join(map(chr, e)), 16)
                            decrypted = pow(sx, ex, mx)  # RSA
                            print "Decrypted:"
                            d = hexx(decrypted).decode('hex')
                            print dump(d, 16)
                            if toSign == d[-20:]:
                                print "*** signature VERIFIED!\n"
                            else:
                                print "*** signature NOT VERIFIED; decrypted value:"
                                print hex(decrypted), "\n"
                        else:
                            print "Unable to verify signature: MODULUS/PUBLIC_EXP not found"
                    except:
                        print "Sign failed, exception:", str(sys.exc_info()[1])
                if decrypt:
                    if m and e:
                        try:
                            toEncrypt = "12345678901234567890"
                            # note: PKCS1 BT2 padding should be random data,
                            # but this is just a test and we use 0xFF...
                            padded = "\x00\x02%s\x00%s" % ("\xFF" * (128 - (len(toEncrypt)) - 3), toEncrypt)
                            print "* Decrypting with 0x%08X following data: %s" % (o.value(), toEncrypt)
                            print "padded:\n", dump(padded, 16)
                            encrypted = pow(eval('0x%sL' % padded.encode('hex')), ex, mx)  # RSA
                            encrypted1 = hexx(encrypted).decode('hex')
                            print "encrypted:\n", dump(encrypted1, 16)
                            decrypted = session.decrypt(o, encrypted1)
                            decrypted1 = ''.join(chr(i) for i in decrypted)
                            print "decrypted:\n", dump(decrypted1, 16)
                            if decrypted1 == toEncrypt:
                                print "decryption SUCCESSFULL!\n"
                            else:
                                print "decryption FAILED!\n"
                        except:
                            print "Decrypt failed, exception:", str(sys.exc_info()[1])
                    else:
                        print "ERROR: Private key don't have MODULUS/PUBLIC_EXP"

            print "Dumping attributes:"
            for q, a in zip(all_attributes, attributes):
                if a == None:
                    # undefined (CKR_ATTRIBUTE_TYPE_INVALID) attribute
                    continue
                if q == PyKCS11.CKA_CLASS:
                    print format_long % (PyKCS11.CKA[q], PyKCS11.CKO[a], a)
                elif q == PyKCS11.CKA_CERTIFICATE_TYPE:
                    print format_long % (PyKCS11.CKA[q], PyKCS11.CKC[a], a)
                elif q == PyKCS11.CKA_KEY_TYPE:
                    print format_long % (PyKCS11.CKA[q], PyKCS11.CKK[a], a)
                elif session.isBin(q):
                    print format_binary % (PyKCS11.CKA[q], len(a))
                    if a:
                        print dump(''.join(map(chr, a)), 16),
                elif q == PyKCS11.CKA_SERIAL_NUMBER:
                    print format_binary % (PyKCS11.CKA[q], len(a))
                    if a:
                        print dump(a, 16),
                else:
                    print format_normal % (PyKCS11.CKA[q], a)
        print

        if pin_available:
            try:
                session.logout()
            except:
                print "logout failed, exception:", str(sys.exc_info()[1])

        session.closeSession()

    except PyKCS11.PyKCS11Error, e:
        print "Error:", e

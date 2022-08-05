#!/usr/bin/env python3

#   Copyright (C) 2006-2014 Ludovic Rousseau (ludovic.rousseau@free.fr)
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

import PyKCS11
import binascii
import getopt
import sys
import platform

# from http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812
# Title: Hex dumper
# Submitter: Sebastien Keim (other recipes)
# Last Updated: 2002/08/05
# Version no: 1.0


def dump(src, length=16):
    def to_ascii(x):
        if x >= 32 and x <= 127:
            return chr(x)
        else:
            return '.'
    N = 0
    result = ""
    while src:
        s, src = src[:length], src[length:]
        text_hexa = " ".join(["%02X" % x for x in s])
        text_ascii = "".join(map(to_ascii , s))
        result += "%04X   %-*s   %s\n" % (N, length * 3, text_hexa, text_ascii)
        N += length
    return result


def usage():
    print("Usage:", sys.argv[0], end=" ")
    print("[-a][--all]", end=" ")
    print("[-p pin][--pin=pin] (use --pin=NULL for pinpad)", end=" ")
    print("[-c lib][--lib=lib]", end=" ")
    print("[-s slot][--slot=slot]", end=" ")
    print("[-h][--help]", end=" ")
    print()


try:
    opts, args = getopt.getopt(
        sys.argv[1:],
        "p:c:Sdhs:a",
        ["pin=", "lib=", "slot=", "help", "all"],
    )
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)

pin_available = False
lib = None
slot = None
token_present = True
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    elif o in ("-p", "--pin"):
        pin = a
        if pin == "NULL":
            pin = None
        pin_available = True
    elif o in ("-c", "--lib"):
        lib = a
        print("using PKCS11 lib:", lib)
    elif o in ("-s", "--slot"):
        slot = int(a)
    if o in ("-a", "--all"):
        token_present = False

red = blue = magenta = normal = ""
if sys.stdout.isatty() and platform.system().lower() != "windows":
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
print("Library manufacturerID:", info.manufacturerID)

slots = pkcs11.getSlotList(token_present)
print("Available Slots:", len(slots), slots)

if slot is not None:
    slots = [slots[slot]]
    print("Using slot:", slots[0])

for s in slots:
    try:
        i = pkcs11.getSlotInfo(s)
        print("Slot no:", s)
        print(format_normal % ("slotDescription", i.slotDescription.strip()))
        print(format_normal % ("manufacturerID ", i.manufacturerID.strip()))
        print(format_normal % ("hardwareVersion", i.hardwareVersion))
        print(format_normal % ("firmwareVersion", i.firmwareVersion))
        print(format_normal % ("flags          ", ", ".join(i.flags2text())))

        if not (i.flags & PyKCS11.CKF_TOKEN_PRESENT):
            print("  Token not present")
            continue

        t = pkcs11.getTokenInfo(s)
        print("TokenInfo")
        print(format_normal % ("label", t.label.strip()))
        print(format_normal % ("manufacturerID", t.manufacturerID.strip()))
        print(format_normal % ("model", t.model.strip()))

        session = pkcs11.openSession(s)
        print("Opened session 0x%08X" % session.session.value())
        if pin_available:
            try:
                if (pin is None) and (
                    PyKCS11.CKF_PROTECTED_AUTHENTICATION_PATH & t.flags
                ):
                    print("\nEnter your PIN for %s on the pinpad" % t.label.strip())
                session.login(pin=pin)
            except PyKCS11.PyKCS11Error as e:
                print("login failed, exception:", e)
                break

        objects = session.findObjects()
        print()
        print("Found %d objects: %s" % (len(objects), [x.value() for x in objects]))

        all_attributes = list(PyKCS11.CKA.keys())
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

        n_obj = 1
        for o in objects:
            print()
            print(
                (
                    red
                    + "==================== Object: %d/%d (%d) ===================="
                    + normal
                )
                % (n_obj, len(objects), o.value())
            )
            n_obj += 1
            try:
                attributes = session.getAttributeValue(o, all_attributes)
            except PyKCS11.PyKCS11Error as e:
                print("getAttributeValue failed:", e)
                continue
            attrDict = dict(list(zip(all_attributes, attributes)))

            print("Dumping attributes:")
            for q, a in zip(all_attributes, attributes):
                if a is None:
                    # undefined (CKR_ATTRIBUTE_TYPE_INVALID) attribute
                    continue
                if q == PyKCS11.CKA_CLASS:
                    print(format_long % (PyKCS11.CKA[q], PyKCS11.CKO[a], a))
                elif q == PyKCS11.CKA_CERTIFICATE_TYPE:
                    print(format_long % (PyKCS11.CKA[q], PyKCS11.CKC[a], a))
                elif q == PyKCS11.CKA_KEY_TYPE:
                    print(format_long % (PyKCS11.CKA[q], PyKCS11.CKK[a], a))
                elif session.isBin(q):
                    print(format_binary % (PyKCS11.CKA[q], len(a)))
                    if a:
                        print(dump(a), end="")
                elif q == PyKCS11.CKA_SERIAL_NUMBER:
                    print(format_binary % (PyKCS11.CKA[q], len(a)))
                    if a:
                        print(dump(a), end="")
                else:
                    print(format_normal % (PyKCS11.CKA[q], a))
        print()

        if pin_available:
            try:
                session.logout()
            except PyKCS11.PyKCS11Error as e:
                print("logout failed, exception:", e)
                break

        session.closeSession()

    except PyKCS11.PyKCS11Error as e:
        print("Error:", e)
        raise

#!/usr/bin/env python

#   Copyright (C) 2006 Ludovic Rousseau (ludovic.rousseau@free.fr)
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

import PyKCS11
import getopt, sys

# from http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/142812
# Title: Hex dumper
# Submitter: Sebastien Keim (other recipes)
# Last Updated: 2002/08/05
# Version no: 1.0 

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length = 8):
    N=0; result=''
    while src:
        s,src = src[:length],src[length:]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
        N += length
    return result

def usage():
    print "Usage:", sys.argv[0],
    print "[-p pin][--pin=pin]",
    print "[-c lib][--lib=lib]",
    print "[-h][--help]",

try:
    opts, args = getopt.getopt(sys.argv[1:], "p:c:h", ["pin=", "lib=", "help"])
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)

pin_available = False
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    if o in ("-p", "--pin"):
        pin = a
        pin_available = True
    if o in ("-d", "--lib"):
        lib = a

red = blue = magenta = normal = ""
if sys.stdout.isatty():
    red = "\x1b[01;31m"
    blue = "\x1b[34m"
    magenta = "\x1b[35m"
    normal = "\x1b[0m"

format_long   = magenta + "  %s:" + blue + " %s (%s)" + normal
format_binary = magenta + "  %s:" + blue + " %d bytes" + normal
format_normal = magenta + "  %s:" + blue + " %s" + normal

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load()
info = pkcs11.getInfo()
print "Library manufacturerID: " + info.manufacturerID

slots = pkcs11.getSlotList()
print "Available Slots:", len(slots)

for s in slots:
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
    if pin_available:
        session.login(pin = pin)

    objects = session.findObjects()
    print
    print "Found %d objects: %s" % (len(objects), objects)

    all_attributes = PyKCS11.CKA.keys()
    # remove the CKR_ATTRIBUTE_SENSITIVE attributes since we can't get
    # their values and will get an exception instead
    all_attributes.remove(PyKCS11.CKA_PRIVATE_EXPONENT)
    all_attributes.remove(PyKCS11.CKA_PRIME_1)
    all_attributes.remove(PyKCS11.CKA_PRIME_2)
    all_attributes.remove(PyKCS11.CKA_EXPONENT_1)
    all_attributes.remove(PyKCS11.CKA_EXPONENT_2)
    all_attributes.remove(PyKCS11.CKA_COEFFICIENT)

    for o in objects:
        print
        print (red + "==================== Object: %d ====================" + normal) % o
        attributes = session.getAttributeValue(o, all_attributes)
        for q, a in zip(all_attributes, attributes):
            if a == None:
                # undefined (CKR_ATTRIBUTE_TYPE_INVALID) attribut
                continue

            if q == PyKCS11.CKA_CLASS:
                print format_long % (PyKCS11.CKA[q], PyKCS11.CKO[a], a)
            if q == PyKCS11.CKA_CERTIFICATE_TYPE:
                print format_long % (PyKCS11.CKA[q], PyKCS11.CKC[a], a)
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

    if pin_available:
        session.logout()

    session.closeSession()


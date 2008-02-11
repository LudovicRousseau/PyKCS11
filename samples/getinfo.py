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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

import PyKCS11
import getopt, sys
import platform

def usage():
    print "Usage:", sys.argv[0],
    print "[-p pin][--pin=pin]",
    print "[-s slot][--slot=slot]",
    print "[-c lib][--lib=lib]",
    print "[-h][--help]",
    print "[-o][--opensession]"

def colorize(text, arg):
    print magenta + text + blue, arg, normal

try:
    opts, args = getopt.getopt(sys.argv[1:], "p:s:c:ho", ["pin=", "slot=", "lib=", "help", "opensession"])
except getopt.GetoptError:
    # print help information and exit:
    usage()
    sys.exit(2)

slot = 0
lib = None
open_session = False
pin_available = False
for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    if o in ("-p", "--pin"):
        pin = a
        pin_available = True
        open_session = True
    if o in ("-s", "--slot"):
        slot = int(a)
    if o in ("-d", "--lib"):
        lib = a
    if o in ("-o", "--opensession"):
        open_session = True

red = blue = magenta = normal = ""
if sys.stdout.isatty() and platform.system().lower() != 'windows':
    red = "\x1b[01;31m"
    blue = "\x1b[34m"
    magenta = "\x1b[35m"
    normal = "\x1b[0m"

pkcs11 = PyKCS11.PyKCS11Lib()
try:
    pkcs11.load(lib)
    info = pkcs11.getInfo()
    colorize("Library Cryptoki Version:", "%d.%d" % info.cryptokiVersion)
    colorize("Library manufacturerID:", info.manufacturerID)
    colorize("Library flags:", info.flags)
    colorize("Library Description:", info.libraryDescription)
    colorize("Library Version:", "%d.%d" % info.libraryVersion)

    slots = pkcs11.getSlotList()
    print "Available Slots:", len(slots)

    if len(slots) == 0:
        sys.exit(2)

    i = pkcs11.getSlotInfo(slots[slot])
    print "Slot n.:", slot
    colorize("  slotDescription:", i.slotDescription.strip())
    colorize("  manufacturerID:", i.manufacturerID.strip())
    colorize("  flags:", i.flags2text())
    colorize("  hardwareVersion:", i.hardwareVersion)
    colorize("  firmwareVersion:", i.firmwareVersion)

    if open_session:
        session = pkcs11.openSession(slots[slot])

    if pin_available:
        session.login(pin = pin)

    t = pkcs11.getTokenInfo(slots[slot])
    print " TokenInfo"
    colorize("  label:", t.label.strip())
    colorize("  manufacturerID:", t.manufacturerID.strip())
    colorize("  model:", t.model.strip())
    colorize("  serialNumber:", t.serialNumber)
    colorize("  flags:", t.flags2text())
    colorize("  ulMaxSessionCount:", t.ulMaxSessionCount)
    colorize("  ulSessionCount:", t.ulSessionCount)
    colorize("  ulMaxRwSessionCount:", t.ulMaxRwSessionCount)
    colorize("  ulRwSessionCount:", t.ulRwSessionCount)
    colorize("  ulMaxPinLen:", t.ulMaxPinLen)
    colorize("  ulMinPinLen:", t.ulMinPinLen)
    colorize("  ulTotalPublicMemory:", t.ulTotalPublicMemory)
    colorize("  ulFreePublicMemory:", t.ulFreePublicMemory)
    colorize("  ulTotalPrivateMemory:", t.ulTotalPrivateMemory)
    colorize("  ulFreePrivateMemory:", t.ulFreePrivateMemory)
    colorize("  hardwareVersion:", "%d.%d" % t.hardwareVersion)
    colorize("  firmwareVersion:", "%d.%d" % t.firmwareVersion)
    colorize("  utcTime:", t.utcTime)

    m = pkcs11.getMechanismList(slots[slot])
    print "  Mechanism list: "
    for x in m:
        print "   " + blue + x + normal
        i = pkcs11.getMechanismInfo(slots[slot], x)
        colorize("    ulMinKeySize:", i.ulMinKeySize)
        colorize("    ulMaxKeySize:", i.ulMaxKeySize)
        colorize("    flags:", i.flags2text())

    if pin_available:
        session.logout()

    if open_session:
        session.closeSession()

except PyKCS11.PyKCS11Error, e:
    print "Error:", e


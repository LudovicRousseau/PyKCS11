#!/usr/bin/env python

#   Copyright (C) 2006-2010 Ludovic Rousseau (ludovic.rousseau@free.fr)
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
import platform
import sys


class getInfo(object):
    red = blue = magenta = normal = ""

    def colorize(self, text, arg):
        print self.magenta + text + self.blue, arg, self.normal

    def display(self, obj, indent=""):
        dico = obj.to_dict()
        for key in sorted(dico.keys()):
            type = obj.fields[key]
            left = indent + key + ":"
            if type == "flags":
                self.colorize(left, ", ".join(dico[key]))
            elif type == "pair":
                self.colorize(left, "%d.%d" % dico[key])
            else:
                self.colorize(left, dico[key])

    def __init__(self, lib=None):
        if sys.stdout.isatty() and platform.system().lower() != 'windows':
            self.red = "\x1b[01;31m"
            self.blue = "\x1b[34m"
            self.magenta = "\x1b[35m"
            self.normal = "\x1b[0m"

        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

    def getSlotInfo(self, slot):
        print "Slot n.:", slot
        self.display(self.pkcs11.getSlotInfo(slot), " ")

    def getTokenInfo(self, slot):
        print " TokenInfo"
        self.display(self.pkcs11.getTokenInfo(slot), "  ")

    def getMechanismInfo(self, slot):
        print "  Mechanism list: "
        m = self.pkcs11.getMechanismList(slot)
        for x in m:
            self.colorize("  ", x)
            i = self.pkcs11.getMechanismInfo(slot, x)
            if not i.flags & PyKCS11.CKF_DIGEST:
                if i.ulMinKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    self.colorize("    ulMinKeySize:", i.ulMinKeySize)
                if i.ulMaxKeySize != PyKCS11.CK_UNAVAILABLE_INFORMATION:
                    self.colorize("    ulMaxKeySize:", i.ulMaxKeySize)
            self.colorize("    flags:", ", ".join(i.flags2text()))

    def getInfo(self):
        self.display(self.pkcs11.getInfo())

    def getSessionInfo(self, slot, pin=None):
        print " SessionInfo",
        session = self.pkcs11.openSession(slot)

        if pin:
            print "(using pin: %s)" % pin
            session.login(pin)
        else:
            print

        self.display(session.getSessionInfo(), "  ")

        if pin:
            session.logout()


def usage():
    print "Usage:", sys.argv[0],
    print "[-p pin][--pin=pin]",
    print "[-s slot][--slot=slot]",
    print "[-c lib][--lib=lib]",
    print "[-h][--help]",
    print "[-o][--opensession]"

if __name__ == '__main__':
    import getopt

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:s:c:ho",
            ["pin=", "slot=", "lib=", "help", "opensession"])
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        sys.exit(2)

    slot = None
    lib = None
    pin = None
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
        if o in ("-c", "--lib"):
            lib = a
        if o in ("-o", "--opensession"):
            open_session = True

    gi = getInfo(lib)
    gi.getInfo()

    slots = gi.pkcs11.getSlotList()
    print "Available Slots:", len(slots), slots

    if len(slots) == 0:
        sys.exit(2)

    if slot:
        slots = [slots[slot]]

    for slot in slots:
        try:
            gi.getSlotInfo(slot)
            gi.getSessionInfo(slot, pin)
            gi.getTokenInfo(slot)
            gi.getMechanismInfo(slot)
        except PyKCS11.PyKCS11Error, e:
            print "Error:", e

#!/usr/bin/env python3

"""
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
"""


import getopt
import platform
import sys

import PyKCS11


# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
class getInfo:
    red = blue = magenta = normal = ""

    def colorize(self, text, arg):
        print(self.magenta + text + self.blue, arg, self.normal)

    def display(self, obj, indent=""):
        dico = obj.to_dict()
        for key in sorted(dico.keys()):
            ck_type = obj.fields[key]
            left = indent + key + ":"
            if ck_type == "flags":
                self.colorize(left, ", ".join(dico[key]))
            elif ck_type == "pair":
                p1, p2 = dico[key]
                self.colorize(left, f"{p1}.{p2}")
            else:
                self.colorize(left, dico[key])

    def __init__(self, lib=None):
        if sys.stdout.isatty() and platform.system().lower() != "windows":
            self.red = "\x1b[01;31m"
            self.blue = "\x1b[34m"
            self.magenta = "\x1b[35m"
            self.normal = "\x1b[0m"

        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

    def getSlotInfo(self, slot, slot_index, nb_slots):
        print()
        print(self.red + f"Slot {slot_index}/{nb_slots} (number {slot}):" + self.normal)
        self.display(self.pkcs11.getSlotInfo(slot), " ")

    def getTokenInfo(self, slot):
        print(" TokenInfo")
        self.display(self.pkcs11.getTokenInfo(slot), "  ")

    def getMechanismInfo(self, slot):
        print("  Mechanism list: ")
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

    def getSessionInfo(self, slot, pin=""):
        print(" SessionInfo", end=" ")
        session = self.pkcs11.openSession(slot)

        if pin != "":
            if pin is None:
                print("(using pinpad)")
            else:
                print(f"(using pin: {pin})")
            session.login(pin)
        else:
            print()

        self.display(session.getSessionInfo(), "  ")

        if pin:
            session.logout()


def usage():
    print("Usage:", sys.argv[0], end=" ")
    print("[-a][--all]", end=" ")
    print("[-p pin][--pin=pin] (use 'NULL' for pinpad)", end=" ")
    print("[-s slot][--slot=slot]", end=" ")
    print("[-c lib][--lib=lib]", end=" ")
    print("[-m][--mechanisms]", end=" ")
    print("[-h][--help]")


def main(opts):
    # pylint: disable=too-many-branches
    slot = None
    lib = None
    pin = ""
    token_present = True
    list_mechanisms = False
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        if o in ("-p", "--pin"):
            pin = a
            if pin == "NULL":
                pin = None
        if o in ("-s", "--slot"):
            slot = int(a)
        if o in ("-c", "--lib"):
            lib = a
        if o in ("-a", "--all"):
            token_present = False
        if o in ("-m", "--mechanisms"):
            list_mechanisms = True

    gi = getInfo(lib)
    gi.getInfo()

    slots = gi.pkcs11.getSlotList(token_present)
    print("Available Slots:", len(slots), slots)

    if len(slots) == 0:
        sys.exit(2)

    if slot is not None:
        slots = [slots[slot]]
        print("Using slot:", slots[0])

    slot_index = 0
    nb_slots = len(slots)
    for slot in slots:
        slot_index += 1
        try:
            gi.getSlotInfo(slot, slot_index, nb_slots)
            gi.getSessionInfo(slot, pin)
            gi.getTokenInfo(slot)
            if list_mechanisms:
                gi.getMechanismInfo(slot)
        except PyKCS11.PyKCS11Error as e:
            print("Error:", e)


if __name__ == "__main__":
    try:
        options, args = getopt.getopt(
            sys.argv[1:],
            "p:s:c:ham",
            ["pin=", "slot=", "lib=", "help", "all", "mechanisms"],
        )
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        sys.exit(2)

    main(options)

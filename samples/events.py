#!/usr/bin/env python

#   Copyright (C) 2009-2014 Ludovic Rousseau (ludovic.rousseau@free.fr)
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

import PyKCS11
import getinfo

if __name__ == '__main__':
    import getopt
    import sys

    def usage():
        print("Usage:", sys.argv[0], end=' ')
        print("[-p pin][--pin=pin]", end=' ')
        print("[-c lib][--lib=lib]", end=' ')
        print("[-h][--help]", end=' ')
        print("[-o][--opensession]")

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:c:ho",
                                   ["pin=", "lib=", "help", "opensession"])
    except getopt.GetoptError:
        # print help information and exit:
        usage()
        sys.exit(2)

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
        if o in ("-c", "--lib"):
            lib = a
        if o in ("-o", "--opensession"):
            open_session = True

    gi = getinfo.getInfo(lib)
    gi.getInfo()

    slots = gi.pkcs11.getSlotList()
    print("Available Slots:", len(slots), slots)

    if len(slots) == 0:
        sys.exit(2)

    while True:
        slot = gi.pkcs11.waitForSlotEvent()

        try:
            gi.getSlotInfo(slot)
            gi.getSessionInfo(slot, pin)
            gi.getTokenInfo(slot)
            gi.getMechanismInfo(slot)
        except PyKCS11.PyKCS11Error as e:
            print("Error:", e)

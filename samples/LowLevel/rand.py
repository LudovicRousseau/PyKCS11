#!/usr/bin/env python

#   Copyright (C) 2010-2014 Ludovic Rousseau <ludovic.rousseau@free.fr>
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 # USA.

from __future__ import print_function

import PyKCS11.LowLevel

a = PyKCS11.LowLevel.CPKCS11Lib()
info = PyKCS11.LowLevel.CK_INFO()
slotInfo = PyKCS11.LowLevel.CK_SLOT_INFO()
lib = "/usr/lib/pkcs11/opensc-pkcs11.so"
session = PyKCS11.LowLevel.CK_SESSION_HANDLE()
slotList = PyKCS11.LowLevel.ckintlist()
rand = PyKCS11.LowLevel.ckbytelist(20)
seed = PyKCS11.LowLevel.ckbytelist(5)

print("Load of " + lib + ": " + str(a.Load(lib, True)))
print("C_GetInfo: " + hex(a.C_GetInfo(info)))
print("Library manufacturerID: " + info.GetManufacturerID())
del info

print("C_GetSlotList(NULL): " + hex(a.C_GetSlotList(0, slotList)))
print("\tAvailable Slots: " + str(len(slotList)))

print("C_OpenSession(): " + hex(a.C_OpenSession(slotList[1], PyKCS11.LowLevel.CKF_RW_SESSION | PyKCS11.LowLevel.CKF_SERIAL_SESSION, session)))

print(' '.join("%02X" % i for i in seed))
print("C_SeedRandom(): " + hex(a.C_SeedRandom(session, seed)))

print("C_GenerateRandom(): " + hex(a.C_GenerateRandom(session, rand)))
print(' '.join("%02X" % i for i in rand))

print("C_CloseSession(): " + hex(a.C_CloseSession(session)))
print("C_Finalize(): " + hex(a.C_Finalize()))
print(a.Unload())

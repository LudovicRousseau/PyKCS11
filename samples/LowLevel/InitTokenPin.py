#!/usr/bin/env python

#   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
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

import PyKCS11.LowLevel

a = PyKCS11.LowLevel.CPKCS11Lib()
info = PyKCS11.LowLevel.CK_INFO()
slotInfo = PyKCS11.LowLevel.CK_SLOT_INFO()
lib = "pkcs11_lib.dll"
session = PyKCS11.LowLevel.CK_SESSION_HANDLE()
sessionInfo = PyKCS11.LowLevel.CK_SESSION_INFO()
tokenInfo = PyKCS11.LowLevel.CK_TOKEN_INFO()
slotList = PyKCS11.LowLevel.ckintlist()
pin = "123456"
puk = "12345678"
Label = "PyKCS#11 Initialized Token      "

print("Load of " + lib + ": " + str(a.Load(lib, True)))
print("C_GetInfo: " + hex(a.C_GetInfo(info)))
print("Library manufacturerID: " + info.GetManufacturerID())
del info

print("C_GetSlotList(NULL): " + hex(a.C_GetSlotList(1, slotList)))
print("\tAvailable Slots: " + str(len(slotList)))

if len(slotList) != 0:
    print("\tC_SlotInfo(): " + hex(a.C_GetSlotInfo(slotList[0], slotInfo)))

    print("\tC_GetTokenInfo(): " + hex(a.C_GetTokenInfo(slotList[0], tokenInfo)))
    print("\t\tTokenInfo: Label=" + tokenInfo.GetLabel() + ", ManufacturerID=" + tokenInfo.GetManufacturerID())
    print("\t\tTokenInfo: flags=" + hex(tokenInfo.flags) + ", Model=" + tokenInfo.GetModel())
    print("\tC_InitToken(): " + hex(a.C_InitToken(slotList[0], puk, Label)))

    print("\tC_GetTokenInfo(): " + hex(a.C_GetTokenInfo(slotList[0], tokenInfo)))
    print("\t\tTokenInfo: Label=" + tokenInfo.GetLabel() + ", ManufacturerID=" + tokenInfo.GetManufacturerID())
    print("\t\tTokenInfo: flags=" + hex(tokenInfo.flags) + ", Model=" + tokenInfo.GetModel())

    print("\tC_OpenSession(): " + hex(a.C_OpenSession(slotList[0], PyKCS11.LowLevel.CKF_SERIAL_SESSION | PyKCS11.LowLevel.CKF_RW_SESSION, session)))
    print("\t\tSession:" + str(session))
    print("\tC_GetSessionInfo(): " + hex(a.C_GetSessionInfo(session, sessionInfo)))
    print("\t\tSessionInfo: state=" + hex(sessionInfo.state) + ", flags=" + hex(sessionInfo.flags))

    print("\tC_Login(SO): " + hex(a.C_Login(session, PyKCS11.LowLevel.CKU_SO, puk)))
    print("\tC_InitPIN(): " + hex(a.C_InitPIN(session, pin)))
    print("\tC_Logout(SO): " + hex(a.C_Logout(session)))

    print("\tC_GetTokenInfo(): " + hex(a.C_GetTokenInfo(slotList[0], tokenInfo)))
    print("\t\tTokenInfo: Label=" + tokenInfo.GetLabel() + ", ManufacturerID=" + tokenInfo.GetManufacturerID())
    print("\t\tTokenInfo: flags=" + hex(tokenInfo.flags) + ", Model=" + tokenInfo.GetModel())

    print("C_Login(USER): " + hex(a.C_Login(session, PyKCS11.LowLevel.CKU_USER, pin)))
    print("C_Logout(USER): " + hex(a.C_Logout(session)))
    print("C_CloseSession(): " + hex(a.C_CloseSession(session)))

print("C_Finalize(): " + hex(a.C_Finalize()))
print(a.Unload())

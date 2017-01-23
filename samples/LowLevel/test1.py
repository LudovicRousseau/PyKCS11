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
lib = "/usr/lib/libopensc.so"
session = PyKCS11.LowLevel.CK_SESSION_HANDLE()
sessionInfo = PyKCS11.LowLevel.CK_SESSION_INFO()
tokenInfo = PyKCS11.LowLevel.CK_TOKEN_INFO()
slotList = PyKCS11.LowLevel.ckintlist()
pin = "1234"

print("Load of " + lib + ": " + str(a.Load(lib, True)))
print("C_GetInfo: " + hex(a.C_GetInfo(info)))
print("Library manufacturerID: " + info.GetManufacturerID())
del info

print("C_GetSlotList(NULL): " + hex(a.C_GetSlotList(0, slotList)))
print("\tAvailable Slots: " + str(len(slotList)))

for x in range(len(slotList)):
    print("\tC_SlotInfo(): " + hex(a.C_GetSlotInfo(slotList[x], slotInfo)))
    print("\t\tSlot N." + str(x) + ": ID=" + str(slotList[x]) + ", name='" + slotInfo.GetSlotDescription() + "'")
    print("\tC_OpenSession(): " + hex(a.C_OpenSession(slotList[x], PyKCS11.LowLevel.CKF_SERIAL_SESSION | PyKCS11.LowLevel.CKF_RW_SESSION, session)))
    print("\t\tSession:" + str(session))
    print("\tC_GetSessionInfo(): " + hex(a.C_GetSessionInfo(session, sessionInfo)))
    print("\t\tSessionInfo: state=" + hex(sessionInfo.state) + ", flags=" + hex(sessionInfo.flags))

    print("\tC_GetTokenInfo(): " + hex(a.C_GetTokenInfo(slotList[x], tokenInfo)))
    print("\t\tTokenInfo: Label=" + tokenInfo.GetLabel() + ", ManufacturerID=" + tokenInfo.GetManufacturerID())
    print("\t\tTokenInfo: flags=" + hex(tokenInfo.flags) + ", Model=" + tokenInfo.GetModel())

    print("\tC_Login(): " + hex(a.C_Login(session, PyKCS11.LowLevel.CKU_USER, pin)))
    print("\tC_Logout(): " + hex(a.C_Logout(session)))
    print("\tC_CloseSession(): " + hex(a.C_CloseSession(session)))

print("C_OpenSession(): " + hex(a.C_OpenSession(slotList[0], PyKCS11.LowLevel.CKF_RW_SESSION | PyKCS11.LowLevel.CKF_SERIAL_SESSION, session)))
print("C_Login(): " + hex(a.C_Login(session, PyKCS11.LowLevel.CKU_USER, pin)))

SearchResult = PyKCS11.LowLevel.ckobjlist(10)
SearchTemplate = PyKCS11.LowLevel.ckattrlist(2)
SearchTemplate[0].SetNum(PyKCS11.LowLevel.CKA_CLASS, PyKCS11.LowLevel.CKO_CERTIFICATE)
SearchTemplate[1].SetBool(PyKCS11.LowLevel.CKA_TOKEN, True)

print("C_FindObjectsInit: " + hex(a.C_FindObjectsInit(session, SearchTemplate)))
print("C_FindObjects: " + hex(a.C_FindObjects(session, SearchResult)))
print("C_FindObjectsFinal: " + hex(a.C_FindObjectsFinal(session)))

for x in SearchResult:
    print("object " + hex(x.value()))
    valTemplate = PyKCS11.LowLevel.ckattrlist(1)
    valTemplate[0].SetType(PyKCS11.LowLevel.CKA_ISSUER)
    # valTemplate[0].Reserve(128)
    print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, x, valTemplate)))
    print("CKA_ISSUER Len: ", valTemplate[0].GetLen())
    print("C_GetAttributeValue(): " + hex(a.C_GetAttributeValue(session, x, valTemplate)))
    binval = list(valTemplate[0].GetBin())
    print("binval=", binval)
    binval[0] = 0
    valTemplate[0].SetBin(PyKCS11.LowLevel.CKA_ISSUER, binval)
    binval = valTemplate[0].GetBin()  # list(valTemplate[0].GetBin())
    print("binval[0]=", binval[0])
    binval[0] = 0

    print("C_SetAttributeValue(): " + hex(a.C_SetAttributeValue(session, x, valTemplate)))

print("C_Logout(): " + hex(a.C_Logout(session)))
print("C_CloseSession(): " + hex(a.C_CloseSession(session)))
print("C_Finalize(): " + hex(a.C_Finalize()))
print(a.Unload())

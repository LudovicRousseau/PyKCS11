#!/usr/bin/env python

#   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
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

a = PyKCS11.CPKCS11Lib()
info = PyKCS11.CK_INFO()
slotInfo = PyKCS11.CK_SLOT_INFO()
lib = "incryptoki2.dll"
session = PyKCS11.CK_SESSION_HANDLE()
sessionInfo = PyKCS11.CK_SESSION_INFO()
tokenInfo = PyKCS11.CK_TOKEN_INFO()
slotList = PyKCS11.ckintlist()
pin = "12345678"

print "Load of " + lib + ": " + str(a.Load(lib, 1))
print "C_GetInfo: " + hex(a.C_GetInfo(info))
print "Library manufacturerID: " + info.GetManufacturerID()
del info

print "C_GetSlotList(NULL): " + hex(a.C_GetSlotList(0, slotList))
print "\tAvailable Slots: " + str(len(slotList))

for x in range(len(slotList)):
    print "\tC_SlotInfo(): " + hex(a.C_GetSlotInfo(slotList[x], slotInfo))
    print "\t\tSlot N." + str(x) + ": ID=" + str(slotList[x]) + ", name='" + slotInfo.GetSlotDescription() + "'"
    print "\tC_OpenSession(): " + hex(a.C_OpenSession(slotList[x], PyKCS11.CKF_SERIAL_SESSION|PyKCS11.CKF_RW_SESSION, session))
    print "\t\tSession:" + str(session)
    print "\tC_GetSessionInfo(): " + hex(a.C_GetSessionInfo(session, sessionInfo))
    print "\t\tSessionInfo: state=" + hex(sessionInfo.state) + ", flags=" + hex(sessionInfo.flags)

    print "\tC_GetTokenInfo(): " + hex(a.C_GetTokenInfo(slotList[x], tokenInfo))
    print "\t\tTokenInfo: Label=" + tokenInfo.GetLabel() + ", ManufacturerID=" + tokenInfo.GetManufacturerID()
    print "\t\tTokenInfo: flags=" + hex(tokenInfo.flags) + ", Model=" + tokenInfo.GetModel()
    
    print "\tC_Login(): " + hex(a.C_Login(session, PyKCS11.CKU_USER, pin))
    print "\tC_Logout(): " + hex(a.C_Logout(session))
    print "\tC_CloseSession(): " + hex(a.C_CloseSession(session))

print "C_OpenSession(): " + hex(a.C_OpenSession(slotList[0], PyKCS11.CKF_SERIAL_SESSION, session))
print "C_Login(): " + hex(a.C_Login(session, PyKCS11.CKU_USER, pin))

SearchResult = PyKCS11.ckintlist(10)
SearchTemplate = PyKCS11.ckattrlist(0)
#SearchTemplate[0].SetNum(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)
#SearchTemplate[1].SetBool(PyKCS11.CKA_TOKEN, True)

print "C_FindObjectsInit: " +  hex(a.C_FindObjectsInit(session, SearchTemplate))
print "C_FindObjects: " +  hex(a.C_FindObjects(session, SearchResult))
print "C_FindObjectsFinal: " +  hex(a.C_FindObjectsFinal(session))

attributes = [
	["CKA_CLASS", PyKCS11.CKA_CLASS],
	["CKA_TOKEN", PyKCS11.CKA_TOKEN],
	["CKA_PRIVATE", PyKCS11.CKA_PRIVATE],
	["CKA_LABEL", PyKCS11.CKA_LABEL],
	["CKA_APPLICATION", PyKCS11.CKA_APPLICATION],
	["CKA_VALUE", PyKCS11.CKA_VALUE],
	["CKA_CERTIFICATE_TYPE", PyKCS11.CKA_CERTIFICATE_TYPE],
	["CKA_ISSUER", PyKCS11.CKA_ISSUER],
	["CKA_SERIAL_NUMBER", PyKCS11.CKA_SERIAL_NUMBER],
	["CKA_KEY_TYPE", PyKCS11.CKA_KEY_TYPE],
	["CKA_SUBJECT", PyKCS11.CKA_SUBJECT],
	["CKA_ID", PyKCS11.CKA_ID],
	["CKA_SENSITIVE", PyKCS11.CKA_SENSITIVE],
	["CKA_ENCRYPT", PyKCS11.CKA_ENCRYPT],
	["CKA_DECRYPT", PyKCS11.CKA_DECRYPT],
	["CKA_WRAP", PyKCS11.CKA_WRAP],
	["CKA_UNWRAP", PyKCS11.CKA_UNWRAP],
	["CKA_SIGN", PyKCS11.CKA_SIGN],
	["CKA_SIGN_RECOVER", PyKCS11.CKA_SIGN_RECOVER],
	["CKA_VERIFY", PyKCS11.CKA_VERIFY],
	["CKA_VERIFY_RECOVER", PyKCS11.CKA_VERIFY_RECOVER],
	["CKA_DERIVE", PyKCS11.CKA_DERIVE],
	["CKA_START_DATE", PyKCS11.CKA_START_DATE],
	["CKA_END_DATE", PyKCS11.CKA_END_DATE],
	["CKA_MODULUS", PyKCS11.CKA_MODULUS],
	["CKA_MODULUS_BITS", PyKCS11.CKA_MODULUS_BITS],
	["CKA_PUBLIC_EXPONENT", PyKCS11.CKA_PUBLIC_EXPONENT],
	["CKA_PRIVATE_EXPONENT", PyKCS11.CKA_PRIVATE_EXPONENT],
	["CKA_PRIME_1", PyKCS11.CKA_PRIME_1],
	["CKA_PRIME_2", PyKCS11.CKA_PRIME_2],
	["CKA_EXPONENT_1", PyKCS11.CKA_EXPONENT_1],
	["CKA_EXPONENT_2", PyKCS11.CKA_EXPONENT_2],
	["CKA_COEFFICIENT", PyKCS11.CKA_COEFFICIENT],
	["CKA_PRIME", PyKCS11.CKA_PRIME],
	["CKA_SUBPRIME", PyKCS11.CKA_SUBPRIME],
	["CKA_BASE", PyKCS11.CKA_BASE],
	["CKA_VALUE_BITS", PyKCS11.CKA_VALUE_BITS],
	["CKA_VALUE_LEN", PyKCS11.CKA_VALUE_LEN],
	["CKA_EXTRACTABLE", PyKCS11.CKA_EXTRACTABLE],
	["CKA_LOCAL", PyKCS11.CKA_LOCAL],
	["CKA_NEVER_EXTRACTABLE", PyKCS11.CKA_NEVER_EXTRACTABLE],
	["CKA_ALWAYS_SENSITIVE", PyKCS11.CKA_ALWAYS_SENSITIVE],
	["CKA_MODIFIABLE", PyKCS11.CKA_MODIFIABLE],
	["CKA_ECDSA_PARAMS", PyKCS11.CKA_ECDSA_PARAMS],
	["CKA_EC_POINT", PyKCS11.CKA_EC_POINT],
	]

for x in SearchResult:
	print "object: " + hex(x)
	valTemplate = PyKCS11.ckattrlist(1)
	for attr in attributes:
		valTemplate[0].Reset()
		valTemplate[0].SetType(attr[1])
		# first call to get the attribute size and reserve the memory
		a.C_GetAttributeValue(session, x, valTemplate)
		# second call to get the attribute value
		rv = a.C_GetAttributeValue(session, x, valTemplate)
		if (rv == PyKCS11.CKR_OK):
			print "\t" + attr[0] + ": ",
			if (valTemplate[0].IsNum()):
				print valTemplate[0].GetNum()
			if (valTemplate[0].IsBool()):
				print valTemplate[0].GetBool()
			if (valTemplate[0].IsString()):
				print valTemplate[0].GetString()
			if (valTemplate[0].IsBin()):
				print "(" + str(valTemplate[0].GetLen()) + " bytes)",
				print map(hex, valTemplate[0].GetBin())
    
print "C_Logout(): " + hex(a.C_Logout(session))
print "C_CloseSession(): " + hex(a.C_CloseSession(session))
print "C_Finalize(): " + hex(a.C_Finalize())
print a.Unload()


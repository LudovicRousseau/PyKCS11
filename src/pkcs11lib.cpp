//   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
//   Copyright (C) 2008-2014 Ludovic Rousseau <ludovic.rousseau@free.fr>
//
// This file is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

#include "stdafx.h"
#include "pykcs11string.h"
#include "ck_attribute_smart.h"
#include "pkcs11lib.h"
#include "utility.h"
#include <stdio.h>
#include "dyn_generic.h"

CPKCS11Lib::CPKCS11Lib(void):
m_hLib(0),
m_pFunc(NULL)
{
}

CPKCS11Lib::~CPKCS11Lib(void)
{
}

CK_RV CPKCS11Lib::Load(const char* szLib)
{
	CK_RV rv;
	SYS_dyn_LoadLibrary((void**)&m_hLib, szLib);
	if (!m_hLib)
		return -1;

	CK_C_GetFunctionList pC_GetFunctionList;
	SYS_dyn_GetAddress(m_hLib, (function_ptr *)&pC_GetFunctionList, "C_GetFunctionList");
	if (!pC_GetFunctionList)
	{
		SYS_dyn_CloseLibrary((void**)&m_hLib);
		return -4;
	}
	rv = pC_GetFunctionList(&m_pFunc);
	if (CKR_OK != rv || !m_pFunc)
	{
		SYS_dyn_CloseLibrary((void**)&m_hLib);
		return rv;
	}

	rv = m_pFunc->C_Initialize(NULL);
	if (CKR_OK != rv  && CKR_CRYPTOKI_ALREADY_INITIALIZED != rv)
		return rv;

	return CKR_OK;
}

bool CPKCS11Lib::Unload()
{
	bool bRes = false;
	if (m_hLib && m_pFunc)
		m_pFunc->C_Finalize(NULL);
	if (m_hLib)
	{
		bRes = true;
		SYS_dyn_CloseLibrary((void**)&m_hLib);
	}
	m_hLib = 0;
	m_pFunc = NULL;
	return bRes;
}

/* duplicate a reference to a library */
void CPKCS11Lib::Duplicate(CPKCS11Lib *ref)
{
    m_hLib = ref->m_hLib;
    m_pFunc = ref->m_pFunc;
}

CK_RV CPKCS11Lib::C_Initialize()
{
	CK_RV rv;
	rv = m_pFunc->C_Initialize(NULL);
	return rv;
}

CK_RV CPKCS11Lib::C_Finalize()
{
	CK_RV rv;
	rv = m_pFunc->C_Finalize(NULL);

	return rv;
}

CK_RV CPKCS11Lib::C_GetInfo(CK_INFO* pInfo)
{
	CK_RV rv;
	if (!m_pFunc)
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	else
		rv = m_pFunc->C_GetInfo(pInfo);
	return rv;
}

CK_RV CPKCS11Lib::C_GetSlotList(
	unsigned char tokenPresent,
	vector<long>& slotList)
{
	CK_RV rv;

	CK_ULONG i;
	slotList.clear();
	CK_ULONG ulSlotCount;
	rv = m_pFunc->C_GetSlotList(tokenPresent, NULL, &ulSlotCount);
	if (CKR_OK == rv)
	{
		CK_SLOT_ID_PTR ck_slotList;
		ck_slotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
		rv = m_pFunc->C_GetSlotList(tokenPresent, ck_slotList, &ulSlotCount);
		if (CKR_OK == rv)
			for(i=0; i<ulSlotCount; i++)
				slotList.push_back(ck_slotList[i]);

		free(ck_slotList);
	}

	return rv;
}

CK_RV CPKCS11Lib::C_GetSlotInfo(
	CK_SLOT_ID slotID,
	CK_SLOT_INFO* pInfo)
{
	CK_RV rv;
	rv = m_pFunc->C_GetSlotInfo(slotID, pInfo);
	return rv;
}

CK_RV CPKCS11Lib::C_GetTokenInfo (
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO* pInfo)
{
	CK_RV rv;
	rv = m_pFunc->C_GetTokenInfo(slotID, pInfo);
	return rv;
}

CK_RV CPKCS11Lib::C_InitToken(
	CK_SLOT_ID slotID,
	vector<unsigned char> pin,
	const char* pLabel)
{
	CK_RV rv;
	CK_ULONG ulPinLen = 0;
	CK_BYTE* pPin = Vector2Buffer(pin, ulPinLen);
	rv = m_pFunc->C_InitToken(slotID, (CK_UTF8CHAR_PTR) pPin, ulPinLen,
		(CK_CHAR*)pLabel);
	return rv;
}

CK_RV CPKCS11Lib::C_InitPIN(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> pin)
{
	CK_RV rv;
	CK_ULONG ulPinLen = 0;
	CK_BYTE* pPin = Vector2Buffer(pin, ulPinLen);
	rv = m_pFunc->C_InitPIN(hSession, (CK_UTF8CHAR_PTR) pPin, ulPinLen);
	return rv;
}

CK_RV CPKCS11Lib::C_SetPIN(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> OldPin,
	vector<unsigned char> NewPin)
{
	CK_RV rv;
	CK_ULONG ulOldLen = 0;
	CK_BYTE* pOldPin = Vector2Buffer(OldPin, ulOldLen);
	CK_ULONG ulNewLen = 0;
	CK_BYTE* pNewPin = Vector2Buffer(NewPin, ulNewLen);
	rv = m_pFunc->C_SetPIN(hSession,
		(CK_UTF8CHAR_PTR)pOldPin, ulOldLen,
		(CK_UTF8CHAR_PTR)pNewPin, ulNewLen);
	return rv;
}

CK_RV CPKCS11Lib::C_OpenSession(
	CK_SLOT_ID slotID,
	CK_FLAGS flags,
	CK_SESSION_HANDLE& outhSession)
{
	CK_RV rv;
	rv = m_pFunc->C_OpenSession(slotID, flags, NULL, NULL, &outhSession);
	return rv;
}

CK_RV CPKCS11Lib::C_CloseSession(
	CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	rv = m_pFunc->C_CloseSession(hSession);
	return rv;
}

CK_RV CPKCS11Lib::C_CloseAllSessions(
	CK_SLOT_ID slotID)
{
	CK_RV rv;
	rv = m_pFunc->C_CloseAllSessions(slotID);
	return rv;
}

CK_RV CPKCS11Lib::C_GetSessionInfo(
	CK_SESSION_HANDLE hSession,
	CK_SESSION_INFO* pInfo)
{
	CK_RV rv;
	rv = m_pFunc->C_GetSessionInfo(hSession, pInfo);
	return rv;
}

CK_RV CPKCS11Lib::C_Login(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType,
	vector<unsigned char> pin)
{
	CK_RV rv;
	CK_ULONG ulPinLen = 0;
	CK_BYTE* pPin = Vector2Buffer(pin, ulPinLen);
	rv = m_pFunc->C_Login(hSession, userType, (CK_UTF8CHAR_PTR)pPin, ulPinLen);
	return rv;
}

CK_RV CPKCS11Lib::C_Logout(
	CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	rv = m_pFunc->C_Logout(hSession);
	return rv;
}

CK_RV CPKCS11Lib::C_CreateObject(
	CK_SESSION_HANDLE hSession,
	vector<CK_ATTRIBUTE_SMART> Template,
	CK_OBJECT_HANDLE& outhObject)
{
	CK_RV rv;
	CK_ULONG ulCount = 0;
	CK_OBJECT_HANDLE hObj = static_cast<CK_OBJECT_HANDLE>(outhObject);

	CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

	rv = m_pFunc->C_CreateObject(hSession, pTemplate, ulCount, &hObj);
	if (pTemplate)
		DestroyTemplate(pTemplate, ulCount);
	outhObject = static_cast<CK_OBJECT_HANDLE>(hObj);
	return rv;
}

CK_RV CPKCS11Lib::C_DestroyObject(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;
	rv = m_pFunc->C_DestroyObject(hSession, (CK_OBJECT_HANDLE)hObject);
	return rv;
}

CK_RV CPKCS11Lib::C_GetObjectSize(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	CK_ULONG* pulSize)
{
	CK_RV rv;
	rv = m_pFunc->C_GetObjectSize(hSession, (CK_OBJECT_HANDLE)hObject, pulSize);
	return rv;
}

CK_RV CPKCS11Lib::C_GetAttributeValue (
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	vector<CK_ATTRIBUTE_SMART> &Template)
{
	CK_RV rv;
	CK_ULONG ulCount = 0, i;
	CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

	rv = m_pFunc->C_GetAttributeValue(hSession, (CK_OBJECT_HANDLE)hObject,
		pTemplate, ulCount);
	for (i=0; i<ulCount; i++)
	{
		if (pTemplate[i].ulValueLen == ~0UL)
		{
			Template[i].ResetValue();
		}
		else
			Template[i] = CK_ATTRIBUTE_SMART(pTemplate[i].type,
				(CK_BYTE*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
	}
	if (pTemplate)
		DestroyTemplate(pTemplate, ulCount);
	return rv;
}

CK_RV CPKCS11Lib::C_SetAttributeValue(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hObject,
	vector<CK_ATTRIBUTE_SMART> Template)
{
	CK_RV rv;
	CK_ULONG ulCount = 0;
	CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

	rv = m_pFunc->C_SetAttributeValue(hSession, (CK_OBJECT_HANDLE)hObject,
		pTemplate, ulCount);
	if (pTemplate)
		DestroyTemplate(pTemplate, ulCount);
	return rv;
}

CK_RV CPKCS11Lib::C_FindObjectsInit(
	CK_SESSION_HANDLE hSession,
	vector<CK_ATTRIBUTE_SMART> &Template)
{
	CK_RV rv;
	CK_ULONG ulCount = 0;
	CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);
	rv = m_pFunc->C_FindObjectsInit(hSession, pTemplate, ulCount);
	if (pTemplate)
		DestroyTemplate(pTemplate, ulCount);
	return rv;
}

CK_RV CPKCS11Lib::C_FindObjects(
	CK_SESSION_HANDLE hSession,
	vector<CK_OBJECT_HANDLE>& objectList)
{
	CK_RV rv;
	CK_ULONG i;
	if (!objectList.size())
		return CKR_ARGUMENTS_BAD;
	CK_ULONG ulObjectsMax = (CK_ULONG) objectList.size();
	CK_ULONG ulObjects = 0;
	CK_OBJECT_HANDLE_PTR pList = new CK_OBJECT_HANDLE[ulObjectsMax];
	objectList.clear();
	rv = m_pFunc->C_FindObjects(hSession, pList, ulObjectsMax, &ulObjects);
	if (CKR_OK == rv && ulObjects)
	{
		for (i=0; i<ulObjects; i++)
			objectList.push_back(static_cast<CK_OBJECT_HANDLE>(pList[i]));
	}
	if (pList)
		delete [] pList;
	return rv;
}

CK_RV CPKCS11Lib::C_FindObjectsFinal(
	CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	rv = m_pFunc->C_FindObjectsFinal(hSession);
	return rv;
}

CK_RV CPKCS11Lib::C_EncryptInit(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = m_pFunc->C_EncryptInit(hSession, pMechanism, (CK_OBJECT_HANDLE)hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_Encrypt(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outEncryptedData)
{
	CK_RV rv;

	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outEncryptedData, ulOutDataLen);

	rv = m_pFunc->C_Encrypt(hSession, pInData, ulInDataLen, pOutData,
		&ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outEncryptedData, true);
	if (pOutData)
		delete []pOutData;
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_EncryptUpdate(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outEncryptedData)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outEncryptedData, ulOutDataLen);

	rv = m_pFunc->C_EncryptUpdate(hSession, pInData, ulInDataLen, pOutData,
		&ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outEncryptedData, true);
	if (pOutData)
		delete []pOutData;
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_EncryptFinal(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outEncryptedData)
{
	CK_RV rv;

	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outEncryptedData, ulOutDataLen);

	rv = m_pFunc->C_EncryptFinal(hSession, pOutData, &ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outEncryptedData, true);
	if (pOutData)
		delete []pOutData;
	return rv;
}

CK_RV CPKCS11Lib::C_DecryptInit(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = m_pFunc->C_DecryptInit(hSession, pMechanism, (CK_OBJECT_HANDLE)hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_Decrypt(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inEncryptedData,
	vector<unsigned char> &outData)
{
	CK_RV rv;
	if (!inEncryptedData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inEncryptedData, ulInDataLen);
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outData, ulOutDataLen);

	rv = m_pFunc->C_Decrypt(hSession, pInData, ulInDataLen, pOutData,
		&ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outData, true);
	if (pOutData)
		delete []pOutData;
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_DecryptUpdate(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inEncryptedData,
	vector<unsigned char> &outData)
{
	CK_RV rv;

	if (!inEncryptedData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inEncryptedData, ulInDataLen);
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outData, ulOutDataLen);

	rv = m_pFunc->C_DecryptUpdate(hSession, pInData, ulInDataLen, pOutData,
		&ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outData, true);
	if (pOutData)
		delete []pOutData;
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_DecryptFinal(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outData)
{
	CK_RV rv;
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outData, ulOutDataLen);

	rv = m_pFunc->C_DecryptFinal(hSession, pOutData, &ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outData, true);
	if (pOutData)
		delete []pOutData;
	return rv;
}

CK_RV CPKCS11Lib::C_DigestInit(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism)
{
	CK_RV rv;
	rv = m_pFunc->C_DigestInit(hSession, pMechanism);
	return rv;
}

CK_RV CPKCS11Lib::C_Digest(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outDigest)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outDigest, ulOutDataLen);

	rv = m_pFunc->C_Digest(hSession, pInData, ulInDataLen, pOutData,
		&ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outDigest, true);
	if (pOutData)
		delete []pOutData;
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_DigestUpdate(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);

	rv = m_pFunc->C_DigestUpdate(hSession, pInData, ulInDataLen);
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_DigestKey (
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = m_pFunc->C_DigestKey(hSession, (CK_OBJECT_HANDLE)hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_DigestFinal(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outDigest)
{
	CK_RV rv;
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outDigest, ulOutDataLen);

	rv = m_pFunc->C_DigestFinal(hSession, pOutData, &ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outDigest, true);
	if (pOutData)
		delete []pOutData;
	return rv;
}

CK_RV CPKCS11Lib::C_SignInit(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = m_pFunc->C_SignInit(hSession, pMechanism, (CK_OBJECT_HANDLE)hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_Sign(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outSignature)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outSignature, ulOutDataLen);

	rv = m_pFunc->C_Sign(hSession, pInData, ulInDataLen, pOutData,
		&ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outSignature, true);
	if (pOutData)
		delete []pOutData;
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_SignUpdate(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);

	rv = m_pFunc->C_SignUpdate(hSession, pInData, ulInDataLen);
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_SignFinal (
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outSignature)
{
	CK_RV rv;
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(outSignature, ulOutDataLen);

	rv = m_pFunc->C_SignFinal(hSession, pOutData, &ulOutDataLen);

	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, outSignature, true);
	if (pOutData)
		delete []pOutData;
	return rv;
}

CK_RV CPKCS11Lib::C_VerifyInit (
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	rv = m_pFunc->C_VerifyInit(hSession, pMechanism, (CK_OBJECT_HANDLE)hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_Verify(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> inSignature)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;
	if (!inSignature.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
	CK_ULONG ulInSignatureLen = 0;
	CK_BYTE* pInSignature = Vector2Buffer(inSignature, ulInSignatureLen);

	rv = m_pFunc->C_Verify(hSession, pInData, ulInDataLen, pInSignature,
		ulInSignatureLen);

	if (pInData)
		delete []pInData;
	if (pInSignature)
		delete []pInSignature;
	return rv;
}

CK_RV CPKCS11Lib::C_VerifyUpdate(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData)
{
	CK_RV rv;
	if (!inData.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);

	rv = m_pFunc->C_VerifyUpdate(hSession, pInData, ulInDataLen);

	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_VerifyFinal(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inSignature)
{
	CK_RV rv;
	if (!inSignature.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInSignatureLen = 0;
	CK_BYTE* pInSignature = Vector2Buffer(inSignature, ulInSignatureLen);

	rv = m_pFunc->C_VerifyFinal(hSession, pInSignature, ulInSignatureLen);

	if (pInSignature)
		delete []pInSignature;
	return rv;
}

CK_RV CPKCS11Lib::C_GenerateKey(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	vector<CK_ATTRIBUTE_SMART> Template,
	CK_OBJECT_HANDLE& outhKey)
{
	CK_RV rv;
	CK_ULONG ulCount = 0;
	CK_OBJECT_HANDLE hKey = static_cast<CK_OBJECT_HANDLE>(outhKey);
	CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

	rv = m_pFunc->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount,
		&hKey);
	if (pTemplate)
		DestroyTemplate(pTemplate, ulCount);
	outhKey = static_cast<CK_OBJECT_HANDLE>(hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_GenerateKeyPair(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	vector<CK_ATTRIBUTE_SMART> PublicKeyTemplate,
	vector<CK_ATTRIBUTE_SMART> PrivateKeyTemplate,
	CK_OBJECT_HANDLE& outhPublicKey,
	CK_OBJECT_HANDLE& outhPrivateKey)
{
	CK_RV rv;
	CK_ULONG ulPublicKeyAttributeCount = 0, ulPrivateKeyAttributeCount = 0;
	CK_OBJECT_HANDLE hPublicKey = static_cast<CK_OBJECT_HANDLE>(outhPublicKey);
	CK_OBJECT_HANDLE hPrivateKey = static_cast<CK_OBJECT_HANDLE>(outhPrivateKey);
	CK_ATTRIBUTE * pPublicKeyTemplate = AttrVector2Template(PublicKeyTemplate,
		ulPublicKeyAttributeCount);
	CK_ATTRIBUTE * pPrivateKeyTemplate = AttrVector2Template(PrivateKeyTemplate,
		ulPrivateKeyAttributeCount);

	rv = m_pFunc->C_GenerateKeyPair(hSession, pMechanism,
		pPublicKeyTemplate, ulPublicKeyAttributeCount,
		pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
		&hPublicKey,
		&hPrivateKey);
	if (pPublicKeyTemplate)
		DestroyTemplate(pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (pPrivateKeyTemplate)
		DestroyTemplate(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	outhPublicKey = static_cast<CK_OBJECT_HANDLE>(hPublicKey);
	outhPrivateKey = static_cast<CK_OBJECT_HANDLE>(hPrivateKey);
	return rv;
}

CK_RV CPKCS11Lib::C_WrapKey(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	CK_OBJECT_HANDLE hWrappingKey,
	CK_OBJECT_HANDLE hKey,
	vector<unsigned char> &WrappedKey)
{
	CK_RV rv;
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(WrappedKey, ulOutDataLen);

	rv = m_pFunc->C_WrapKey(hSession, pMechanism,
		(CK_OBJECT_HANDLE)hWrappingKey,
		(CK_OBJECT_HANDLE)hKey,
		pOutData, &ulOutDataLen);
	if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, WrappedKey, true);
	if (pOutData)
		delete []pOutData;
	return rv;
}

CK_RV CPKCS11Lib::C_UnwrapKey(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM* pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	vector<unsigned char> WrappedKey,
	vector<CK_ATTRIBUTE_SMART> Template,
	CK_OBJECT_HANDLE& outhKey)
{
	CK_RV rv;
	CK_OBJECT_HANDLE hKey = static_cast<CK_OBJECT_HANDLE>(outhKey);
	if (!WrappedKey.size())
		return CKR_ARGUMENTS_BAD;

	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(WrappedKey, ulInDataLen);
	CK_ULONG ulAttributeCount = 0;
	CK_ATTRIBUTE* pTemplate = AttrVector2Template(Template, ulAttributeCount);

	rv = m_pFunc->C_UnwrapKey(hSession,
		pMechanism,
		(CK_OBJECT_HANDLE)hUnwrappingKey,
		pInData,
		ulInDataLen,
		pTemplate,
		ulAttributeCount,
		&hKey);

	if (pInData)
		delete []pInData;
	if (pTemplate)
		DestroyTemplate(pTemplate, ulAttributeCount);
	outhKey = static_cast<CK_OBJECT_HANDLE>(hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_DeriveKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM *pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		vector<CK_ATTRIBUTE_SMART> Template,
		CK_OBJECT_HANDLE & outKey)
{
	CK_RV rv;
	CK_OBJECT_HANDLE hKey = static_cast<CK_OBJECT_HANDLE>(outKey);

	CK_ULONG ulAttributeCount = 0;
	CK_ATTRIBUTE* pTemplate = AttrVector2Template(Template, ulAttributeCount);

	rv = m_pFunc->C_DeriveKey(hSession,
		pMechanism,
		hBaseKey,
		pTemplate,
		ulAttributeCount,
		&hKey);

	if (pTemplate)
		DestroyTemplate(pTemplate, ulAttributeCount);
	outKey = static_cast<CK_OBJECT_HANDLE>(hKey);
	return rv;
}

CK_RV CPKCS11Lib::C_SeedRandom(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> Seed)
{
	CK_RV rv;
	CK_ULONG ulInDataLen = 0;
	CK_BYTE* pInData = Vector2Buffer(Seed, ulInDataLen);
	rv = m_pFunc->C_SeedRandom(hSession, pInData, ulInDataLen);
	if (pInData)
		delete []pInData;
	return rv;
}

CK_RV CPKCS11Lib::C_GenerateRandom(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &RandomData)
{
	CK_RV rv;
	CK_ULONG ulOutDataLen = 0;
	CK_BYTE* pOutData = Vector2Buffer(RandomData, ulOutDataLen);
	rv = m_pFunc->C_GenerateRandom(hSession, pOutData, ulOutDataLen);
    if (CKR_OK == rv)
		Buffer2Vector(pOutData, ulOutDataLen, RandomData, true);
	if (pOutData)
		delete []pOutData;
	return rv;
}

CK_RV CPKCS11Lib::C_WaitForSlotEvent(
	CK_FLAGS flags,
	unsigned long* pSlot)
{
	CK_RV rv;
	rv = m_pFunc->C_WaitForSlotEvent(flags, pSlot, NULL);
	return rv;
}

CK_RV CPKCS11Lib::C_GetMechanismList(
	unsigned long slotID,
	vector<long> &mechanismList)
{
	CK_RV rv;

	CK_ULONG i;
	mechanismList.clear();
	CK_MECHANISM_TYPE ck_mechanismList[1024];
	CK_ULONG ulCount = sizeof(ck_mechanismList)/sizeof(ck_mechanismList[0]);
	rv = m_pFunc->C_GetMechanismList(slotID, ck_mechanismList, &ulCount);
	if (CKR_OK == rv)
		for(i=0; i<ulCount; i++)
			mechanismList.push_back(ck_mechanismList[i]);

	return rv;
}

CK_RV CPKCS11Lib::C_GetMechanismInfo(
	unsigned long slotID,
	unsigned long type,
	CK_MECHANISM_INFO* pInfo)
{
	CK_RV rv;

	rv = m_pFunc->C_GetMechanismInfo(slotID, type, pInfo);

	return rv;
}

///////////////////////////////////////////////////////////////////////////////


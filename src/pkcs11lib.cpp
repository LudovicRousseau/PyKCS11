//   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
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
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

#include "stdafx.h"
#include "pykcs11string.h"
#include "ck_attribute_smart.h"
#include "pkcs11lib.h"
#include "utility.h"
#include <stdio.h>
#include "dyn_generic.h"

#define CPKCS11LIB_PROLOGUE(FUNCTION_NAME) \
	bool bRetryed = false; \
Retry: \
	CK_RV rv; \
	rv = CKR_OK; \
	if (!m_hLib || !m_pFunc) \
		return CKR_CRYPTOKI_NOT_INITIALIZED;

#define CPKCS11LIB_EPILOGUE if (!bRetryed && m_hLib && m_pFunc && m_bAutoInitialized && \
								CKR_CRYPTOKI_NOT_INITIALIZED == rv) { \
								 m_pFunc->C_Initialize(NULL); \
								 bRetryed=true; \
								 goto Retry; \
								}


CPKCS11Lib::CPKCS11Lib(void):
m_bFinalizeOnClose(false),
m_bAutoInitialized(false),
m_hLib(0),
m_pFunc(NULL)
{
}

CPKCS11Lib::~CPKCS11Lib(void)
{
	Unload();
}

bool CPKCS11Lib::Load(const char* szLib, bool bAutoCallInitialize)
{
	CK_RV rv;
	Unload();
	SYS_dyn_LoadLibrary((void**)&m_hLib, szLib);
	//m_hLib = LoadLibrary(szLib);
	if (!m_hLib) return false;

	CK_C_GetFunctionList pC_GetFunctionList;
	SYS_dyn_GetAddress(m_hLib, (function_ptr *)&pC_GetFunctionList, "C_GetFunctionList");
	if (!pC_GetFunctionList)
	{
		SYS_dyn_CloseLibrary((void**)&m_hLib);
		return false;
	}
	rv = pC_GetFunctionList(&m_pFunc);
	if (CKR_OK != rv || !m_pFunc)
	{
		SYS_dyn_CloseLibrary((void**)&m_hLib);
		return false;
	}

	if (bAutoCallInitialize)
	{
		CK_INFO infos;
		if (m_pFunc->C_GetInfo(&infos) == CKR_CRYPTOKI_NOT_INITIALIZED)
		{
			m_bAutoInitialized = m_bFinalizeOnClose = CKR_OK == m_pFunc->C_Initialize(NULL);
		}
		else
			m_bAutoInitialized = true;
	}
	return true;
}

bool CPKCS11Lib::Unload()
{
	bool bRes = false;
	if (m_hLib && m_pFunc && m_bFinalizeOnClose)
		m_pFunc->C_Finalize(NULL);
	if (m_hLib)
	{
		bRes = true;
		SYS_dyn_CloseLibrary((void**)&m_hLib);
	}
	m_hLib = 0;
	m_pFunc = NULL;
	m_bFinalizeOnClose = false;
	return bRes;
}

	CK_RV CPKCS11Lib:: C_Initialize()
	{
		CPKCS11LIB_PROLOGUE(C_Initialize);
		rv =  m_pFunc->C_Initialize(NULL);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_Finalize()
	{
		CPKCS11LIB_PROLOGUE(C_Finalize);
		rv =  m_pFunc->C_Finalize(NULL);
		if (CKR_OK == rv)
		{
			m_bFinalizeOnClose = false;
		}

		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_GetInfo(CK_INFO*   pInfo)
	{
		CK_RV rv;
		if (!m_pFunc)
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		else
		rv =  m_pFunc->C_GetInfo(pInfo);
		return rv;

	}

	CK_RV CPKCS11Lib::C_GetSlotList(unsigned char tokenPresent,
									vector<int>& slotList)
	{
		CPKCS11LIB_PROLOGUE(C_GetSlotList);

		CK_ULONG i;
		slotList.clear();
		CK_SLOT_ID ck_slotList[1024];
		CK_ULONG ulSlotCount = sizeof(ck_slotList)/sizeof(ck_slotList[0]);
		rv = m_pFunc->C_GetSlotList(tokenPresent, ck_slotList, &ulSlotCount);
		if (CKR_OK == rv)
			for(i=0; i< ulSlotCount; i++)
				slotList.push_back(ck_slotList[i]);

		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_GetSlotInfo
	(
	CK_SLOT_ID  slotID,
	CK_SLOT_INFO* pInfo
	)
	{
		CPKCS11LIB_PROLOGUE(C_GetSlotInfo);
		rv = m_pFunc->C_GetSlotInfo(slotID, pInfo);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}

	CK_RV CPKCS11Lib::C_GetTokenInfo
	(
	CK_SLOT_ID slotID,
	CK_TOKEN_INFO* pInfo
	)
	{
		CPKCS11LIB_PROLOGUE(C_GetTokenInfo);
		rv =  m_pFunc->C_GetTokenInfo(slotID, pInfo);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_InitToken(
	CK_SLOT_ID      slotID,
	CK_UTF8CHAR* pPin,
	CK_ULONG        ulPinLen,
	const char* pLabel)
	{
		CPKCS11LIB_PROLOGUE(C_InitToken);
		rv =  m_pFunc->C_InitToken(slotID, (CK_CHAR*)pPin, ulPinLen, (CK_CHAR*)pLabel );
		CPKCS11LIB_EPILOGUE;
		return rv;

	}



	CK_RV CPKCS11Lib::C_InitPIN
	(CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR*   pPin,
	CK_ULONG       ulPinLen)
	{
		CPKCS11LIB_PROLOGUE(C_InitPIN);
		rv =  m_pFunc->C_InitPIN(hSession, pPin, ulPinLen );
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_SetPIN
	(
	CK_SESSION_HANDLE hSession,
	CK_UTF8CHAR*   pOldPin,
	CK_ULONG          ulOldLen,
	CK_UTF8CHAR*   pNewPin,
	CK_ULONG          ulNewLen
	)
	{
		CPKCS11LIB_PROLOGUE(C_SetPIN);
		rv =  m_pFunc->C_SetPIN(hSession, pOldPin, ulOldLen,  pNewPin, ulNewLen);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_OpenSession
	(
	CK_SLOT_ID            slotID,
	CK_FLAGS              flags,
	CK_SESSION_HANDLE& outhSession
	)
	{
		CPKCS11LIB_PROLOGUE(C_OpenSession);
		rv =  m_pFunc->C_OpenSession(slotID, flags, NULL,  NULL, &outhSession);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::   C_CloseSession
	(
	CK_SESSION_HANDLE hSession
	)
	{
		CPKCS11LIB_PROLOGUE(C_CloseSession);
		rv =  m_pFunc->C_CloseSession(hSession);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_CloseAllSessions
	(
	CK_SLOT_ID     slotID
	)
	{
		CPKCS11LIB_PROLOGUE(C_CloseAllSessions);
		rv =  m_pFunc->C_CloseAllSessions(slotID);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_GetSessionInfo
	(
	CK_SESSION_HANDLE   hSession,
	CK_SESSION_INFO* pInfo
	)
	{
		CPKCS11LIB_PROLOGUE(C_GetSessionInfo);
		rv =  m_pFunc->C_GetSessionInfo(hSession, pInfo);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}



	CK_RV CPKCS11Lib::C_Login
	(
	CK_SESSION_HANDLE hSession,
	CK_USER_TYPE      userType,
	CK_UTF8CHAR*   pPin,
	CK_ULONG          ulPinLen
	)
	{
		CPKCS11LIB_PROLOGUE(C_Login);
		rv =  m_pFunc->C_Login(hSession, userType, pPin, ulPinLen);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::C_Logout
	(
	CK_SESSION_HANDLE hSession
	)
	{
		CPKCS11LIB_PROLOGUE(C_Logout);
		rv =  m_pFunc->C_Logout(hSession);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::C_CreateObject
	(
	CK_SESSION_HANDLE hSession,
	vector<CK_ATTRIBUTE_SMART> Template,
	CK_OBJECT_HANDLE& outhObject
	)
	{
		CPKCS11LIB_PROLOGUE(C_CreateObject);
		CK_ULONG ulCount = 0;

		CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

		rv = m_pFunc->C_CreateObject(hSession, pTemplate, ulCount, &outhObject);
		if (pTemplate)
			DestroyTemplate(pTemplate, ulCount);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}

	CK_RV CPKCS11Lib::   C_DestroyObject(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE  hObject)
	{
		CPKCS11LIB_PROLOGUE(C_DestroyObject);
		rv =  m_pFunc->C_DestroyObject(hSession, hObject);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::   C_GetObjectSize
		(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE  hObject,
		CK_ULONG*      pulSize)
	{
		CPKCS11LIB_PROLOGUE(C_GetObjectSize);
		rv =  m_pFunc->C_GetObjectSize(hSession, hObject, pulSize);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::C_GetAttributeValue
	(CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject,
	vector<CK_ATTRIBUTE_SMART> &Template)
	{
		CPKCS11LIB_PROLOGUE(C_GetAttributeValue);
		CK_ULONG ulCount = 0, i;
		CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

		rv = m_pFunc->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
		for (i=0; i<ulCount; i++)
		{
			if (pTemplate[i].ulValueLen == ~0UL)
			{
				Template[i].ResetValue();
			}
			else
				Template[i] = CK_ATTRIBUTE_SMART(pTemplate[i].type, (CK_BYTE*)pTemplate[i].pValue, pTemplate[i].ulValueLen);

		}
		if (pTemplate)
			DestroyTemplate(pTemplate, ulCount);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_SetAttributeValue
	(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hObject,
	vector<CK_ATTRIBUTE_SMART> Template
	)
	{
		CPKCS11LIB_PROLOGUE(C_SetAttributeValue);
		CK_ULONG ulCount = 0;
		CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

		rv = m_pFunc->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
		if (pTemplate)
			DestroyTemplate(pTemplate, ulCount);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_FindObjectsInit
	(
	CK_SESSION_HANDLE hSession,
	vector<CK_ATTRIBUTE_SMART> &Template
	)
	{
		CPKCS11LIB_PROLOGUE(C_FindObjectsInit);
		CK_ULONG ulCount = 0;
		CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);
		rv = m_pFunc->C_FindObjectsInit(hSession, pTemplate, ulCount);
		if (pTemplate)
			DestroyTemplate(pTemplate, ulCount);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}



	CK_RV CPKCS11Lib::C_FindObjects
	(
	CK_SESSION_HANDLE    hSession,
	vector<int>& objectList
	)
	{
		CPKCS11LIB_PROLOGUE(C_FindObjects);
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
			for (i=0; i < ulObjects; i++)
				objectList.push_back((int)pList[i]);
		}
		if (pList) delete [] pList;
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::C_FindObjectsFinal
	(
	CK_SESSION_HANDLE hSession
	)
	{
		CPKCS11LIB_PROLOGUE(C_FindObjectsFinal);
		rv =  m_pFunc->C_FindObjectsFinal(hSession);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}



	CK_RV CPKCS11Lib::   C_EncryptInit
	(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM*  pMechanism,
	CK_OBJECT_HANDLE  hKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_EncryptInit);
		rv =  m_pFunc->C_EncryptInit(hSession, pMechanism, hKey);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::C_Encrypt
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outEncryptedData
	)
	{
		CPKCS11LIB_PROLOGUE(C_Encrypt);

		if (!inData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outEncryptedData, ulOutDataLen);

		rv = m_pFunc->C_Encrypt(hSession, pInData, ulInDataLen, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outEncryptedData, true);
		if (pOutData) delete []pOutData;
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}



	CK_RV CPKCS11Lib::   C_EncryptUpdate
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outEncryptedData
	)
	{
		CPKCS11LIB_PROLOGUE(C_EncryptUpdate);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outEncryptedData, ulOutDataLen);

		rv = m_pFunc->C_EncryptUpdate(hSession, pInData, ulInDataLen, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outEncryptedData, true);
		if (pOutData) delete []pOutData;
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_EncryptFinal
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outEncryptedData
	)
	{
		CPKCS11LIB_PROLOGUE(C_EncryptFinal);

		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outEncryptedData, ulOutDataLen);

		rv = m_pFunc->C_EncryptFinal(hSession, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outEncryptedData, true);
		if (pOutData) delete []pOutData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::   C_DecryptInit
	(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM*  pMechanism,
	CK_OBJECT_HANDLE  hKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_DecryptInit);
		rv =  m_pFunc->C_DecryptInit(hSession, pMechanism, hKey);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_Decrypt
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inEncryptedData,
	vector<unsigned char> &outData
	)
	{
		CPKCS11LIB_PROLOGUE(C_Decrypt);
		if (!inEncryptedData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inEncryptedData, ulInDataLen);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outData, ulOutDataLen);

		rv = m_pFunc->C_Decrypt(hSession, pInData, ulInDataLen, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outData, true);
		if (pOutData) delete []pOutData;
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_DecryptUpdate
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inEncryptedData,
	vector<unsigned char> &outData
	)
	{
		CPKCS11LIB_PROLOGUE(C_DecryptUpdate);

		if (!inEncryptedData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inEncryptedData, ulInDataLen);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outData, ulOutDataLen);

		rv = m_pFunc->C_DecryptUpdate(hSession, pInData, ulInDataLen, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outData, true);
		if (pOutData) delete []pOutData;
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::   C_DecryptFinal
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outData
	)
	{
		CPKCS11LIB_PROLOGUE(C_DecryptFinal);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outData, ulOutDataLen);

		rv = m_pFunc->C_DecryptFinal(hSession, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outData, true);
		if (pOutData) delete []pOutData;
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::   C_DigestInit
	(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM*  pMechanism
	)
	{
		CPKCS11LIB_PROLOGUE(C_DigestInit);
		rv =  m_pFunc->C_DigestInit(hSession, pMechanism);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_Digest
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outDigest
	)
	{
		CPKCS11LIB_PROLOGUE(C_Digest);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outDigest, ulOutDataLen);

		rv = m_pFunc->C_Digest(hSession, pInData, ulInDataLen, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outDigest, true);
		if (pOutData) delete []pOutData;
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}

	CK_RV CPKCS11Lib::   C_DigestUpdate
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData
	)
	{
		CPKCS11LIB_PROLOGUE(C_DigestUpdate);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);

		rv = m_pFunc->C_DigestUpdate(hSession, pInData, ulInDataLen);
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::   C_DigestKey
	(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE  hKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_DigestKey);
		rv =  m_pFunc->C_DigestKey(hSession, hKey);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_DigestFinal
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outDigest
	)
	{
		CPKCS11LIB_PROLOGUE(C_DigestFinal);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outDigest, ulOutDataLen);

		rv = m_pFunc->C_DigestFinal(hSession, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outDigest, true);
		if (pOutData) delete []pOutData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_SignInit

	(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM*  pMechanism,
	CK_OBJECT_HANDLE  hKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_SignInit);
		rv =  m_pFunc->C_SignInit(hSession, pMechanism, hKey);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}

	CK_RV CPKCS11Lib::C_Sign

	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> &outSignature
	)
	{
		CPKCS11LIB_PROLOGUE(C_Sign);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outSignature, ulOutDataLen);

		rv = m_pFunc->C_Sign(hSession, pInData, ulInDataLen, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outSignature, true);
		if (pOutData) delete []pOutData;
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_SignUpdate
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData
	)
	{
		CPKCS11LIB_PROLOGUE(C_SignUpdate);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);

		rv = m_pFunc->C_SignUpdate(hSession, pInData, ulInDataLen);
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_SignFinal

	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> &outSignature
	)
	{
		CPKCS11LIB_PROLOGUE(C_SignFinal);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(outSignature, ulOutDataLen);

		rv = m_pFunc->C_SignFinal(hSession, pOutData, &ulOutDataLen);

		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, outSignature, true);
		if (pOutData) delete []pOutData;
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::C_VerifyInit

	(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM*  pMechanism,
	CK_OBJECT_HANDLE  hKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_VerifyInit);
		rv =  m_pFunc->C_VerifyInit(hSession, pMechanism, hKey);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_Verify

	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData,
	vector<unsigned char> inSignature
	)
	{
		CPKCS11LIB_PROLOGUE(C_Verify);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;
		if (!inSignature.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);
		CK_ULONG ulInSignatureLen = 0;
		CK_BYTE* pInSignature = Vector2Buffer(inData, ulInDataLen);

		rv = m_pFunc->C_Verify(hSession, pInData, ulInDataLen, pInSignature, ulInSignatureLen);

		if (pInData) delete []pInData;
		if (pInSignature) delete []pInSignature;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_VerifyUpdate

	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inData
	)
	{
		CPKCS11LIB_PROLOGUE(C_VerifyUpdate);
		if (!inData.size())
			return CKR_ARGUMENTS_BAD;


		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(inData, ulInDataLen);

		rv = m_pFunc->C_VerifyUpdate(hSession, pInData, ulInDataLen);

		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::   C_VerifyFinal

	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> inSignature
	)
	{
		CPKCS11LIB_PROLOGUE(C_VerifyFinal);
		if (!inSignature.size())
			return CKR_ARGUMENTS_BAD;


		CK_ULONG ulInSignatureLen = 0;
		CK_BYTE* pInSignature = Vector2Buffer(inSignature, ulInSignatureLen);

		rv = m_pFunc->C_VerifyFinal(hSession, pInSignature, ulInSignatureLen);

		if (pInSignature) delete []pInSignature;
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_GenerateKey

	(
	CK_SESSION_HANDLE    hSession,
	CK_MECHANISM*     pMechanism,
	vector<CK_ATTRIBUTE_SMART> Template,
	CK_OBJECT_HANDLE& outhKey
	)
	{

		CPKCS11LIB_PROLOGUE(C_GenerateKey);
		CK_ULONG ulCount = 0;

		CK_ATTRIBUTE * pTemplate = AttrVector2Template(Template, ulCount);

		rv = m_pFunc->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, &outhKey);
		if (pTemplate)
			DestroyTemplate(pTemplate, ulCount);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


	CK_RV CPKCS11Lib::   C_GenerateKeyPair
	(
	CK_SESSION_HANDLE    hSession,
	CK_MECHANISM*     pMechanism,
	vector<CK_ATTRIBUTE_SMART> PublicKeyTemplate,
	vector<CK_ATTRIBUTE_SMART> PrivateKeyTemplate,
	CK_OBJECT_HANDLE& outhPublicKey,
	CK_OBJECT_HANDLE& outhPrivateKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_GenerateKeyPair);
		CK_ULONG ulPublicKeyAttributeCount = 0, ulPrivateKeyAttributeCount=0;

		CK_ATTRIBUTE * pPublicKeyTemplate = AttrVector2Template(PublicKeyTemplate, ulPublicKeyAttributeCount);
		CK_ATTRIBUTE * pPrivateKeyTemplate = AttrVector2Template(PrivateKeyTemplate, ulPrivateKeyAttributeCount);


		rv =m_pFunc->C_GenerateKeyPair(hSession, pMechanism,
							pPublicKeyTemplate, ulPublicKeyAttributeCount,
							pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
							&outhPublicKey, &outhPrivateKey);
		if (pPublicKeyTemplate)
			DestroyTemplate(pPublicKeyTemplate, ulPublicKeyAttributeCount);
		if (pPrivateKeyTemplate)
			DestroyTemplate(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}

	CK_RV CPKCS11Lib::C_WrapKey
	(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM*  pMechanism,
	CK_OBJECT_HANDLE  hWrappingKey,
	CK_OBJECT_HANDLE  hKey,
	vector<unsigned char> &WrappedKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_WrapKey);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(WrappedKey, ulOutDataLen);

		rv = m_pFunc->C_WrapKey(hSession, pMechanism,
							hWrappingKey, hKey,
							pOutData, &ulOutDataLen);
		if (CKR_OK == rv)
			Buffer2Vector( pOutData, ulOutDataLen, WrappedKey, true);
		if (pOutData) delete []pOutData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::   C_UnwrapKey
	(
	CK_SESSION_HANDLE    hSession,
	CK_MECHANISM*     pMechanism,
	CK_OBJECT_HANDLE     hUnwrappingKey,
	vector<unsigned char> WrappedKey,
	vector<CK_ATTRIBUTE_SMART> Template,
	CK_OBJECT_HANDLE& outhKey
	)
	{
		CPKCS11LIB_PROLOGUE(C_UnwrapKey);

		if (!WrappedKey.size())
			return CKR_ARGUMENTS_BAD;

		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(WrappedKey, ulInDataLen);
		CK_ULONG ulAttributeCount = 0;
		CK_ATTRIBUTE* pTemplate = AttrVector2Template(Template, ulAttributeCount);

		rv = m_pFunc->C_UnwrapKey(hSession,
							pMechanism,
							hUnwrappingKey,
							pInData,
							ulInDataLen,
							pTemplate,
							ulAttributeCount,
							&outhKey);

		if (pInData) delete []pInData;
		if (pTemplate)
			DestroyTemplate(pTemplate, ulAttributeCount);
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::C_SeedRandom

	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> Seed
	)
	{
		CPKCS11LIB_PROLOGUE(C_SeedRandom);
		CK_ULONG ulInDataLen = 0;
		CK_BYTE* pInData = Vector2Buffer(Seed, ulInDataLen);
		rv = m_pFunc->C_SeedRandom(hSession, pInData, ulInDataLen);
		if (pInData) delete []pInData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}

	CK_RV CPKCS11Lib::C_GenerateRandom
	(
	CK_SESSION_HANDLE hSession,
	vector<unsigned char> RandomData
	)
	{
		CPKCS11LIB_PROLOGUE(C_GenerateRandom);
		CK_ULONG ulOutDataLen = 0;
		CK_BYTE* pOutData = Vector2Buffer(RandomData, ulOutDataLen);
		rv = m_pFunc->C_GenerateRandom(hSession, pOutData, ulOutDataLen);
		if (pOutData) delete []pOutData;
		CPKCS11LIB_EPILOGUE;
		return rv;
	}


	CK_RV CPKCS11Lib::   C_WaitForSlotEvent
	(
	CK_FLAGS flags,
	unsigned long* pSlot
	)
	{
		CPKCS11LIB_PROLOGUE(C_WaitForSlotEvent);
		rv =  m_pFunc->C_WaitForSlotEvent(flags, pSlot, NULL);
		CPKCS11LIB_EPILOGUE;
		return rv;

	}


///////////////////////////////////////////////////////////////////////////////////////////





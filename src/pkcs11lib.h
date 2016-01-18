//   Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
//   Copyright (C) 2008-2010 Ludovic Rousseau <ludovic.rousseau@free.fr>
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


#pragma once

#ifdef SWIG

//#define CK_OBJECT_HANDLE unsigned long
//#define CK_SESSION_HANDLE unsigned long

#else

	typedef CK_ATTRIBUTE CK_ATTRIBUTE_INTERNAL;
#ifdef WIN32
	#pragma warning(disable: 4800 4244)
#include <windows.h>
#endif
	#include <vector>

	using namespace std;

#endif

class CPKCS11Lib
{
	bool m_bFinalizeOnClose;
	bool m_bAutoInitialized;
#ifdef WIN32
	HMODULE m_hLib;
#else
	void *m_hLib;
#endif
	CK_FUNCTION_LIST* m_pFunc;

public:
	CPKCS11Lib(void);
	~CPKCS11Lib(void);
	bool Load(const char* szLib, bool bAutoCallInitialize);
	bool Unload();

	CK_RV C_Initialize();
	CK_RV C_Finalize();
	CK_RV C_GetInfo(CK_INFO* pInfo);
	CK_RV C_GetSlotList(unsigned char tokenPresent, vector<long>& slotList);

	CK_RV C_GetSlotInfo(unsigned long slotID,CK_SLOT_INFO* pInfo);

	CK_RV C_GetTokenInfo(unsigned long slotID,CK_TOKEN_INFO* pInfo);

#ifdef SWIG
%apply (char *STRING, int LENGTH) { (char* pPin, unsigned long ulPinLen),
									(char* pOldPin, unsigned long ulOldLen),
									(char* pNewPin, unsigned long ulNewLen) };
%apply (char *STRING) { (char* pLabel) };

#endif
	CK_RV C_InitToken(unsigned long slotID,
		char* pPin,
		unsigned long ulPinLen,
		const char* pLabel);

	CK_RV C_InitPIN(
		CK_SESSION_HANDLE hSession,
		char* pPin,
		unsigned long ulPinLen);

	CK_RV C_SetPIN(
		CK_SESSION_HANDLE hSession,
		char* pOldPin,
		unsigned long ulOldLen,
		char* pNewPin,
		unsigned long ulNewLen);

	CK_RV C_OpenSession(
		unsigned long slotID,
		unsigned long flags,
		CK_SESSION_HANDLE& outhSession);

	CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);

	CK_RV C_CloseAllSessions(unsigned long slotID);

	CK_RV C_GetSessionInfo(
		CK_SESSION_HANDLE hSession,
		CK_SESSION_INFO* pInfo);

	CK_RV C_Login(
		CK_SESSION_HANDLE hSession,
		unsigned long userType,
		char* pPin, unsigned long ulPinLen);
#ifdef SWIG
%clear (char* pPin, unsigned long ulPinLen),
	(char* pOldPin, unsigned long ulOldLen),
	(char* pNewPin, unsigned long ulNewLen) ;
%clear (char* pLabel);
#endif

	CK_RV C_Logout(CK_SESSION_HANDLE hSession);

	CK_RV C_CreateObject(
		CK_SESSION_HANDLE hSession,
		vector<CK_ATTRIBUTE_SMART> Template,
		CK_OBJECT_HANDLE& outhObject);

	CK_RV C_DestroyObject(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject);

	CK_RV C_GetObjectSize(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		unsigned long* pulSize);

	CK_RV C_GetAttributeValue(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		vector<CK_ATTRIBUTE_SMART> &Template);

	CK_RV C_SetAttributeValue(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		vector<CK_ATTRIBUTE_SMART> Template);

	CK_RV C_FindObjectsInit(
		CK_SESSION_HANDLE hSession,
		vector<CK_ATTRIBUTE_SMART> &Template);

	CK_RV C_FindObjects(
		CK_SESSION_HANDLE hSession,
		vector<CK_OBJECT_HANDLE> &objectsList);

	CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);

	CK_RV C_EncryptInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		CK_OBJECT_HANDLE hKey);

	CK_RV C_Encrypt(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData,
		vector<unsigned char> &outEncryptedData);

	CK_RV C_EncryptUpdate(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData,
		vector<unsigned char> &outEncryptedData);

	CK_RV C_EncryptFinal(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> &outEncryptedData);

	CK_RV C_DecryptInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		CK_OBJECT_HANDLE hKey);

	CK_RV C_Decrypt(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inEncryptedData,
		vector<unsigned char> &outData);

	CK_RV C_DecryptUpdate(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inEncryptedData,
		vector<unsigned char> &outData);

	CK_RV C_DecryptFinal(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> &outData);

	CK_RV C_DigestInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism);

	CK_RV C_Digest(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData,
		vector<unsigned char> &outDigest);

	CK_RV C_DigestUpdate(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData);

	CK_RV C_DigestKey(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hKey);

	CK_RV C_DigestFinal(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> &outDigest);

	CK_RV C_SignInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		CK_OBJECT_HANDLE hKey);

	CK_RV C_Sign(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData,
		vector<unsigned char> &outSignature);

	CK_RV C_SignUpdate(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData);

	CK_RV C_SignFinal(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> &outSignature);

	CK_RV C_VerifyInit(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		CK_OBJECT_HANDLE hKey);

	CK_RV C_Verify(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData,
		vector<unsigned char> inSignature);

	CK_RV C_VerifyUpdate(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inData);

	CK_RV C_VerifyFinal(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> inSignature);

	CK_RV C_GenerateKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		vector<CK_ATTRIBUTE_SMART> Template,
		CK_OBJECT_HANDLE & outhKey);

	CK_RV C_GenerateKeyPair(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		vector<CK_ATTRIBUTE_SMART> PublicKeyTemplate,
		vector<CK_ATTRIBUTE_SMART> PrivateKeyTemplate,
		CK_OBJECT_HANDLE& outhPublicKey,
		CK_OBJECT_HANDLE& outhPrivateKey );

	CK_RV C_WrapKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		vector<unsigned char> &WrappedKey);

	CK_RV C_UnwrapKey(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM* pMechanism,
		CK_OBJECT_HANDLE hUnwrappingKey,
		vector<unsigned char> WrappedKey,
		vector<CK_ATTRIBUTE_SMART> Template,
		CK_OBJECT_HANDLE & outhKey);

	CK_RV C_SeedRandom(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> Seed);

	CK_RV C_GenerateRandom(
		CK_SESSION_HANDLE hSession,
		vector<unsigned char> &RandomData);

	CK_RV C_WaitForSlotEvent(
		unsigned long flags,
		unsigned long * INOUT);

	CK_RV C_GetMechanismList(
		unsigned long slotID,
		vector<long> &mechanismList);

	CK_RV C_GetMechanismInfo(
		unsigned long slotID,
		unsigned long type,
		CK_MECHANISM_INFO* pInfo);

};


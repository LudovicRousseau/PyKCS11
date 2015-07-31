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
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.

#include "stdafx.h"
#include "pykcs11string.h"
#include "ck_attribute_smart.h"
#include "pkcs11lib.h"
#include "utility.h"
#include <stdio.h>
#include <string.h>

	CK_ATTRIBUTE_SMART::CK_ATTRIBUTE_SMART(CK_ULONG type, const CK_BYTE* pValue, CK_ULONG len)
	{
		this->m_type = type;
		CK_ULONG i;
		if (pValue)
		{
			m_value.reserve(len);
			m_value.clear();
			for (i=0; i<len; i++)
				m_value.push_back(pValue[i]);
		}
		else
			m_value = vector<unsigned char>(len);
	}

	CK_ATTRIBUTE_SMART::CK_ATTRIBUTE_SMART(const CK_ATTRIBUTE_SMART & val)
	{
		vector<unsigned char>::const_iterator it;
		for (it = val.m_value.begin(); it != val.m_value.end(); it++)
			m_value.push_back(*it);
		m_type = val.m_type;
	}

	CK_ATTRIBUTE_SMART& CK_ATTRIBUTE_SMART::operator=(const CK_ATTRIBUTE_SMART & val)
	{
		m_value = val.m_value;
		m_type = val.m_type;
		return *this;
	}

	CK_ATTRIBUTE_SMART::CK_ATTRIBUTE_SMART()
	{
		m_value.reserve(1024);
	}

	CK_ATTRIBUTE_SMART::~CK_ATTRIBUTE_SMART()
	{
		Reset();
	}


	CK_ULONG CK_ATTRIBUTE_SMART::GetType() const
	{
		return m_type;
	}

	void CK_ATTRIBUTE_SMART::SetType(CK_ULONG attrType)
	{
		m_type = attrType;
	}

	int CK_ATTRIBUTE_SMART::GetLen() const
	{
		return (int)m_value.size();
	}

	bool CK_ATTRIBUTE_SMART::IsString() const
	{
		switch(m_type)
		{
		case CKA_LABEL:
		case CKA_APPLICATION:
			return true;
		default:
			return false;
		}
	}
	bool CK_ATTRIBUTE_SMART::IsBool() const
	{
		switch(m_type)
		{
		case CKA_ALWAYS_SENSITIVE:
		case CKA_DECRYPT:
		case CKA_DERIVE:
		case CKA_ENCRYPT:
		case CKA_HAS_RESET:
		case CKA_LOCAL:
		case CKA_MODIFIABLE:
		case CKA_NEVER_EXTRACTABLE:
		case CKA_PRIVATE:
		case CKA_RESET_ON_INIT:
		case CKA_SECONDARY_AUTH:
		case CKA_SENSITIVE:
		case CKA_SIGN:
		case CKA_SIGN_RECOVER:
		case CKA_TOKEN:
		case CKA_TRUSTED:
		case CKA_UNWRAP:
		case CKA_VERIFY:
		case CKA_VERIFY_RECOVER:
		case CKA_WRAP:
			return true;
		default:
			return false;
		}
	}


	bool CK_ATTRIBUTE_SMART::IsNum() const
	{
		switch(m_type)
		{
		case CKA_CERTIFICATE_TYPE:
		case CKA_CLASS:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_VALUE_BITS:
		case CKA_VALUE_LEN:
			return true;
		default:
			return false;
		}
	}

	bool CK_ATTRIBUTE_SMART::IsBin() const
	{
		return !IsBool() && !IsString() && !IsNum();
	}

	void CK_ATTRIBUTE_SMART::Reset()
	{
		m_value.clear();
		m_value.reserve(1024);
		m_type = 0;
	}
	void CK_ATTRIBUTE_SMART::ResetValue()
	{
		m_value.clear();
		m_value.reserve(1024);
	}
	void CK_ATTRIBUTE_SMART::Reserve(long len)
	{
		m_value = vector<unsigned char>(len);
	}

	PyKCS11String CK_ATTRIBUTE_SMART::GetString() const
	{
		return PyKCS11String(m_value);
	}

	void CK_ATTRIBUTE_SMART::SetString(CK_ULONG attrType, const char* szValue)
	{
		Reset();
		m_type = attrType;
		if (szValue && strlen(szValue))
		{
			size_t i;
			size_t iLen = strlen(szValue);
			for (i=0; i< iLen; i++)
				m_value.push_back((unsigned char)szValue[i]);
		}
	}

	long CK_ATTRIBUTE_SMART::GetNum() const
	{
		if (!IsNum() || m_value.size() != sizeof(CK_ULONG))
			return 0;
		else
		{
			CK_ULONG i;
			CK_ULONG ulRes = 0;
			unsigned char* pVal = (unsigned char*)&ulRes;
			for (i=0; i<sizeof(ulRes); i++)
				pVal[i] = m_value.at(i);
			return ulRes;
		}
	}
	void CK_ATTRIBUTE_SMART::SetNum(CK_ULONG attrType, CK_ULONG ulValue)
	{
		Reset();
		CK_ULONG i;
		unsigned char* pVal = (unsigned char*)&ulValue;
		m_type = attrType;
		for (i=0; i<sizeof(ulValue); i++)
			m_value.push_back(pVal[i]);
	}


	bool CK_ATTRIBUTE_SMART::GetBool() const
	{
		if (!IsBool() || m_value.size() != sizeof(unsigned char))
			return false;
		else
		{
			return m_value[0] != CK_FALSE;
		}
	}
	void CK_ATTRIBUTE_SMART::SetBool(CK_ULONG attrType, bool bValue)
	{
		Reset();
		m_type = attrType;
		m_value.push_back(bValue?CK_TRUE:CK_FALSE);
	}

	vector<unsigned char>& CK_ATTRIBUTE_SMART::GetBin()
	{
		return m_value;
	}

	void CK_ATTRIBUTE_SMART::SetBin(unsigned long attrType, const vector<unsigned char>& pBuf)
	{
		Reset();
		m_value = pBuf;
		m_type = attrType;
	}


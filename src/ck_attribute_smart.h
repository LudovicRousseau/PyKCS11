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

#pragma once

#include "pykcs11string.h"

#include <vector>
using namespace std;

class CK_ATTRIBUTE_SMART
{

	CK_ATTRIBUTE_TYPE m_type;
	vector<unsigned char> m_value;
	public:

	CK_ATTRIBUTE_SMART(unsigned long type, const unsigned char* pValue, unsigned long len);
	CK_ATTRIBUTE_SMART(const CK_ATTRIBUTE_SMART & val);
	CK_ATTRIBUTE_SMART& operator=(const CK_ATTRIBUTE_SMART & val);


	CK_ATTRIBUTE_SMART();

	~CK_ATTRIBUTE_SMART();

	void Reset();
	void ResetValue();
	void Reserve(long len);
	unsigned long GetType()  const;
	void SetType(unsigned long attrType);
	int GetLen() const;

	bool IsString() const;
	bool IsBool() const;
	bool IsNum() const;
	bool IsBin() const;

	// returns the value as SWIG "cdata.i"'s struct
	PyKCS11String GetString() const;
	void SetString(unsigned long attrType, const char* szValue);

	long GetNum() const;
	void SetNum(unsigned long attrType, unsigned long ulValue);

	bool GetBool() const;
	void SetBool(unsigned long attrType, bool bValue);

	vector<unsigned char>& GetBin();
	void SetBin(unsigned long attrType, const vector<unsigned char>& pBuf);
};


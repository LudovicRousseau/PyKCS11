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
#include <vector>
#include "pykcs11string.h"
#include "ck_attribute_smart.h"
#include "pkcs11lib.h"
#include "utility.h"

using namespace std;

unsigned char * Vector2Buffer(vector<unsigned char> &Buf, CK_ULONG &Len)
{
	Len = (CK_ULONG)Buf.size();
	if (!Len)
		return NULL;
	CK_ULONG i;
	unsigned char *pBuf = new unsigned char[Len];
	for (i = 0; i<Len; i++)
		pBuf[i] = Buf[i];
	return pBuf;
}
void Buffer2Vector(unsigned char* pBuf, CK_ULONG Len, vector<unsigned char> &Buf, bool bAllocIfNull)
{
	Buf.clear();
	if (!pBuf & bAllocIfNull)
		Buf = vector<unsigned char>(Len);
	else
	{
		Buf.reserve(Len);
		CK_ULONG i;
		for (i = 0; i<Len; i++)
			Buf.push_back(pBuf[i]);
	}
}


CK_ATTRIBUTE_PTR AttrVector2Template(vector<CK_ATTRIBUTE_SMART> &Attr, CK_ULONG &Len)
{
	Len = (CK_ULONG) Attr.size();
	if (!Len)
		return NULL;
	CK_ULONG i;

	CK_ATTRIBUTE_PTR pTemplate = new CK_ATTRIBUTE[Len];
	for (i=0; i< Len; i++)
	{
		pTemplate[i].type = Attr[i].GetType();
		pTemplate[i].pValue = Vector2Buffer(Attr[i].GetBin(), pTemplate[i].ulValueLen);
	}
	return pTemplate;
}

void Template2AttrVector(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG Len, vector<CK_ATTRIBUTE_SMART> &Attr)
{
	CK_ULONG i;
	for (i=0; i<Len;i++)
	{
		Attr[i] = CK_ATTRIBUTE_SMART(pTemplate[i].type, (CK_BYTE*)pTemplate[i].pValue, pTemplate[i].ulValueLen);
	}
}

void DestroyTemplate(CK_ATTRIBUTE_PTR &pTemplate, CK_ULONG Len)
{
	CK_ULONG i;
	for (i=0; i<Len; i++)
	{
		try{
		if (pTemplate[i].pValue)
			delete [] (unsigned char*) pTemplate[i].pValue;
		}
		catch(...){}
		pTemplate[i].pValue = NULL;
	}
	try{
	delete [] pTemplate;
	}catch(...){}
	pTemplate = NULL;

}



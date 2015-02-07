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

#ifndef _UTILITY_H__DEFINED_
#define _UTILITY_H__DEFINED_

unsigned char * Vector2Buffer(vector<unsigned char> &Buf, CK_ULONG &Len);
CK_ATTRIBUTE_PTR AttrVector2Template(vector<CK_ATTRIBUTE_SMART> &Attr, CK_ULONG &Len);
void Template2AttrVector(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG Len, vector<CK_ATTRIBUTE_SMART> &Attr);
void DestroyTemplate(CK_ATTRIBUTE_PTR &pTemplate, CK_ULONG Len);
void Buffer2Vector(unsigned char* pBuf, CK_ULONG Len, vector<unsigned char> &Buf, bool bAllocIfNull);

#endif //_UTILITY_H__DEFINED_


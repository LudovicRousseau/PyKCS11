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

PyKCS11String::PyKCS11String()
{}

PyKCS11String::PyKCS11String(unsigned char* pBuf, int len)
{
	int i;
	if (m_str.max_size() < (size_t)len)
		m_str.reserve(len);
	for (i=0; i < len; i++)
		m_str.push_back((char)pBuf[i]);

}

PyKCS11String::PyKCS11String(const char* str):m_str(str)
{
}
PyKCS11String::PyKCS11String(basic_string<char> str):m_str(str)
{
}

PyKCS11String::PyKCS11String(vector<unsigned char> bin_str)
{
	if (m_str.max_size() < bin_str.size())
		m_str.reserve(bin_str.size());
	size_t iSize = bin_str.size();
	size_t i;
	for (i=0; i < iSize; i++)
		m_str.push_back(bin_str[i]);
}


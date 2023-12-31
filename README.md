PyKCS11 - PKCS#11 Wrapper for Python - Project Overview
=======================================================

Authors
=======

- Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
- Copyright (C) 2006-2018 Ludovic Rousseau (ludovic.rousseau@free.fr)


Licence
=======

 This file is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

Status
======

[![Coverage Status](https://coveralls.io/repos/github/LudovicRousseau/PyKCS11/badge.svg?branch=master)](https://coveralls.io/github/LudovicRousseau/PyKCS11?branch=master)

API
===
The API documentation is available at https://pkcs11wrap.sourceforge.io/api/

Installation
============

    pip install pykcs11

Unix build Howto
================
To build:

	python3 -m venv temp
	source temp/bin/activate
	pip3 install -r dev-requirements.txt
	make

To install in editable mode:

	make install

Windows build Howto
===================

Prerequisites

* Install python3 (and add "C:\Python34;C:\Python34\Scripts" to PATH
  environment variable)
* Install swig (and add swig install folder to PATH environment variable)
* Install Visual studio 2010 SDK

To install:

    nmake install

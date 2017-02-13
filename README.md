========================================================================
        PyKCS11 - PKCS#11 Wrapper for Python - Project Overview
========================================================================

Authors
"""""""

- Copyright (C) 2004 Midori (midori -- a-t -- paipai dot net)
- Copyright (C) 2006-2017 Ludovic Rousseau (ludovic.rousseau@free.fr)


Licence
"""""""

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

API
"""
The API documentation is available at http://pkcs11wrap.sourceforge.net/api/

Unix Howto
""""""""""
To install::

    $ make build
    $ make install (or make install DESTDIR=/foo/bar)


Windows Howto
"""""""""""""

Prerequisites

* Install python3 (and add "C:\Python34;C:\Python34\Scripts" to PATH
  environment variable)
* Install swig (and add swig install folder to PATH environment variable)
* Install Visual studio 2010 SDK

To install:

Open "Visual Studio command prompt (2010)"

cd to PyKCS11 folder and run::

    > nmake -f Makefile.win32 build
    > nmake -f Makefile.win32 install


Known Bugs
""""""""""

If in Windows the linker complains that the Python24_d.lib doesn't exists
Please edit the "SWIG-Install-Dir\Lib\python\python.swg" file and replace
following line::

    #include "Python.h"

with following code::

    #ifdef _DEBUG
      #undef _DEBUG
      #include "Python.h"
      #define _DEBUG
    #else
      #include "Python.h"
    #endif

This prevents the linker to try to link against the debug version of python lib
that doesn't come with the standard distribution.


History
"""""""

1.4.1 - February 2017, Ludovic Rousseau
    - fix compilation under Python 3
    - add rsa encryption sample program

1.4.0 - February 2017, Ludovic Rousseau
    - fix closeAllSessions() and move it Session to PKCS11Lib
    - add RSAOAEPMechanism to support RSA Encryption
    - add DigestSession which enables multi-part digesting
    - add Elliptic curve keypair generating mechanism
    - fix bug in Templates using booleans CK_TRUE/CK_FALSE
      Templates are used by generateKey(), generateKeyPair(),
      findObjects() createObject(), unwrapKey()
    - fix dumpit.py sample for Python 3

1.3.3 - November 2016, Ludovic Rousseau
    - PKCS#11 definitions: sync with Cryptoki version 2.40
      . add missing CKM_* and CKP_* defines
    - Add generateKey() with default mechanism CKM_AES_KEY_GEN
    - Make sure the PyKCS11Lib is referenced as long as Session object is live
    - Fix OverflowError on Windows
    - Attribute CKA_WRAP_WITH_TRUSTED is bool
    - samples
     . dumpit: ask to enter the PIN on the pinpad if needed
     . getinfo & dumpit: add --slot= parameter
    - some minor improvements

1.3.2 - January 2016, Ludovic Rousseau
    - Add wrappers for C_Verify, C_WrapKey, C_UnwrapKey
    - PKCS#11 definitions: sync with Cryptoki version 2.30
    - Generate CKM[CKM_VENDOR_DEFINED+x] values on the fly
    - Fix use of a pinpad reader CKF_PROTECTED_AUTHENTICATION_PATH
    - dumpit.py: lots of small fixes
    - Setup call make to build pykcs11_wrap.cpp using SWIG
    - Fix build on Windows
    - Small bugs fixed

1.3.1 - October 2015, Ludovic Rousseau
    - PKCS#11 definitions: sync with Cryptoki version 2.30
    - Add user type CK_CONTEXT_SPECIFIC
    - Fixes #9, incorrect assignment of pParameter for CK_MECHANISMs.
    - CKA_DERIVE is a CK_BBOOL and not byte array
    - Add digest() and encrypt method to Session class
    - Add samples:
      . key-pair generation
      . key-pair generation + certificate import
      . printing public key modulus
      . computing signature
    - small bugs fixed

1.3.0 - July 2014, Ludovic Rousseau
    - add Python3 support

1.2.4 - April 2012, Ludovic Rousseau
    - improve epydoc documentation
    - add pinpad support in C_Login() using pin=None
    - add pinpad support in samples getinfo.py and dumpit.py
    - add createObject()

1.2.3 - December 2010, Ludovic Rousseau
    - Add new classes CK_SLOT_INFO, CK_INFO, CK_SESSION_INFO,
      CK_MECHANISM_INFO and CK_TOKEN_INFO instead of the low level ones
      to have a __repr__() method.  It is now possible to just print an
      object of these classes and have a human readable version.
    - Add a new class CK_OBJECT_HANDLE() to replace the low level one
      and have a __repr__() method for objects returned by findObjects()
    - Move initToken() from class Session to class PyKCS11Lib and add a
      slot parameter.
    - Add generateKeyPair and destoryObject support in high level
      interface

1.2.2 - June 2010, Ludovic Rousseau
    Debug low level C_GenerateRandom
    Add seedRandom() and generateRandom() in the high level API

1.2.1 - November 2008, Ludovic Rousseau
    Use src/opensc/pkcs11.h instead of src/rsaref/* files since the
     files from RSA are not free enough (no right to distribute modified
     versions for example)
    improve samples/getinfo.py script
    bug fixes

1.2.0 - August 2008, Ludovic Rousseau
    add getMechanismList() and getMechanismInfo()
    add Session().getSessionInfo()
    bug fixes

1.1.1 - December 2006, Giuseppe Amato (Midori)
    bug fixes

1.1.0 - August 2006, Ludovic Rousseau
    Introduce high level API

1.0.2 - July 2006, Ludovic Rousseau
    port to Unix (tested on GNU/Linux only)
    explicit call to SWIG to generate the wrapper

1.0.1 - 2004 Giuseppe Amato (Midori)
    first version
    Windows only

#! /usr/bin/env python

# python setup.py install --root=/tmp/p
# PYTHONPATH=/tmp/p/usr/lib/python2.4/site-packages python test.py

from distutils.core import setup, Extension
from sys import version_info as pyver
from os import path
import platform

description = '''A complete PKCS#11 wrapper for Python.
You can use any PKCS#11 (aka CryptoKi) module such as the PSM which
comes as part of mozilla or the various modules supplied by vendors of
hardware crypto tokens, and almost all PKCS#11 functions and data types.
The wrapper has been generated with the help of the SWIG compiler.'''

classifiers = ["Development Status :: 5 - Production/Stable",
"Intended Audience :: Developers",
"License :: OSI Approved :: GNU General Public License (GPL)",
"Natural Language :: English",
"Operating System :: Microsoft :: Windows",
"Operating System :: OS Independent",
"Operating System :: Unix",
"Programming Language :: C",
"Programming Language :: C++",
"Programming Language :: Python",
"Topic :: Security :: Cryptography",
"Topic :: Software Development :: Libraries :: Python Modules"]

lib_dirs = []
inc_dirs = ["src"]
# some OS, such as FreeBSD, uses /usr/local folders
if path.exists("/usr/local"):
    lib_dirs.append("/usr/local/lib")
    inc_dirs.append("/usr/local/include")
source_files = ["src/ck_attribute_smart.cpp",
                "src/pkcs11lib.cpp",
                "src/pykcs11string.cpp",
                "src/utility.cpp",
                "src/pykcs11.cpp"]
define_macros = []
extra_compile_args = []
extra_link_args = []
if (platform.system().lower() == 'windows'):
    source_files.append("src/dyn_win32.c")
    source_files.append("pykcs11.rc")
    source_files.append("src/win32_pykcs11_wrap.cpp")
    libraries_val = ["python%d%d" % pyver[:2]]
    extra_compile_args = ["/Fdvc70.pdb", "/Zi", "/GR"]
    extra_link_args = ["/DEBUG", "/PDB:_LowLevel.pdb", "/SUBSYSTEM:WINDOWS", "/OPT:REF", "/OPT:ICF"]
else:
    source_files.append("src/dyn_unix.c")
    source_files.append("src/unix_pykcs11_wrap.cpp")
    libraries_val = ["python%d.%d" % pyver[:2]]

setup(name="PyKCS11",
    version="1.2.4",
    description="A Full PKCS#11 wrapper for Python",
    keywords="crypto,pki,pkcs11,c++",
    classifiers=classifiers,
    platforms="Win32 Unix",
    long_description=description,
    author="Giuseppe Amato (Midori)",
    author_email="paipai at tiscali.it",
    maintainer="Ludovic Rousseau",
    maintainer_email="ludovic.rousseau@free.fr",
    url="http://www.bit4id.org/trac/pykcs11",
    download_url="http://www.bit4id.org/trac/pykcs11/wiki/Download",
    license="GPL",
    ext_modules=[
        Extension(
            "PyKCS11._LowLevel",
            sources=source_files,
            include_dirs=inc_dirs,
            library_dirs=lib_dirs,
            libraries=libraries_val,
            define_macros=define_macros,
            extra_compile_args=extra_compile_args,
            extra_link_args=extra_link_args)],
    py_modules=["PyKCS11.__init__", "PyKCS11.LowLevel"],
)

# python setup.py install --root=/tmp/p
# PYTHONPATH=/tmp/p/usr/lib/python2.4/site-packages python test.py 

from distutils.core import setup, Extension
from sys import version_info as pyver
from os import path
lib_dirs = []
inc_dirs = ["src"]
# some OS, such as FreeBSD, uses /usr/local folders
if path.exists("/usr/local"):
    lib_dirs.append("/usr/local/lib")
    inc_dirs.append("/usr/local/include")

setup(name="PyKCS11",
    version="1.1.0",
    ext_modules=[
        Extension(
            "PyKCS11/_LowLevel",
            ["src/ck_attribute_smart.cpp", "src/pkcs11lib.cpp",
            "src/pykcs11string.cpp", "src/unix_pykcs11_wrap.cpp",
            "src/utility.cpp", "src/dyn_unix.c"],
            include_dirs = inc_dirs,
            library_dirs = lib_dirs,
            libraries = ["python%d.%d" % pyver[:2]]
        )
    ],
    py_modules=["PyKCS11/__init__", "PyKCS11/LowLevel"],
)


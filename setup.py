# python setup.py install --root=/tmp/p
# PYTHONPATH=/tmp/p/usr/lib/python2.4/site-packages python test.py 

from distutils.core import setup, Extension

setup(name="PyKCS11", version="1.0.2",
	ext_modules=[
		Extension(
			"_PyKCS11",
			["src/ck_attribute_smart.cpp", "src/pkcs11lib.cpp",
			"src/pykcs11string.cpp", "src/unix_pykcs11_wrap.cpp",
			"src/utility.cpp", "src/dyn_unix.c"],
			include_dirs = ["src"],
			libraries = ["python2.4"]
		)
	],
	py_modules=["PyKCS11"],
)


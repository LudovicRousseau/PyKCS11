# give some default values
PREFIX ?= /usr
DESTDIR ?= /
ifeq (, $(PYTHON))
ifeq (, $(PYTHONVER))
	PYTHONVER=2.4
endif
PYTHON=python$(PYTHONVER)
endif

build: build-stamp

build-stamp: src/unix_pykcs11_wrap.cpp
	$(PYTHON) setup.py build
	touch build-stamp

install: build
	$(PYTHON) setup.py install --prefix=$(PREFIX) --root=$(DESTDIR)

clean:
	$(PYTHON) setup.py clean
	rm -f src/unix_pykcs11_wrap.cpp
	rm -rf build
	rm -f *.pyc PyKCS11/*.pyc
	rm -f PyKCS11/LowLevel.py
	rm -f build-stamp

rebuild: clean build

src/unix_pykcs11_wrap.cpp: src/pykcs11.i
	cd src ; swig -c++ -python pykcs11.i ; mv pykcs11_wrap.cxx unix_pykcs11_wrap.cpp ; mv LowLevel.py ../PyKCS11

src/pykcs11.i: src/opensc/pkcs11.h src/pkcs11lib.h src/pykcs11string.h src/ck_attribute_smart.h
	touch $@

dist:
	$(PYTHON) setup.py sdist
	
doc: build
	rm -rf html
	PYTHONPATH=`find build -name PyKCS11` epydoc PyKCS11


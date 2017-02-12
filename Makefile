# give some default values
DESTDIR ?= /
ifeq (, $(PYTHON))
PYTHON=python
endif
PREFIX ?= $(shell $(PYTHON) -c 'import sys; print(sys.prefix)')

build: build-stamp

build-stamp: src/pykcs11_wrap.cpp-py2 src/pykcs11_wrap.cpp-py3
	cp src/pykcs11_wrap.cpp-py"`$(PYTHON) -c 'import sys; print(sys.version[0])'`" src/pykcs11_wrap.cpp
	cp PyKCS11/LowLevel.py"`$(PYTHON) -c 'import sys; print(sys.version[0])'`" PyKCS11/LowLevel.py
	$(PYTHON) setup.py build
	touch build-stamp

install: build
	$(PYTHON) setup.py install --prefix=$(PREFIX) --root=$(DESTDIR)

clean distclean:
	$(PYTHON) setup.py clean
	rm -f src/pykcs11_wrap.cpp*
	rm -rf build
	rm -f *.pyc PyKCS11/*.pyc
	rm -f PyKCS11/LowLevel.py*
	rm -f build-stamp

rebuild: clean build

src/pykcs11_wrap.cpp-py2: src/pykcs11.i
	cd src ; swig -c++ -python -o pykcs11_wrap.cpp-py2 -outdir ../PyKCS11 pykcs11.i ; cd ../PyKCS11 ; mv LowLevel.py LowLevel.py2

src/pykcs11_wrap.cpp-py3: src/pykcs11.i
	cd src ; swig -c++ -python -py3 -o pykcs11_wrap.cpp-py3 pykcs11.i ; mv LowLevel.py ../PyKCS11/LowLevel.py3

src/pykcs11.i: src/opensc/pkcs11.h src/pkcs11lib.h src/pykcs11string.h src/ck_attribute_smart.h
	touch $@

dist: clean
	$(PYTHON) setup.py sdist

pypi: clean
	$(PYTHON) setup.py sdist upload

doc: build
	rm -rf html
	epydoc --verbose PyKCS11

doc-upload: doc
	mv html api
	scp -r api ludov@web.sourceforge.net:/home/project-web/pkcs11wrap/htdocs

.PHONY: build install clean rebuild dist doc

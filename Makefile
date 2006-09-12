# give some default values
PREFIX ?= /usr
DESTDIR ?= /
ifeq (, $(PYTHONVER))
	PYTHONVER=2.4
endif
PYTHON=python$(PYTHONVER)

build: src/unix_pykcs11_wrap.cpp
	$(PYTHON) setup.py build

install: build
	$(PYTHON) setup.py install --prefix=$(PREFIX) --root=$(DESTDIR)

clean:
	$(PYTHON) setup.py clean
	rm -f src/unix_pykcs11_wrap.cpp
	rm -rf build

rebuild: clean build

src/unix_pykcs11_wrap.cpp: src/pykcs11.i
	cd src ; swig -c++ -python pykcs11.i ; mv pykcs11_wrap.cxx unix_pykcs11_wrap.cpp ; mv PyKCS11.py ..

src/pykcs11.i: src/rsaref/cryptoki.h src/pkcs11lib.h src/pykcs11string.h src/ck_attribute_smart.h
	touch $@

# give some default values
PREFIX ?= /usr
DESTDIR ?= /

build: src/unix_pykcs11_wrap.cpp
	python setup.py build

install: build
	python setup.py install --prefix=$(PREFIX) --root=$(DESTDIR)

clean:
	python setup.py clean
	rm -f src/unix_pykcs11_wrap.cpp
	rm -rf build
	rm -f *.pyc PyKCS11/*.pyc

rebuild: clean build

src/unix_pykcs11_wrap.cpp: src/pykcs11.i
	cd src ; swig -c++ -python pykcs11.i ; mv pykcs11_wrap.cxx unix_pykcs11_wrap.cpp ; mv LowLevel.py ../PyKCS11

src/pykcs11.i: src/rsaref/cryptoki.h src/pkcs11lib.h src/pykcs11string.h src/ck_attribute_smart.h
	touch $@

doc:
	epydoc PyKCS11


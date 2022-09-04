# give some default values
DESTDIR ?= /
ifeq (, $(PYTHON))
PYTHON=python3
endif
PREFIX ?= $(shell $(PYTHON) -c 'import sys; print(sys.prefix)')
COVERAGE ?= python3-coverage

build: build-stamp

build-stamp:
	$(PYTHON) setup.py build
	touch build-stamp

install: build
	$(PYTHON) setup.py install --prefix=$(PREFIX) --root=$(DESTDIR)

clean distclean:
	$(PYTHON) setup.py clean
	rm -f src/pykcs11_wrap.cpp
	rm -f src/LowLevel.py
	rm -rf build
	rm -f *.pyc PyKCS11/*.pyc
	rm -f PyKCS11/LowLevel.py
	rm -f PyKCS11/_LowLevel*
	rm -f build-stamp
	rm -f test/*.pyc

rebuild: clean build

src/pykcs11.i: src/opensc/pkcs11.h src/pkcs11lib.h src/pykcs11string.h src/ck_attribute_smart.h
	touch $@

dist: clean
	$(PYTHON) setup.py sdist bdist_wheel

pypi: clean
	rm -rf dist
	$(PYTHON) setup.py sdist bdist_wheel
	$(PYTHON) -m twine upload dist/*

prepare4test: build
	cd PyKCS11 ; ln -sf ../build/lib.*/PyKCS11/_LowLevel*.so

tests: prepare4test
	$(PYTHON) run_test.py

coverage: prepare4test
	$(COVERAGE) erase
	$(COVERAGE) run run_test.py
	$(COVERAGE) report
	$(COVERAGE) html

doc:
	cd docs ; ./generate.sh

doc-upload: doc
	rm -r api
	mv docs/_build/html api
	scp -r api ludov@web.sourceforge.net:/home/project-web/pkcs11wrap/htdocs

.PHONY: build install clean rebuild dist doc

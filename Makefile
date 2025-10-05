# give some default values
ifeq (, $(PYTHON))
PYTHON=python3
endif
COVERAGE ?= $(PYTHON) -m coverage

build:
	$(PYTHON) -m build

constants:
	$(PYTHON) generate_constants.py > constants.py
	mv constants.py src/PyKCS11/

install:
	$(PYTHON) -m pip install --editable .

clean distclean:
	$(PYTHON) setup.py clean
	rm -f src/pykcs11_wrap.cpp
	rm -rf build
	rm -f *.pyc PyKCS11/*.pyc
	rm -f src/PyKCS11/LowLevel.py
	rm -f src/PyKCS11/_LowLevel*
	rm -f build-stamp
	rm -f test/*.pyc
	find . -name .DS_Store -exec rm {} \;

src/pykcs11.i: src/opensc/pkcs11.h src/pkcs11lib.h src/pykcs11string.h src/ck_attribute_smart.h
	touch $@

pypi: clean
	rm -rf dist
	$(PYTHON) -m build
	$(PYTHON) -m twine upload dist/*

test:
	$(PYTHON) run_pytest.py

coverage:
	$(COVERAGE) erase
	$(COVERAGE) run run_test.py
	$(COVERAGE) report
	$(COVERAGE) html

tox:
	./get_PYKCS11LIB.py > tox.env
	tox -- -v

pylint:
	$(PYTHON) -m pylint PyKCS11
	$(PYTHON) -m pylint samples

doc:
	cd docs ; ./generate.sh

doc-upload: doc
	rm -rf api
	mv docs/_build/html api
	scp -r api ludov@web.sourceforge.net:/home/project-web/pkcs11wrap/htdocs

.PHONY: build install clean doc test

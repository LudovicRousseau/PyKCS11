#!/bin/bash

set -e

cd $(dirname $0)

# Enable a virtualenv before running the script to avoid modifying
# the system Python libraries

virtualenv tmp
source tmp/bin/activate
pip3 install sphinx

(cd .. ; python setup.py install)
make html

deactivate
rm -r tmp

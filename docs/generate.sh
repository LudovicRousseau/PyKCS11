#!/bin/bash

set -e

cd $(dirname $0)

# Enable a virtualenv before running the script to avoid modifying
# the system Python libraries

python3 -m venv tmp
source tmp/bin/activate
pip3 install sphinx setuptools

(cd .. ; python3 -m pip install .)
make html

deactivate
rm -r tmp

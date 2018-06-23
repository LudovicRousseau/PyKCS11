#!/bin/bash

# Enable a virtualenv before running the script to avoid modifying
# the system Python libraries

cd $(dirname $0)

(cd .. ; python setup.py install)
make html

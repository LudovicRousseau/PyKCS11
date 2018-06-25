#!/bin/bash

# Enable a virtualenv before running the script to avoid modifying
# the system Python libraries

if [ ! "$VIRTUAL_ENV" ]
then
	echo "Run it from inside a virtualenv"
	exit 1
fi

cd $(dirname $0)

(cd .. ; python setup.py install)
make html

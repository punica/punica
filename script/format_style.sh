#!/bin/bash

set -e

ASTYLE=./astyle/build/gcc/bin/astyle
ASTYLE_OPTS="--options=.astyle.conf $@"
ASTYLE_FILES="src/*.h src/*.c"

# Download and install
if [ ! -x $ASTYLE ]; then
    wget https://sourceforge.net/projects/astyle/files/astyle/astyle%203.1/astyle_3.1_linux.tar.gz
    tar xzvf astyle_3.1_linux.tar.gz
    cd astyle/build/gcc
    make
    cd ../../..
fi

# Verify version
$ASTYLE --version
if [ "`$ASTYLE --version`" != "Artistic Style Version 3.1" ]; then
    echo "Error! Astyle version must be 3.1!"
    exit 1
fi

# Check style
echo "$ASTYLE $ASTYLE_OPTS $ASTYLE_FILES"
output=`$ASTYLE $ASTYLE_OPTS $ASTYLE_FILES`
if [ -z "$output" ]; then
    echo "Code style pass!"
else
    echo "Code style fail!"
    exit 1
fi

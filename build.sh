#!/bin/sh

set -e

if [[ $1 = --help ]]; then
	echo "Usage: $0 [MAKE-OPTIONS] [test | install]"
	echo "       $0 distclean"
	exit 0
elif [[ $1 = distclean ]]; then
	cmd="rm -rf Doxyfile build html"
	echo $cmd
	`$cmd`
	exit 0
fi

mkdir -p build
cd build
if [[ ! -f Makefile ]]; then
	cmake ..
fi
exec make "$@"

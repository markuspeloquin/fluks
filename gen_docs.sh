#!/bin/sh

doxygen -g || exit $?
./tools/doxyset \
    BUILTIN_STL_SUPPORT		YES \
    EXTRACT_ALL			YES \
    EXTRACT_LOCAL_CLASSES	NO \
    GENERATE_LATEX		NO \
    MACRO_EXPANSION		YES \
    EXPAND_ONLY_PREDEF		YES \
    PREDEFINED			__BEGIN_DECLS= \
    #
doxyset_status=$?
if [[ $doxyset_status != 0 ]]; then
	rm -f Doxyfile
	exit $doxyset_status
fi
rm -f Doxyfile.bak

exec doxygen

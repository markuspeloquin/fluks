all:
	@echo "You really meant to type \`bjam', didn't you?"

doc: Doxyfile
	doxygen

Doxyfile:
	doxygen -g
	./doxyset \
    BUILTIN_STL_SUPPORT 	YES \
    EXTRACT_ALL 		YES \
    EXTRACT_LOCAL_CLASSES 	NO \
    GENERATE_LATEX 		NO \
    MACRO_EXPANSION		YES \
    EXPAND_ONLY_PREDEF		YES \
    PREDEFINED			"__BEGIN_DECLS="

clean:
	rm -rf Doxyfile bin debug html release

.PHONY: test

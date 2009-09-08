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
	    GENERATE_LATEX 		NO

clean:
	rm -rf Doxyfile bin debug html release

.PHONY: test

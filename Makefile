all:
	@echo "You really meant to type \`bjam', didn't you?"

doc:
	@doxygen

test:
	@(cd test; ../bin/*/debug/test/serpent)
	@bin/*/debug/test/tiger
	@bin/*/debug/test/whirlpool

clean:
	rm -rf bin debug html release

.PHONY: test

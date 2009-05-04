all:
	@echo "You really meant to type \`bjam', didn't you?"

doc:
	@doxygen

clean:
	rm -rf bin debug html release

all: test

unit: test

test:
	mocha -R spec

.PHONY: test
	
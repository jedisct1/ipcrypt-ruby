# Makefile for IPCrypt2 Ruby implementation

.PHONY: test examples clean

test:
	ruby test/test_ipcrypt.rb

examples:
	ruby examples.rb

clean:
	rm -f *.gem

build:
	gem build ipcrypt2.gemspec

install: build
	gem install ipcrypt2-*.gem
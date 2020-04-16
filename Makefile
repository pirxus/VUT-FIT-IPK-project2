CPPFLAGS= -std=c++17 -Wall -Wextra -pedantic -g

all: run

run: sniffer
	build/sniffer

sniffer: src/main.cc
	g++ $(CPPFLAGS) src/main.cc -o build/sniffer

.PHONY: clean

clean:
	rm -rf build/*

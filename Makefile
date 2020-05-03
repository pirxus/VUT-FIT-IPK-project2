CPPFLAGS= -std=c++17 -Wall -Wextra -pedantic -g -DDO_NOT_TRANSLATE_IP
LIBS= -lpcap
SRC= src/main.cpp src/resources.cpp src/resources.hpp src/sniffer.cpp src/sniffer.hpp

all: sniffer

run: sniffer
	./build/sniffer

sniffer: $(SRC)
	g++ $(CPPFLAGS) $(LIBS) src/main.cpp src/resources.cpp src/sniffer.cpp -o sniffer

.PHONY: clean

clean:
	rm -rf build/*
	rm sniffer

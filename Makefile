CPPFLAGS= -std=c++17 -Wall -Wextra -pedantic -g # -DDO_NOT_TRANSLATE_IP
LIBS= -lpcap
SRC= src/main.cpp src/resources.cpp src/resources.hpp src/sniffer.cpp src/sniffer.hpp

all: sniffer

sniffer: $(SRC)
	g++ $(CPPFLAGS) src/main.cpp src/resources.cpp src/sniffer.cpp -o ipk-sniffer $(LIBS)

.PHONY: clean

clean:
	rm -rf build/*
	rm -f ipk-sniffer

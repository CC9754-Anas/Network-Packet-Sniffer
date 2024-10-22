CC=clang++
CXXFLAGS=-g -Wall -std=c++2a
LFLAGS=-lpthread -lnet -lpcap
SHELL=/bin/bash

.PHONY: all build debug run

create_build_dir:

	[ -d build ] || mkdir build

test: test/test.cpp

	$(CC) $(CXXFLAGS) -o build/test $(LFLAGS) \
		&& ./build/test.cpp
	

build: src/main.cpp

	make create_build_dir
	$(CC) $(CXXFLAGS) -o build/main.elf src/main.cpp $(LFLAGS)

run: build/main.elf
	
	sudo ./build/main.elf

debug:

	gdb build/main.elf

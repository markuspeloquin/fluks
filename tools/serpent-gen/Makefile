CFLAGS = -Wall -pipe -std=c99
CFLAGS += -O3
#CFLAGS += -O0 -g

all: brute

brute: brute.o serpent_bits.o
	$(CC) brute.o serpent_bits.o -o brute

brute.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) brute.c -c

serpent_bits.o: serpent_bits.c serpent_bits.h
	$(CC) $(CFLAGS) serpent_bits.c -c

clean:
	rm -f brute.o serpent_bits.o brute

test: test.o serpent_bits.o
	g++ test.o serpent_bits.o -o test

test.o: test.cpp serpent_bits.h serpent_sboxes.hpp
	g++ -Wall -std=c++98 test.cpp -c

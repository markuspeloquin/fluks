CFLAGS = -Wall -pipe -std=c99 -pedantic -pthread
CFLAGS += -O3
#CFLAGS += -O0 -g 
LDFLAGS = -pthread

all: brute

brute: brute.o serpent_bits.o thread_list.o
	$(CC) brute.o serpent_bits.o thread_list.o $(LDFLAGS) -o brute

brute.o: brute.c serpent_bits.h thread_list.h
	$(CC) $(CFLAGS) brute.c -c

serpent_bits.o: serpent_bits.c serpent_bits.h
	$(CC) $(CFLAGS) serpent_bits.c -c

thread_list.o: thread_list.c thread_list.h
	$(CC) $(CFLAGS) thread_list.c -c

clean:
	rm -f brute.o serpent_bits.o thread_list.o brute

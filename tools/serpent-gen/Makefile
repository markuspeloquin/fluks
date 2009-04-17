CFLAGS = -Wall -pipe -std=c99
CFLAGS += -O2
#CFLAGS += -O0 -g

all: brute00 brute01 brute02 brute03 brute04 brute05 brute06 brute07 \
    brute10 brute11 brute12 brute13 brute14 brute15 brute16 brute17

brute00: brute00.o serpent_bits.o
	$(CC) brute00.o serpent_bits.o -o brute00

brute01: brute01.o serpent_bits.o
	$(CC) brute01.o serpent_bits.o -o brute01

brute02: brute02.o serpent_bits.o
	$(CC) brute02.o serpent_bits.o -o brute02

brute03: brute03.o serpent_bits.o
	$(CC) brute03.o serpent_bits.o -o brute03

brute04: brute04.o serpent_bits.o
	$(CC) brute04.o serpent_bits.o -o brute04

brute05: brute05.o serpent_bits.o
	$(CC) brute05.o serpent_bits.o -o brute05

brute06: brute06.o serpent_bits.o
	$(CC) brute06.o serpent_bits.o -o brute06

brute07: brute07.o serpent_bits.o
	$(CC) brute07.o serpent_bits.o -o brute07

brute10: brute10.o serpent_bits.o
	$(CC) brute10.o serpent_bits.o -o brute10

brute11: brute11.o serpent_bits.o
	$(CC) brute11.o serpent_bits.o -o brute11

brute12: brute12.o serpent_bits.o
	$(CC) brute12.o serpent_bits.o -o brute12

brute13: brute13.o serpent_bits.o
	$(CC) brute13.o serpent_bits.o -o brute13

brute14: brute14.o serpent_bits.o
	$(CC) brute14.o serpent_bits.o -o brute14

brute15: brute15.o serpent_bits.o
	$(CC) brute15.o serpent_bits.o -o brute15

brute16: brute16.o serpent_bits.o
	$(CC) brute16.o serpent_bits.o -o brute16

brute17: brute17.o serpent_bits.o
	$(CC) brute17.o serpent_bits.o -o brute17

brute00.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=0 brute.c -c -o brute00.o

brute01.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=1 brute.c -c -o brute01.o

brute02.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=2 brute.c -c -o brute02.o

brute03.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=3 brute.c -c -o brute03.o

brute04.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=4 brute.c -c -o brute04.o

brute05.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=5 brute.c -c -o brute05.o

brute06.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=6 brute.c -c -o brute06.o

brute07.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=0 -DSBOX=7 brute.c -c -o brute07.o

brute10.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=0 brute.c -c -o brute10.o

brute11.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=1 brute.c -c -o brute11.o

brute12.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=2 brute.c -c -o brute12.o

brute13.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=3 brute.c -c -o brute13.o

brute14.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=4 brute.c -c -o brute14.o

brute15.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=5 brute.c -c -o brute15.o

brute16.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=6 brute.c -c -o brute16.o

brute17.o: brute.c serpent_bits.h
	$(CC) $(CFLAGS) -DCORE=1 -DSBOX=7 brute.c -c -o brute17.o

serpent_bits.o: serpent_bits.c serpent_bits.h
	$(CC) $(CFLAGS) serpent_bits.c -c

clean:
	rm -f brute[01][0-7].o serpent_bits.o brute[01][0-7]

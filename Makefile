CFLAGS=-Wall -Wextra -Wpedantic -O3 -flto -fPIC

default: test

main: main.c csidh.h csidh.c mont.c mont.h fp.S u512.S rng.c rng.h
	@gcc $(CFLAGS) \
		-Wall -Wextra \
		-O0 -funroll-loops \
		-g \
		rng.c \
		u512.S fp.S \
		mont.c \
		csidh.c \
		main.c \
		-o main

debug:
	gcc \
		-Wall -Wextra \
		-g \
		rng.c \
		u512.S fp.S \
		mont.c \
		csidh.c \
		main.c \
		-o main

clean:
	rm -f main

libcsidh.a: libcsidh.h libcsidh.o csidh.o mont.o fp.o u512.o rng.o
	chmod u+w $@
	ar rcs $@ $^
	chmod u-w $@

test: test.c libcsidh.a
	$(CC) $(CFLAGS) -o $@ $^
	./test

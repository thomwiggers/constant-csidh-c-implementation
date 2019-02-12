all:
	@gcc \
		-Wall -Wextra \
		-O0 -funroll-loops \
		-g \
		rng.c \
		u512.S fp.S \
		mont.c \
		csidh.c \
		seasign.c \
		main.c \
		-o main \
		-lcrypto

bench:
	@gcc \
		-Wall -Wextra \
		-O0 -funroll-loops \
		-g -pg \
		rng.c \
		u512.S fp.S \
		mont.c \
		csidh.c \
		seasign.c \
		bench.c \
		-o main


debug:
	gcc \
		-Wall -Wextra \
		-g \
		rng.c \
		u512.S fp.S \
		mont.c \
		csidh.c \
		seasign.c \		
		main.c \
		-o main

clean:
	rm -f main


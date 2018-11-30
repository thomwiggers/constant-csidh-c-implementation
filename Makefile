all:
	@gcc \
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


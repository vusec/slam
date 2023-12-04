LIB = ../lib
LIB_SRC=$(wildcard $(LIB)/*.c)

all: covert.c $(LIB_SRC) $(LIB)/slam.h
	gcc $(CFLAGS) -O2 -no-pie -o covert -I$(LIB) covert.c $(LIB_SRC) -lm

clean:
	rm covert

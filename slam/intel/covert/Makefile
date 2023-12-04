LIB = ../lib
LIB_SRC=$(wildcard $(LIB)/*.c) $(wildcard $(LIB)/*.S)

all: $(LIB_SRC) $(LIB)/slam.h covert.c
	gcc -DIDEAL -DONLY_128_RELOADS -O2 -no-pie -o covert -I$(LIB) $(LIB_SRC) covert.c -lm

clean:
	rm covert

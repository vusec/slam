LIB = ../../slam/intel/lib
LIB_SRC=$(wildcard $(LIB)/*.c) $(wildcard $(LIB)/*.S)

fineibt: $(LIB_SRC) $(LIB)/slam.h fineibt.c
	gcc -DIDEAL -g3 -O2 -no-pie -o fineibt -I$(LIB) $(LIB_SRC) fineibt.c -lm

clean:
	rm fineibt

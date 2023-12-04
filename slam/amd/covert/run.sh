#!/bin/bash

if [ "$EUID" -ne 0 ]
then
  echo "need root permission";
  exit;
fi

make CFLAGS=-DSIMULATE_UAI

for i in 1 2 3 4 5 6 7 8 9 10
do
        echo UAI on - run $i
        ./covert >> uai_on.out
done

make

for i in 1 2 3 4 5 6 7 8 9 10
do
        echo UAI off - run $i
        ./covert >> uai_off.out
done

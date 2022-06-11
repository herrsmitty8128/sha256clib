objects = sha256.o calcsha256.o

calcsha256 : $(objects)
	gcc -Wall -o calcsha256 $(objects) -O3
	make clean

sha256.o : sha256.c sha256.h
	gcc -Wall -c sha256.c -O3

calcsha256.o : calcsha256.c
	gcc -Wall -c calcsha256.c -O3

.PHONY : clean
clean :
	rm $(objects)
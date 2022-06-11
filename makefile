objects = calcsha256.o
libpath = ./lib/

calcsha256 : $(objects) sha256.so
	gcc -Wall -O3 -o $(exepath)calcsha256 calcsha256.o -Llib$(libpath) -Wl,-rpath,$(libpath) $(libpath)sha256.so
	make clean

sha256.so : sha256.c sha256.h
	gcc -fPIC -shared -Wall -Werror -Wextra -O3 sha256.c -o $(libpath)sha256.so

calcsha256.o : calcsha256.c
	gcc -Wall -c calcsha256.c -O3

.PHONY : clean
clean :
	rm $(objects)
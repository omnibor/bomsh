
CC=gcc

hello: hello.o
	$(CC) -o hello hello.o

hello.o: hello.c
	$(CC) -c -o hello.o hello.c

release: hello
	strip hello

clean:
	-rm hello.o hello


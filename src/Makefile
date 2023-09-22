
CC=gcc

hello: hello.o
	$(CC) -o hello hello.o

hello.o: hello.c
	$(CC) -c -o hello.o hello.c

release: hello
	strip hello

# another app with static linking and dynamic linking
hello2: hello2.o
	$(CC) -o hello2 hello2.o -L. -ls1 -ld1

hello2.o: hello2.c
	$(CC) -c -o hello2.o hello2.c

hello2-release: hello2
	strip hello2

clean:
	-rm hello.o hello hello2.o hello2


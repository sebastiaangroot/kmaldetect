CC=gcc
CFLAGS=-c -Wall
LIBS=-lpthread -ldl
PLUGINS=

all: core plugins

core: core.o loader.o libiface.o
	$(CC) core.o loader.o libiface.o -o core $(LIBS)

core.o: core.c
	$(CC) $(CFLAGS) core.c

loader.o: loader.c
	$(CC) $(CFLAGS) loader.c

libiface.o: libiface.c
	$(CC) $(CFLAGS) libiface.c

plugins: plugin/libdummy.c
	$(CC) -fPIC -c plugin/libdummy.c -o plugin/libdummy.o
	$(CC) -shared plugin/libdummy.o -o plugin/libdummy.so

clean:
	rm -rf *.o core plugin/*.o plugin/*.so

cleanobj:
	rm -rf *.o plugin/*.o

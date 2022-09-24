CC=gcc
LIBCFLAGS=-fPIC -Wall -pedantic -std=gnu99

all: dbclient dbserver stringstore.o libstringstore.so
dbclient: dbclient.c
	gcc -Wall -pedantic -std=gnu99 -I/local/courses/csse2310/include -L/local/courses/csse2310/lib -lcsse2310a4 -o $@ $<
dbserver: dbserver.c
	gcc -Wall -pedantic -pthread -std=gnu99 -I/local/courses/csse2310/include -L/local/courses/csse2310/lib -lcsse2310a4 -L/local/courses/csse2310/lib  -L/local/courses/csse2310/lib -lcsse2310a3 -lstringstore -o $@ $<

stringstore.o: stringstore.c 
	$(CC) $(LIBCFLAGS) -c $<

libstringstore.so: stringstore.o
	$(CC) -shared -o $@ stringstore.o

clean:
	rm dbclient

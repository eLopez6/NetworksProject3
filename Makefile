CC=gcc
LD=gcc
CFLAGS= -Wall -Werror -g
LDFLAGS=$(CFLAGS)

TARGETS=proj3

proj3: Project3.o
	$(CC) $(CFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o

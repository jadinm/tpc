CC=gcc
CFLAGS=-I../lib -O2 -Wall -Werror -Wextra -g # TODO Remove -g for performance
LDFLAGS=-lzlog
SRC=sr-endhostd.c monitor.c
OBJ=$(SRC:.c=.o)
EXEC=sr-endhostd

all:
	$(MAKE) $(EXEC)
	ln -fs $(EXEC) ../bin/$(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ) ../bin/$(EXEC)


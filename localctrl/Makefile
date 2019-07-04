CC=gcc
CFLAGS=-I../lib -I../srn-dev/lib -O2 -Wall -Werror -Wextra -g # TODO Remove -g for performance
LDFLAGS=-L../srn-dev/lib -lzlog -ljansson -pthread -lsr
SRC=sr-localctrl.c monitor.c prefixmatch.c
OBJ=$(SRC:.c=.o)
EXEC=sr-localctrl

all:
	$(MAKE) $(EXEC)
	ln -fs $(CURDIR)/$(EXEC) ../bin/$(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ) ../bin/$(EXEC)

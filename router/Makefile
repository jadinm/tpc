CC=gcc
CFLAGS=-I../lib -I../srn-dev/lib -O2 -Wall -Werror -Wextra -g # TODO Remove -g for performance
LDFLAGS=-lzlog -lmnl -lnetfilter_queue -ljansson -lpthread -L../srn-dev/lib -lsr
SRC=nf_queue.c sr-rerouted.c notifier.c
OBJ=$(SRC:.c=.o)
EXEC=sr-rerouted

all:
	$(MAKE) $(EXEC)
	ln -fs $(CURDIR)/$(EXEC) ../bin/$(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ) ../bin/$(EXEC)


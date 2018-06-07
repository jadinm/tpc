CC=gcc
CFLAGS=-I../lib -O2 -Wall -Werror -Wextra -g # TODO Remove -g for performance
LDFLAGS=-lzlog -lmnl -lnetfilter_queue -ljansson
SRC=nf_queue.c sr-rerouted.c notifier.c
OBJ=$(SRC:.c=.o)
EXEC=sr-rerouted

all:
	$(MAKE) $(EXEC)
	ln -fs ../bin/$(EXEC) $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ) ../bin/$(EXEC)


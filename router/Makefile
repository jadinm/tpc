CC=gcc
CFLAGS=-O2 -Wall -Werror -Wextra -g # TODO Remove -g for performance
LDFLAGS=-lzlog -lmnl -lnetfilter_queue
SRC=nf_queue.c
OBJ=$(SRC:.c=.o)
EXEC=nf_queue

all:
	$(MAKE) $(EXEC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXEC): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(EXEC) $(OBJ)


CC=gcc
kerneltree=/usr/src/ebpf_hhf_kernel
CFLAGS=-I../lib -I../srn-dev/lib -O2 -Wall -Werror -Wextra -Wno-unused-variable \
       -Wno-unused-parameter -Wshadow -Wno-missing-field-initializers -D__EXPORTED_HEADERS__ \
	   -I$(kerneltree)/tools/lib/bpf -g # TODO Remove -g for performance
LDFLAGS=-L../srn-dev/lib -lzlog -ljansson -pthread -lsr $(kerneltree)/tools/lib/bpf/libbpf.a -lelf
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

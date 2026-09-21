CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?=

all: fcheck test_fcheck

fcheck: main.c fcheck.c fcheck.h
	$(CC) $(CFLAGS) main.c fcheck.c -o $@ $(LDFLAGS)

test_fcheck: test_fcheck.c fcheck.c fcheck.h
	$(CC) $(CFLAGS) test_fcheck.c fcheck.c -o $@ $(LDFLAGS)

test: test_fcheck
	./test_fcheck

clean:
	rm -f fcheck test_fcheck t_fc.idx t_fc_abc t_fc_empty
	rm -rf t_fc_dir

.PHONY: all test clean

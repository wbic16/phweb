# phweb — build with the system cc by default, or with phcc:
#   make            -> cc
#   make PHCC=1     -> phcc (Will's TinyCC fork), when present on PATH
CC ?= cc
ifeq ($(PHCC),1)
CC = phcc
endif
CFLAGS ?= -O2 -std=c99 -Wall -Wextra
LDLIBS = -lssl -lcrypto

phweb: phweb.c
	$(CC) $(CFLAGS) -o $@ phweb.c $(LDLIBS)

test: phweb
	python3 test_phweb.py

clean:
	rm -f phweb

.PHONY: test clean

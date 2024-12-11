#Makefile
#Drake Wheeler
#CS333
#Lab3

CC = gcc
DEBUG = -g -DNOISY_DEBUG
CFLAGS =  -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls -Wmissing-declarations -Wold-style-definition \
		 -Wmissing-prototypes -Wdeclaration-after-statement -Wno-return-local-addr -Wunsafe-loop-optimizations \
		 -Wuninitialized -Werror

LDFLAGS = -lcrypto -lmd

PROG1 = viktar
PROGS = $(PROG1)
INCLUDES = 


all: $(PROGS)

$(PROG1): $(PROG1).o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(PROG1).o: $(PROG1).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

#adds -g for debug compile and -DNOISY_DEBUG to the compile flags for program to define the macro at compile time
#and print out the debug statements while the program is running
debug: CFLAGS += DEBUG
debug: all

clean cls:
	rm -f $(PROGS) *.o *~ \#*

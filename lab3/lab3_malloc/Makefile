#
# Students' Makefile for the Malloc Lab
#

CC = gcc -g
CFLAGS = -Wall

OBJS1 = memlib.o mm.o mmdriver.o
OBJS2 = ep_mm.o memlib.o epmmdriver.o

all = mmdriver epmmdriver

mmdriver: $(OBJS1)
	$(CC) $(CFLAGS)  -o mmdriver $(OBJS1)

epmmdriver: $(OBJS2)
	$(CC) $(CFLAGS)  -o epmmdriver $(OBJS2)

mmdriver.o: memlib.h mm.h 
memlib.o: memlib.h config.h 
mm.o: mm.h memlib.h 
ep_mm.o: mm.h memlib.h


clean:
	rm -f *~ *.o mmdriver



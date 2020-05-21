#
# Students' Makefile for the Malloc Lab
#

CC = gcc -g
CFLAGS = -Wall

# 待补充
OBJS = memlib.o mm.o mmdriver.o

mmdriver: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o mmdriver

mmdriver.o: memlib.h mm.h 
memlib.o: memlib.h config.h 
mm.o: mm.h memlib.h 

clean:
	rm -f *~ *.o mmdriver



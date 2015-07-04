SRCFILE=src/st-base.c src/st-http.c src/st-daemon.c src/st-ui.c
OBJFILE=st-base.o st-http.o st-daemon.o st-ui.o
EXEC_NAME=simpleText
LIBS=-lpthread -lmagic -lconfig
BIN_PATH=/usr/bin/
CC=gcc
CFLAGS=-c -ggdb -Wall 
RMFLAGS=-f 

# link object files to executable
build: src2obj
	$(CC) -o $(EXEC_NAME) $(OBJFILE) $(LIBS)

# compile to object file
src2obj: $(SRCFILE)
	$(CC) $(CFLAGS) $(SRCFILE)

# remove executable & objectfiles
clean:
	rm -f $(EXEC_NAME) *.o

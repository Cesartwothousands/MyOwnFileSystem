.PHONY: all clean

CC = gcc
CFLAGS = -g -Wall

EXE1 = testfs
EXE2 = libFS

all: $(EXE1) $(EXE2)

${EXE2}: 
	$(CC) $(CFLAGS) -DWOF_LIB -fPIC -shared writeonceFS.c -o libwriteonceFS.so
	cp libwriteonceFS.so /lib64
	
${EXE1}:
	$(CC) $(CFLAGS) writeonceFS.c -o testFS

clean:
	rm -rf $(EXE1) $(EXE2) *.o libwriteonceFS.so
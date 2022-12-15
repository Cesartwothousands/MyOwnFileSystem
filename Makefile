.PHONY: all clean

CC = gcc
CFLAGS = -g -Wall

EXE1 = writeonceFS
EXE2 = libwriteonceFS

all: $(EXE1) $(EXE2)

${EXE2}: 
	$(CC) $(CFLAGS) -DWOF_LIB -fPIC -shared writeonceFS.c -o libwriteonceFS.so
	
${EXE1}:
	$(CC) $(CFLAGS) writeonceFS.c -o writeonceFS

clean:
	rm -rf $(EXE1) $(EXE2) *.o libwriteonceFS.so wof.disk writeonceFS
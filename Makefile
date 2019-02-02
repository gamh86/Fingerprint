CC=gcc
WFLAGS=-Wall -Werror
CFILES=fingerprint.c
OFILES=fingerprint.o
LIBS=-lcrypto

fingerprint: $(OFILES)
	$(CC) -g -o fingerprint $(OFILES) $(LIBS)

$(OFILES): $(CFILES)
	$(CC) -g -c $(CFILES) $(LIBS)

clean:
	rm *.o

 CC = gcc
 COPTS = -g -Wall -O0
 LIBS = -lssl -lcrypto -lpthread

 DEBUG_VAR  = -D _DEBUG_
 DEBUG_VAR += -D _DEBUG_OSSL_
 DEBUG_VAR += -D  _DEBUG_TCPIP_

all:
	$(CC) -c $(COPTS) $(DEBUG_VAR) tcpip.c
	$(CC) -c $(COPTS) $(DEBUG_VAR) inossl.c
	$(CC)    $(COPTS) $(DEBUG_VAR) main.c inossl.c tcpip.o $(LIBS)

clean:
	rm -f *.o a.out


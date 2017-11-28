INCLUDE = -I./ -I../
CC = gcc
CFLAGS = -g -Wno-format -DNOOUTPUT
LDFLAGS = -lm -lgmp -lcrypto -lssl -ldl -lpthread -lrt
DEBUGFLAGS = -DDEBUG -DCLNLOGDIR='"../../clnLog/"' -DSVRLOGDIR='"../../svrLog/"'

SOURCE :=			\
	Main.c			\
	utils/FileIO.c	\
	crypto/Base64.c	\
	ssl/SSLLib.c	\
	ssl/S31Svr.c	\
	ssl/S31Cln.c	\
	ssl/SSLSvr.c	\
    myopenssl.c     \
#	crypto/X509.c	\
#	crypto/RSA.c	\


default: myhttpd.o clg.o myopenssl.o
	$(CC) $(CFLAGS) $(SOURCE) http/myhttpd.o http/clg.o $(INCLUDE) -o runSSL $(LDFLAGS)

debug: myhttpd.o clg.o myopenssl.o
	$(CC) $(CFLAGS) $(DEBUGFLAGS) $(SOURCE) http/myhttpd.o http/clg.o $(INCLUDE) -o runSSL $(LDFLAGS)

myhttpd.o: ./http/myhttpd.c
	$(CC) $(CFLAGS) -c ./http/myhttpd.c $(INCLUDE) -o http/myhttpd.o

clg.o: ./http/clg.c
	$(CC) $(CFLAGS) -c ./http/clg.c $(INCLUDE) -o http/clg.o

myopenssl.o: ./myopenssl.c
	$(CC) $(CFLAGS) -c myopenssl.c $(INCLUDE) -o myopenssl.o

clean:
	rm runSSL

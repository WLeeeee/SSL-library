
clg: clg.c
	gcc clg.c -o clg -lrt -lpthread

clg-sat: clg.c
	gcc clg.c -DSATURATION -o clg-sat -lrt -lpthread

fork: myhttpd.c
	gcc myhttpd.c -DFORK -o myhttpd

select: myhttpd.c
	gcc myhttpd.c -g -o myhttpd

.PHONY: fork select clg clg-sat clean

clean:
	rm myhttpd clg clg-sat

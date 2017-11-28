Under the directory with Makefile

1. Server
1.1 Using fork approach
- compile
	make fork
- run HTTP 1.0
	./myhttpd 1.0 1024 0 
- run HTTP 1.1
	./myhttpd 1.1 1024 10 

1.2 Using select approach
- compile
	make select
- run HTTP 1.0
	./myhttpd 1.0 1024 0 
- run HTTP 1.1
	./myhttpd 1.1 1024 10 

2. client load generator
2.1 Saturate purpose client
- compile
	make clg-sat
- run HTTP 1.0 with 5 child processes
	clg-sat 127.0.0.1 1024 1.0 5 
- run HTTP 1.1 with 5 child processes
	clg-sat 127.0.0.1 1024 1.1 5 

2.2 Experimental purpose client
- compile
	make clg
- run HTTP 1.0 with 5 child processes
	clg 127.0.0.1 1024 1.0 5 
- run HTTP 1.1 with 5 child processes
	clg 127.0.0.1 1024 1.1 5 

3. All pictures are under pics directory

4. Saturate server
sudo mn --topo single,3
h1 ./myhttpd 1.1 1024 10 > log1 2> /dev/null &
h3 ./clg-sat h1 1024 1.1 15 > log3 &

5. Run without saturating server
h1 ./myhttpd 1.1 1024 10 > log1 2> /dev/null &
h2 ./clg h1 1024 1.1 15

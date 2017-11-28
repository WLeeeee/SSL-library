#!/bin/sh
a=0
while [ $a -lt 5 ]
do
echo "#################### Test Round $a #################### "

#b=`expr $a + 4`
#./exp_only1.py > result_ssl_$a.txt
./exp.py > result_ssl_$a.txt

#$1
#./exp_openssl_only1.py > result_openssl_$a.txt
./exp_openssl.py > result_openssl_$a.txt

a=`expr $a + 1`
done



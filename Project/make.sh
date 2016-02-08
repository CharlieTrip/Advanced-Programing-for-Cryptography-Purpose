#!/bin/bash

rm ./server/log_server.txt ./client/log_client.txt
gcc -c ./common/utilities.c -o ./build/utilities.o -I/usr/local/opt/openssl/include
gcc -c ./common/crypto.c -o ./build/crypto.o -I/usr/local/opt/openssl/include
gcc -c ./common/errors.c -o ./build/errors.o -I/usr/local/opt/openssl/include

gcc -g ./server/server.c -o ./server/server -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -Icommon ./build/utilities.o ./build/crypto.o ./build/errors.o
gcc -g ./client/client.c -o ./client/client -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -Icommon ./build/utilities.o ./build/crypto.o ./build/errors.o

echo "Parallel processes have started in parallel";
echo

./server/server & ./client/client

wait $PID_LIST

echo
echo "All processes have completed";
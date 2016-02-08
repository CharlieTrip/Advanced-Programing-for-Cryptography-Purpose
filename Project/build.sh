#!/bin/bash

mkdir build semaphore log certificate_client

gcc ./mish/clear_before.c -o ./build/clear_before
gcc ./mish/see.c -o ./build/see

gcc -c ./common/utilities.c -o ./build/utilities.o -I/usr/local/opt/openssl/include
gcc -c ./common/crypto.c -o ./build/crypto.o -I/usr/local/opt/openssl/include
gcc -c ./common/errors.c -o ./build/errors.o -I/usr/local/opt/openssl/include
gcc -c ./common/semaphore.c -o ./build/semaphore.o -I/usr/local/opt/openssl/include

gcc -c ./server/server_cases.c -o ./build/server_cases.o -I/usr/local/opt/openssl/include
gcc -c ./server/server_states.c -o ./build/server_states.o -I/usr/local/opt/openssl/include

gcc -c ./client/client_cases.c -o ./build/client_cases.o -I/usr/local/opt/openssl/include
gcc -c ./client/client_states.c -o ./build/client_states.o -I/usr/local/opt/openssl/include

gcc ./server/server.c -o ./build/server -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -Icommon ./build/utilities.o ./build/crypto.o ./build/errors.o ./build/server_states.o ./build/server_cases.o ./build/semaphore.o
gcc ./client/client.c -o ./build/client -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -Icommon ./build/utilities.o ./build/crypto.o ./build/errors.o ./build/client_states.o ./build/client_cases.o ./build/semaphore.o

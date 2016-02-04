#!/bin/bash

rm ./server/log_server.txt ./client/log_client.txt
gcc ./server/server.c -o ./server/server -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
gcc ./client/client.c -o ./client/client -lcrypto -lssl -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

for cmd in "$@"; do {
  echo "Process \"$cmd\" started";
  $cmd & pid=$!
  PID_LIST+=" $pid";
} done

trap "kill $PID_LIST" SIGINT

echo "Parallel processes have started";

wait $PID_LIST

echo
echo "All processes have completed";
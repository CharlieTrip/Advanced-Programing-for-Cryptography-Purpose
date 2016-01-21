#!/usr/bin/env bash

gcc ./server/server.c -o ./server/server -lcrypto -lssl -I/usr/local/opt/openssl/include
gcc ./client/client.c -o ./client/client -lcrypto -lssl -I/usr/local/opt/openssl/include

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

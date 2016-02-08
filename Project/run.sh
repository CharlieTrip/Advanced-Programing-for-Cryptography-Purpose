#!/bin/bash

./build/clear_before


if [ $# -eq 0 ]
  then
  	echo
    echo "One argument is needed";
    echo
    exit 1;
fi

echo

./build/server "$@" & ./build/client "$@";

echo





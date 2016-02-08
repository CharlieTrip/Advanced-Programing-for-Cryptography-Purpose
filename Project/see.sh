#!/bin/bash

if [ $# -eq 0 ]
  then
  	echo
    echo "One argument is needed";
    echo
    exit 1;
fi


./build/see "$@"
// 
// [WIP]
// 
// All the prototype for the concurrency on the channel

#ifndef semaphore_h
#define semaphore_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

bool check_semaphore_CLIENT();

void change_semaphore_CLIENT();

bool check_semaphore_SERVER();

void change_semaphore_SERVER();

void open_semaphore_to_CLIENT();

void close_all();

#endif
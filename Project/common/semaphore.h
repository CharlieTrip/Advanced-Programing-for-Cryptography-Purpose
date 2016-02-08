// Functions for the concurrency on the channel

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

bool check_semaphore_SERVER();

void change_semaphore_SERVER();

bool check_semaphore_CLIENT();

void change_semaphore_CLIENT();

void open_semaphore_to_CLIENT();

void close_all();

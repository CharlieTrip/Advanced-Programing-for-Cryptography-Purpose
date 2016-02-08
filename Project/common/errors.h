#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "semaphore.h"

#ifndef errors_h
#define errors_h

void handleError(int who, FILE * log_file);

void closeConversation(FILE * log_file);

#endif


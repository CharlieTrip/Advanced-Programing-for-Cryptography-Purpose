// 
// [WIP]
// 
// All the prototype for reading and managing the files

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


FILE *fopen(const char *filename, const char *mode); // "r" for read mode, "a" for write/appending mode 

int fscanf(FILE *filename, const char *destination); 

int fprintf(FILE *filename, const char *destination);
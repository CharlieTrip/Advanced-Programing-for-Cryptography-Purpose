// 
// [WIP]
// 
// All the prototype for reading and managing the files

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//FILE *fopen(const char *filename, const char *mode); // "r" for read mode, "a" for write/appending mode 

//int fscanf(FILE *filename, const char *destination); 

//int fprintf(FILE *filename, const char *tobeprint);

//char *fgets(char *str, int n, FILE *stream);

int get_nth_line( FILE *f, int line_no, char *content_of_line); 

/*save in 'line' the nth line of the file
it returns the content of a line, example: if a line is
'05 +server+: testprova' it returns just 'testprova'
*/
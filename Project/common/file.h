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

/* THE FOLLOWING FUNCTION HAS TO BE MODIFIED AND CAN BE USED BEFORE THE HMAC
save in 'line' the nth line of the file
it returns the content of a line, example: if a line is
'05 +server+: testprova' it returns just 'testprova'
*/

int get_nth_line( FILE *f, int line_no, char *content_of_line); 

int send_message (FILE* channel, const char * source_sender, int number_of_strings,...);

int read_channel (FILE *channel, char *content);

unsigned char *gen_rdm_bytestream (size_t num_bytes)
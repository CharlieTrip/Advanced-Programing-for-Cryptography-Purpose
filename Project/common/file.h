// 
// [WIP]
// 
// All the prototype for reading and managing the files

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <openssl/rand.h>

#define BUF_SIZE ( 2048 )


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

char * gen_rdm_bytestream (size_t num_bytes);

int get_byte_length(char * message);

int get_n_of_blocks(char * message);

int get_nth_length_block(char * message, int n_block);

char * get_nth_block(char * message, int n_block);

void get_random_block(char * message, char * random_block);




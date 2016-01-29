
 /* following code assumes all file operations succeed. In practice,
 * return codes from open, close, fstat, mmap, munmap all need to be
 * checked for error. It returns 0 if the line is read,  -1 in case
 * of error.
 * 
 *  THE FOLLOWING FUNCTION HAS TO BE MODIFIED AND CAN BE USED BEFORE THE HMAC
 * save in 'line' the nth line of the file
 * it returns the content of a line, example: if a line is
 * '05 +server+: testprova' it returns just 'testprova'
*/

 
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <openssl/rand.h>

#define BUF_SIZE ( 4098 )
 

int get_nth_line( FILE *f, int line_no, char *content_of_line)
{
    char buf[ BUF_SIZE ];
    char *line = malloc( BUF_SIZE );
    size_t curr_alloc = BUF_SIZE, curr_ofs = 0;
    int    in_line    = line_no == 1;
    size_t bytes_read;
 
    /* Illegal to ask for a line before the first one. */
    if ( line_no < 1 )
        return -1;
 
    /* Handle out-of-memory by returning NULL */
    if ( !line )
        return -1;
 
    /* Scan the file looking for newlines */
    while ( line_no && 
            ( bytes_read = fread( buf, 1, BUF_SIZE, f ) ) > 0 )
    {
        int i;
 
        for ( i = 0 ; i < bytes_read ; i++ )
        {
            if ( in_line )
            {
                if ( curr_ofs >= curr_alloc )
                {
                    curr_alloc <<= 1;
                    line = realloc( line, curr_alloc );
 
                    if ( !line )    /* out of memory? */
                        return -1;
                }
                line[ curr_ofs++ ] = buf[i];
            }
 
            if ( buf[i] == '\n' )
            {
                line_no--;
 
                if ( line_no == 1 )
                    in_line = 1;
 
                if ( line_no == 0 )
                    break;
            }
        }
    }
 
    /* Didn't find the line? */
    if ( line_no != 0 ) 
    {
        free( line );
        return -1;
    }
 
    /* Resize allocated buffer to what's exactly needed by the string 
       and the terminating NUL character.  Note that this code *keeps*
       the terminating newline as part of the string. 
     */
    line = realloc( line, curr_ofs + 1 );
 
    if ( !line ) /* out of memory? */
        return -1;
 
    /* Add the terminating NUL. */
    line[ curr_ofs ] = '\0';

    for(int i = 0; i<20; i++){
    	if(line[i] == ':'){
    		strcpy(content_of_line,line+i+2);
    		break;
    	}
    }
    return 0;
    free(line);
}



int read_channel (FILE *channel, char *content){

/* 
* Read the content of the channel
*
OLD VERSION
fread(conte,BUF_SIZE+1,1,channel);
return 1;
*/

    size_t bytes_read = 0;
    char   buf[ BUF_SIZE+1 ];
    size_t curr_alloc = BUF_SIZE+1, curr_ofs = 0;

    while ( ( bytes_read = fread( buf, 1, BUF_SIZE, channel ) )  > 0 ){
        int i;
        for ( i = 0 ; i < bytes_read ; i++ ){
                if ( curr_ofs >= curr_alloc ){
                    curr_alloc <<= 1;
                    content = realloc( content, curr_alloc );
                    if ( !content )    /* out of memory? */
                        return -1;
                }
                content[ curr_ofs++ ] = buf[i];
            }
            if ( buf[i] == '\0' ){
                break;
        }
    }
    return 0;
}


int send_message (FILE* channel, int number_of_strings,...){

/* Writes the concatenation of the single string (they can be multiple as the user wants)
* into the file channel (the number of them must be expressed in number_of_strings). Also
* the source_sender must be expressed as this function can be used both for client and server.
* Each string is separated by a tab.
*/


    if (number_of_strings<0){ //number of string cannot be negative
        return -1;
    }

    va_list valist;
    va_start(valist,number_of_strings); //initialization of the va_list

    char * to_be_send = (char *) calloc (BUF_SIZE+1, sizeof(char));

    for(int i = 0; i<number_of_strings; i++){
        if(i != 0){
            strcat(to_be_send,"\t");
        }
        strcat(to_be_send,va_arg(valist, char*));    
    }

    strcat(to_be_send,"\0");

    va_end(valist);

    fputs(to_be_send, channel);
    free(to_be_send);
    return 0;

}



char * gen_rdm_bytestream(size_t num_bytes){

    /* Return a pointer to a string of random bytes  *
     * of a num_bytes length in byte                 */

    int byte_count = 1;
    char data[1];
    char *stream = calloc (num_bytes+1,sizeof(char));
    FILE *fp = fopen("/dev/urandom", "r");
    fread(&data, 1, byte_count, fp);
    fclose(fp);
    srand((int) data);
    
    for (int i = 0; i < num_bytes; i++){
        stream[i] = 50+(rand () % 50);
    }
    stream[num_bytes+1] = '\0';
    return stream;
}





int get_byte_length(char * message){
/* return length of the message in byte (number of char) */
    int length = 0;
    while(message[length] != '\0'){
        length++;
    }
    return length;
}




int get_n_of_blocks(char * message){
/* return number of blocks separated by tab */
    int n_blocks = 0;
    int length;
    length = get_byte_length(message);

    for (int i = 0; i < length; i++){
        if (message[i] == '\t'){
            n_blocks++;
        }
    }
    return n_blocks;
}




int get_nth_length_block(char * message, int n_block){
/* return the lenhth in byte (char) of the n-th block */
    int length;
    length = get_byte_length(message);
    int length_block = 0;
    int count_tab = 1;
    for (int i = 0; i < length; ++i){
        if (message[i] == '\t'){
            count_tab++;
        }
        if (count_tab == n_block && message[i] != '\t'){
                length_block++;
        }
    }
    return length_block;
}



char * get_nth_block(char * message, int n_block){
/* return the content of the n-th block to *
 * not use for extract the random block    */
    int length;
    length = get_byte_length(message);
    int length_block = 0;
    int count_tab = 1;
    char * content;

    for (int i = 0; i < length; ++i){
        if (message[i] == '\t'){
            count_tab++;
        }
        if (count_tab == n_block && message[i] != '\t'){
                content = (message+i);
                break;
        }
    }
    return content;
}



void get_random_block(char * message, char * random_block){
/* use this code to get the random block from the message */

    int random_block_position = 4;
    int length;
    length = get_byte_length(message);
    int count_tab = 1;

    for (int i = 0; i < length; ++i){
        if (message[i] == '\t'){
            count_tab++;
        }
        if (count_tab == 4 && message[i] != '\t'){
                 strncpy (random_block, message+i,  32);
                break;
        }
    }
}


int hexToString(char * hexstring, char* charstring){

    int tmp;
    for (int i = 0; i < strlen(hexstring)/2; i++){
    sscanf(&hexstring[i * 2], "%02x", &tmp);
    charstring[i] = tmp;
    }
    return 1;
}





















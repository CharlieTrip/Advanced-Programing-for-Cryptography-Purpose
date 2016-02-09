
#include "utilities.h"

const char TLS_DHE_RSA_WITH_SHA224[] = "10";
const char TLS_DHE_RSA_WITH_SHA256[] = "11";
const char TLS_DHE_RSA_WITH_SHA384[] = "12";
const char TLS_DHE_RSA_WITH_SHA512[] = "13";
const char TLS_RSA_WITH_SHA224[] = "14";
const char TLS_RSA_WITH_SHA256[] = "15";
const char TLS_RSA_WITH_SHA384[] = "16";
const char TLS_RSA_WITH_SHA512[] = "17";


// Signature ALGORITMS
const char TLS_SIGN_RSA_SHA256[] = "20";

// The Message Type (for the Handshake)

const char TLS_HANDSHAKE[] = "32";
const char TLS_HELLOREQUEST[] = "33";
const char TLS_CLIENTHELLO[] = "34";
const char TLS_SERVERHELLO[] = "35";
const char TLS_SERVER_CERTIFICATE[] = "36";
const char TLS_SERVERKEYEXCHANGE[] = "37";
const char TLS_SERVERHELLODONE[] = "38";
const char TLS_CLIENTKEYEXCHANGE[] = "39";
const char TLS_CHANGECIPHERSPEC[] = "40";
const char TLS_FINISHED[] = "41";
const char TLS_VERSION[] = "42";

// Errors

const char TLS_ERROR_OCCURRED[] = "33 32 30";

// constants used in the code

const int RANDOM_DIM_HELLO = 32;
const int RANDOM_DIM_KEY_EXCHANGE = 46;
const int CIPHERSUITE_TO_USE_POSITION = 5;
const int CERTIFICATE_POSITION = 4;
const int DIM_MASTER_SECRET = 48;
const int PREMAS_SECRET_POSITION = 4;

// Link channel

const char link_channel[] = "channel.txt";

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
                        printf("ERROR: failed receiving message");
                        return 0;
                }
                content[ curr_ofs++ ] = buf[i];
            }
            if ( buf[i] == '\0' ){
                break;
        }
    }
    return 1;
}


int send_message (FILE* channel, int number_of_strings,...){

/* Writes the concatenation of the single string (they can be multiple as the user wants)
* into the file channel (the number of them must be expressed in number_of_strings). Also
* the source_sender must be expressed as this function can be used both for client and server.
* Each string is separated by a tab.
*/
    if (number_of_strings<0){ //number of string cannot be negative
        printf("ERROR: failed sending message\n");
        return 0;
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
    return 1;
}



int gen_rdm_bytestream(size_t num_bytes, char * stream, unsigned char * hexstring){

    /* Return a pointer to a string of random bytes  *
     * of a num_bytes length in byte                 *
     * NOTE: hexstring can be also NULL              */

    int byte_count = 1;
    char data[1];
    FILE *fp = fopen("/dev/urandom", "r");
    fread(&data, 1, byte_count, fp);
    fclose(fp);
    srand((int) data);
    
    for (int i = 0; i < num_bytes; i++){
        stream[i] = (rand ());
    }

    if(hexstring != NULL){
        for (int i = 0; i < num_bytes; ++i){
            sprintf((char*) &hexstring[i*2],"%02x", (unsigned char) stream[i]);
        }
    }
    return 1;
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
/* return the length in byte (char) of the n-th block */
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
/* return the content of the n-th block   */
    int length = get_byte_length(message);
    int count_tab = 1;
    char * content = calloc(BUF_SIZE, sizeof(char));

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


int get_block(char * message, int n_block, char * result){
    
    int length = get_byte_length(message);
    int count_tab = 1; int pos = 0; int end = 0;
    for (int i = 0; i < length; ++i){
        if (message[i] == '\t'){
            count_tab++;
        }
        if (count_tab == n_block)
            break;
        pos++;
    }
    pos++;
    while (1){
        if(message[pos+end] == 0 || message[pos+end] == '\t' || message[pos+end] == '\n'){
            break;
        }
        end ++;
    }
    
    strncpy(result,message+pos,end);
    return 1;
}


int hexToString(char * hexstring, char* charstring){

    int tmp;
    for (int i = 0; i < strlen(hexstring)/2; i++){
    sscanf(&hexstring[i * 2], "%02x", &tmp);
    charstring[i] = tmp;
    }
    charstring[(strlen(hexstring)/2)+1] = 0;
    return 1;
}

int stringToHex(char * string, int length, char * hexstring){

    for (int i = 0; i < length; ++i)
    {
       sprintf(hexstring + i*2, "%02x", (unsigned char) string[i]);
    }
    return 1;
}


int print_file(char * file_name){
    
    /* Print the content of the file on display */
    
    FILE * file = fopen(file_name,"r"); // read mode
    
    if( file == NULL ){
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    char ch;
    while( ( ch = fgetc(file) ) != EOF )
        printf("%c", ch);
    
    fclose(file);
    return 1;
}



















#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <openssl/rand.h>
//#include "extern constants.c"

//COSTANTI
#define BUF_SIZE ( 4098 )

//Ciphersuites

extern const char TLS_DHE_RSA_WITH_SHA256[];
extern const char TLS_RSA_WITH_SHA256[];



// Signature ALGORITMS

extern const char TLS_SIGN_RSA_SHA256[];
extern const char TLS_SIGN_DSA_SHA256[];


extern const char TLS_ALERT[];
extern const char TLS_HANDSHAKE[];

// The Message Type (for the Handshake)

extern const char TLS_HELLOREQUEST[];
extern const char TLS_CLIENTHELLO[];
extern const char TLS_SERVERHELLO[] ;
extern const char TLS_SERVER_CERTIFICATE[] ;
extern const char TLS_SERVERKEYEXCHANGE[] ;
extern const char TLS_SERVERHELLODONE[];
extern const char TLS_CLIENTKEYEXCHANGE[] ;
extern const char TLS_CHANGECIPHERSPEC[];
extern const char TLS_FINISHED[] ;
extern const char TLS_VERSION[] ;

// Errors

extern const char TLS_ERROR_OCCURRED[] ;

// extern constants used in the code

extern const int RANDOM_DIM_HELLO ;
extern const int RANDOM_DIM_KEY_EXCHANGE;
extern const int CIPHERSUITE_TO_USE_POSITION;
extern const int CERTIFICATE_POSITION;
extern const int DIM_MASTER_SECRET ;
extern const int PREMAS_SECRET_POSITION ;

// Link channel

extern const char link_channel[];

int read_channel (FILE *channel, char *content);

int send_message (FILE* channel, int number_of_strings,...);

int gen_rdm_bytestream(size_t num_bytes, char * stream, unsigned char * hexstring);

int get_byte_length(char * message);

int get_n_of_blocks(char * message);

int get_nth_length_block(char * message, int n_block);

char * get_nth_block(char * message, int n_block);

int get_block(char * message, int n_block, char * result);

void get_random_block(char * message, char * random_block);

int hexToString(char * hexstring, char* charstring);

int stringToHex(char * string, int length, char * hexstring);

int print_file(char * file_name);

















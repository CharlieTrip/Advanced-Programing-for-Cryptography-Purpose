#include <stdio.h>
#include <stdlib.h>
#include "../common/crypto.h"
#include "../common/errors.h"

extern const char receiving[];
extern const char sending[]; 
extern const char * link_RSA_prvkey;


extern int RSA_Key_exchange(FILE* log_server, char * ciphersuite_to_use, char* random_from_client, char* random_from_server, DH * dh);

extern int decrypt_secret_RSA(FILE * log_server, char * premaster_secret);

int check_input(char * argv[]);


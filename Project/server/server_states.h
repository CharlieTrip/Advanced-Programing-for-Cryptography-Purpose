
#include <stdio.h>
#include <stdlib.h>
#include "server_cases.h"

extern int hello_server (FILE* log_server, char * ciphersuites_to_use, char * random_from_client, char * random_from_server);

extern int send_certificate(FILE* log_server, char * ciphersuite_to_use);

extern int server_key_exchange(FILE* log_server, char * ciphersuite_to_use, char* random_from_client, char* random_from_server, DH * dh);

extern int hello_done(FILE* log_server);

extern int receive_exchange_key(FILE * log_server, char * ciphersuite_to_use, unsigned char * master_secret, char * premaster_secret, char * random_from_client, char * random_from_server);

extern int receive_change_cipher_spec(FILE * log_server);

extern int change_cipher_spec(FILE * log_server, unsigned char * master_secret, char * ciphersuite_to_use);

extern int server_finished(FILE * log_server, char * master_secret, char * ciphersuite_to_use);



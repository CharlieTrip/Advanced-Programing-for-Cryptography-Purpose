#include <stdio.h>
#include <stdlib.h>
#include "client_cases.h"


extern int hello_client (FILE* log_client, char * random_from_client, char * ciphersuite_to_use);

extern int receive_hello_server (FILE* log_client, char * random_from_server);

extern int receive_certificate (FILE* log_client, char * ciphersuite_to_use);

extern int receiving_key_exchange(FILE * log_client, char * ciphersuite_to_use, char * random_from_client, char * random_from_server, DH * dh);

extern int exchange_key(FILE* log_client, char * ciphersuite_to_use, unsigned char * master_secret, char * premaster_secret, char * random_from_client, char * random_from_server, DH * dh);

extern int change_cipher_spec(FILE* log_client);

extern int client_finished(FILE* log_client, char * master_secret, char * ciphersuite_to_use);

extern int receive_change_cipher_spec(FILE * log_client);

extern int receive_server_finished(FILE* log_client, unsigned char * master_secret, char * ciphersuite_to_use);


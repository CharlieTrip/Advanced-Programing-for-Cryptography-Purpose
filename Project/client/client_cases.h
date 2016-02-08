#include <stdio.h>
#include <stdlib.h>
#include "../common/crypto.h"
#include "../common/errors.h"

extern const char sending[];
extern const char receiving[]; 
extern const char * RSA_link_public_key;
extern const char * RSA_link_certificate;

int encrypt_secret_RSA(FILE* log_client, char * premaster_secret);

int encrypt_secret_DH(FILE* log_client, char * premaster_secret, char * received_message, DH * dh);

char * get_ciphersuite(char * argv[]);

char * check_input(char * argv[]);

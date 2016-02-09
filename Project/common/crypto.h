#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>
#include "utilities.h"


char * X509_to_string(X509 *cert);

X509 *string_to_X509(char *string);

char * get_certificate( char * link);

int get_pubkey(const char * pubkey_filestr, const char * cert_filestr);

void choose_best_ciphersuite(char * message, char * best_chipersuite);

RSA * TLS_createRSAWithFilename(char * filename, char * public_or_private);
 
int TLS_RSA_public_encrypt(unsigned char * data, int data_len, const char * key, char *encrypted);

int TLS_RSA_private_decrypt(unsigned char * enc_data, int data_len, const char * key, unsigned char * decrypted);

int is_needed_keyexchange(char * ciphersuite_to_use);

int P_Hash( const EVP_MD * evp_md, int round, char * secret, int len_secret, char * text, int len_text, char * output,  int sha_len);

int compute_master_secret(unsigned char * master_secret, const EVP_MD * evp_md, char * random_from_client, char * random_from_server, char * premaster_secret, char * label);

int compute_hash_log(FILE * log, const EVP_MD * evp_md, unsigned char * master_secret, unsigned int len_master_secret, unsigned char * hash_server_log);










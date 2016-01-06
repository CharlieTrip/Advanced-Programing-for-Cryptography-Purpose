// 
// [WIP]
// 
// All the prototype for the crypto elements to be used in the protocol
// Using OpenSSL API for this part

// 
// All the includes for the OpenSSL



#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


// 
// Certificate 

int verifyCertificate(FILE *certificate);


// 
// RSA functions

RSA * createRSA(unsigned char * key,int public);
int RSA_public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int RSA_private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int RSA_private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int RSA_public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted); 


// 
// DH function
// [WIP on prototypes]


DH * createDH(unsigned char * key,int public);
int DH_public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int DH_private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int DH_private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int DH_public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted); 

// 
// Hashing functions for HMAC

int HMAC_SHA1(unsigned char* key ,unsigned char* data, unsigned char* expected unsigned char* result);
int HMAC_SHA2(unsigned char* key ,unsigned char* data, unsigned char* expected unsigned char* result);
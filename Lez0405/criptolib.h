//
//  criptolib.h
//  CriptoLib
//
//  Created by Darka on 19/10/15.
//  Copyright © 2015 Darka. All rights reserved.
//

#ifndef criptolib_h
#define criptolib_h

/********************** HASH FUNCTIONS ************************/

//lenght of the result string
#define SHA1_BYTE_SIZE 20
extern void sha1(unsigned char *word,long int word_lenght,unsigned char *res);

//lenght of the result string
#define SHA256_BYTE_SIZE 32
extern void sha256(unsigned char *word,long int word_lenght,unsigned char *res);

//lenght of the result string
#define SHA224_BYTE_SIZE 28
extern void sha224(unsigned char *word,long int word_lenght,unsigned char *res);

extern void sha512(unsigned char *word,long int word_lenght,unsigned char *res);

/**********************    GENERAL   ************************/
typedef struct{
    long int hash_out;
    long int blockSize;
    void (*hash)(unsigned char*,long int,unsigned char*);
}hmac_params;

extern const hmac_params HMAC_SHA1_PARAMS;
extern const hmac_params HMAC_SHA256_PARAMS;

extern void hmac(unsigned char *key, long int key_lenght,
          unsigned char *message, long int message_lenght,
          unsigned char *result,hmac_params params);

/*********************************/
void PBKDF2(unsigned char *password, long int key_lenght,
            unsigned char *salt,int c,int kLen,unsigned char *DK);
#endif /* criptolib_h */


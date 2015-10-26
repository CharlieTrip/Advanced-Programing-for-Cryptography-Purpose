//
//  PBKDF2.c
//  criptolib
//
//  Created by Darka on 26/10/15.
//  Copyright © 2015 Darka. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "criptolib.h"

/*
PRF is a pseudorandom function of two parameters with output length hLen (e.g. a keyed HMAC)
Password is the master password from which a derived key is generated
Salt is a sequence of bits, known as a cryptographic salt
c is the number of iterations desired
kLen is the desired length of the derived key in bit
DK is the generated derived key
 */

void PBKDF2(unsigned char *password, long int key_lenght,
            unsigned char *salt,int c,int kLen,unsigned char *DK){
    
    uint32_t hLen=SHA1_BYTE_SIZE;
    uint32_t len=ceil((float)kLen/(float)hLen); //TODO:parametrizzare per differenti hash
    uint32_t r = kLen-(len-1)*hLen;
    unsigned char *T=calloc(sizeof(char),SHA1_BYTE_SIZE*len);
    unsigned char *U=calloc(sizeof(char),SHA1_BYTE_SIZE);
    for(int i=0;i<len;i++)
    {
        //T[i]=0;
        memcpy(U, salt, strlen((char*)salt)); //TODO:salt lenght
        memcpy(U+4, &i,4);

        for(int j=1;j<c;j++){
            hmac(password, key_lenght, U, SHA1_BYTE_SIZE,U, HMAC_SHA1_PARAMS);
            for(int i=0;i<SHA1_BYTE_SIZE*len;i++)
                T[i]^=U[i];
        }
        printf("%02x",*T);
    }
    
}
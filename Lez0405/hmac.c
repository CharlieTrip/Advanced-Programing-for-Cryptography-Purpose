//
//  hmac.c
//  criptolib
//
//  Created by Darka on 20/10/15.
//  Copyright © 2015 Darka. All rights reserved.
//
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "criptolib.h"

const hmac_params HMAC_SHA1_PARAMS={SHA1_BYTE_SIZE,64,&sha1};
const hmac_params HMAC_SHA256_PARAMS={SHA256_BYTE_SIZE,64,&sha256};

void hmac(unsigned char *key, long int key_lenght,
          unsigned char *message, long int message_lenght,
          unsigned char *result,hmac_params params){
    
    unsigned char *new_key = calloc(params.blockSize,sizeof(char));
    unsigned char *o_key_pad = calloc(params.blockSize+params.hash_out/2,sizeof(char));
    unsigned char *i_key_pad = calloc(params.blockSize+message_lenght,sizeof(char));
    
    if(key_lenght>params.blockSize)
        params.hash(key,key_lenght,new_key);
    else memcpy(new_key, key, key_lenght);
    
    for(int i=0;i<params.blockSize;i++){
        *(o_key_pad+i)=*(new_key+i)^0x5c;
        *(i_key_pad+i)=*(new_key+i)^0x36;
    }
    
    memcpy(i_key_pad+params.blockSize, message, message_lenght);

    params.hash(i_key_pad,params.blockSize+message_lenght,result);

    memcpy(o_key_pad+params.blockSize, result, params.hash_out);
    
    params.hash(o_key_pad,params.blockSize+params.hash_out,result);
    
    free(new_key);
    free(o_key_pad);
    //free(i_key_pad);//TODO:check it
}

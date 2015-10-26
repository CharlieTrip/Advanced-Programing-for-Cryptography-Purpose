//
//  sha1.c
//  criptolib
//
//  Created by Darka on 14/10/15.
//  Copyright © 2015 Darka. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "criptolib.h"

#define ROTL(n,r)({(n<<r)|(n>>(32-r));})
#define REV(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})

void sha1_core(uint32_t *message,unsigned long long lenght,unsigned char *res);

uint32_t *sha1_padding(unsigned char *word,uint64_t word_lenght8,unsigned long long *lenght_32);
/*
 Calculate the sha1 digest of a string word of lenght word_lenght
 */
void sha1(unsigned char *word,long int word_lenght,unsigned char *res){
    unsigned long long lenght;
    //prepare string for processing
    unsigned char *to_hash=malloc(word_lenght*sizeof(unsigned char));
    memcpy(to_hash, word, word_lenght*sizeof(unsigned char));
    uint32_t *padded_message = sha1_padding(to_hash,word_lenght,&lenght); //not need to free to_hash
    sha1_core(padded_message, lenght,res);
    free(padded_message);
}

void sha1_core(uint32_t *message,unsigned long long lenght,unsigned char *res){
    //starting constants
    uint32_t h[5]={0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    
    const uint32_t k[4]={0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xCA62C1D6};
    
    uint32_t a ,b, c, d, e, f;
    
    uint32_t *w=malloc(80*sizeof(uint32_t));
    if(w==NULL){
        printf("Error malloc in sha1_core");
        abort();
    }
    //main loop of the hash
    for(int chunk=0;chunk<lenght;chunk+=16){
        //copy the chunk
        memcpy(w,message+chunk, 16*sizeof(uint32_t));
        
        for(int i=16;i<80;i++)
            w[i]=ROTL((w[i-3]^w[i-8]^w[i-14]^w[i-16]),1);
        
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = 0;
        
        for(int i=0;i<80;i++){
            if(i<=19)
                f=(b&c)|((~b)&d);
            
            else if (i<=39)
                f = b^c^d;
            
            else if(i<=59)
                f = (b & c)|(b & d)|(c & d);
           	
            else f = b^c^d;
            
            uint32_t temp = (ROTL(a,5) + f + e + k[i/20] + w[i]);
            e = d;
            d = c;
            c = ROTL(b,30);
            b = a;
            a = temp;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
    free(w);
    for(int i=0;i<5;i++){
        h[i]=REV(h[i]);
        memcpy(res+i*4,&h[i], 4);
    }
    //sprintf((char*)res,"%u%u%u%u%u",h0,h1,h2,h3,h4);
}

//Padding function, note the word has to be stored in heap
//word lenght is byte_lenght
uint32_t *sha1_padding(unsigned char *word,uint64_t word_lenght8,unsigned long long *lenght_32){
    
    //compute the number of byte that has to be 0
    uint64_t n_zeros8=(513-(word_lenght8*8-447)%512)/8;
    
    //output lenght
    *lenght_32=(word_lenght8+n_zeros8+8)/4;
    
    //realloc memory for padding
    uint32_t *bit32_message=(uint32_t*)realloc(word,*lenght_32*sizeof(uint32_t));
    if(bit32_message==NULL){
        printf("Error realloc in sha1_padding");
        abort();
    }
    //adding zeros
    memset((char*)bit32_message+word_lenght8,0,*lenght_32*4-word_lenght8);
    
    //reverse byte order
    for(int i=0;i<word_lenght8;i+=4)
        *(bit32_message+i/4)=REV(*(bit32_message+i/4));
    
    //add 1 to the end of the message
    memset((char*)bit32_message+(4*(word_lenght8/4)+3-word_lenght8%4),0x80,1);
    
    //add the lenght of the message in bit at the end of the output
    *(bit32_message+*lenght_32-1)=((word_lenght8*8)<<32)>>32;
    *(bit32_message+*lenght_32-2)=(word_lenght8*8)>>32;
    return bit32_message;
}

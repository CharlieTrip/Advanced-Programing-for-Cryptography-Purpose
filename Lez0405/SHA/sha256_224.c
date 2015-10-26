//
//  sha256_224.c
//  criptolib
//
//  Created by Darka on 19/10/15.
//  Copyright © 2015 Darka. All rights reserved.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "criptolib.h"

#define REV(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})

#define ROTR(n,r)({(n>>r)|(n<<(32-r));})
#define Ch(e,f,g) ((e&f)^((~e)&g))
#define Maj(a,b,c) ((a&b)^(a&c)^(b&c))
#define Sigma0(a) (ROTR(a,2)^ROTR(a,13)^ROTR(a,22))
#define Sigma1(e) (ROTR(e,6)^ROTR(e,11)^ROTR(e,25))
#define sigma0(a) (ROTR(a,7)^ROTR(a,18)^(a>>3))
#define sigma1(a) (ROTR(a,17)^ROTR(a,19)^(a>>10))

//starting constants
const uint32_t k256[64]={0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_core(uint32_t *message,unsigned long long lenght,unsigned char *res,uint32_t H[], const uint32_t k[]);

uint32_t *sha256_padding(unsigned char *word,uint64_t word_lenght8,unsigned long long *lenght_32);

void sha256(unsigned char *word,long int word_lenght,unsigned char *res){
    
    unsigned long long lenght;
    //prepare string for processing
    unsigned char *to_hash=malloc(word_lenght*sizeof(unsigned char));
    if(to_hash==NULL){
        printf("Error realloc in sha256");
        abort();
    }
    memcpy(to_hash, word, word_lenght*sizeof(unsigned char));
    
    uint32_t *padded_message = sha256_padding(to_hash,word_lenght,&lenght); //do not need to free to_hash
    
    uint32_t H[]={0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    
    sha256_core(padded_message, lenght,res,H,k256);
    
    free(padded_message);
}

void sha224(unsigned char *word,long int word_lenght,unsigned char *res){
    unsigned long long lenght;
    //prepare string for processing
    unsigned char *to_hash=malloc(word_lenght*sizeof(unsigned char));
    if(to_hash==NULL){
        printf("Error realloc in sha224");
        abort();
    }
    memcpy(to_hash, word, word_lenght*sizeof(unsigned char));
    
    uint32_t *padded_message = sha256_padding(to_hash,word_lenght,&lenght); //do not need to free to_hash
    
    uint32_t H[]={0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
    
    sha256_core(padded_message, lenght,res,H,k256);
    
    free(padded_message);
}

void sha256_core(uint32_t *message,unsigned long long lenght,unsigned char *res,
               uint32_t H[], const uint32_t k[]){
    uint32_t a ,b, c, d, e, f, g, h, temp1, temp2;
    
    uint32_t *w=malloc(64*sizeof(uint32_t));
    if(w==NULL){
        printf("Error malloc in sha2_core");
        abort();
    }
    
    //main loop of the hash
    for(int chunk=0;chunk<lenght;chunk+=16){
        //copy the chunk
        memcpy(w,message+chunk, 16*sizeof(uint32_t));
        
        for(int i=16;i<64;i++)
            w[i]=w[i-16]+w[i-7]+sigma0(w[i-15])+sigma1(w[i-2]);
        
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];
        //compression
        for(int i=0;i<64;i++){
            temp1 = h+Sigma1(e)+Ch(e,f,g)+k[i]+w[i];
            temp2= Sigma0(a)+Maj(a,b,c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
            
        }
        
        H[0]+= a;
        H[1]+= b;
        H[2]+= c;
        H[3]+= d;
        H[4]+= e;
        H[5]+= f;
        H[6]+= g;
        H[7]+= h;
    }
    free(w);
    for(int i=0;i<8;i++){
        H[i]=REV(H[i]);
        memcpy(res+i*4,&H[i], 4);
    }
    //sprintf((char*)res,"%08x%08x%08x%08x%08x%08x%08x%08x",h0,h1,h2,h3,h4,h5,h6,h7);
}

uint32_t *sha256_padding(unsigned char *word,uint64_t word_lenght8,unsigned long long *lenght_32){
    
    //compute the number of byte that has to be 0
    uint64_t n_zeros8=(513-(word_lenght8*8-447)%512)/8;
    
    //output lenght
    *lenght_32=(word_lenght8+n_zeros8+8)/4;
    
    //realloc memory for padding
    uint32_t *bit32_message=(uint32_t*)realloc(word,*lenght_32*sizeof(uint32_t));
    if(bit32_message==NULL){
        printf("Error realloc in sha2_padding");
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

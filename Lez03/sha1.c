#include <stdio.h>
// #include <omp.h>
#include <stdlib.h>


void sha1(char *stringa,char *digest);


int main(int argc , char *argv[]){
	char digests[101];
	if(argc == 2){
		sha1(argv[1],digests);
	}
	printf("%s\n",digests);
	
	return 0;
}


void sha1(char *stringa,char *digest){
	
	unsigned int word[80] = {0};
	unsigned int wordtmp = 0;
	
	char posizione = 0;
	char* carattere;
	
	unsigned int a = 0;
	unsigned int b = 0;
	unsigned int c = 0;
	unsigned int d = 0;
	unsigned int e = 0;

	unsigned int k = 0;
	unsigned int f = 0;

	unsigned int hh0,hh1,hh2,hh3,hh4;

	unsigned int temp = 0;



	carattere = stringa;

	while (*carattere !='\0'){
		word[posizione/4] = word[posizione/4] ^ (*carattere << (24-(8*(posizione%4))))  ;
		posizione++;
		//  [0123] - [4567] - ... - []
		//  4*0+[0123] - 4*1+[0123] - ... - []
		// scanf("%c",&carattere);
		carattere++;
	}

// Padding
// 10*	
	word[posizione/4] = word[posizione/4] ^ ((1<<7) << (24-(8*(posizione%4))))  ;
	
	word[15] = 8*(posizione);


	for(int i = 16; i < 80; i ++){
			wordtmp = (word[i-3] ^ word[i-8] ^ word[i-14] ^ word[i-16]);
			word[i] = wordtmp<< 1 ^ wordtmp >> 31;
		}

	// Initialize 
	hh0 = 0x67452301;
	hh1 = 0xEFCDAB89;
	hh2 = 0x98BADCFE;
	hh3 = 0x10325476;
	hh4 = 0xC3D2E1F0;


	a = hh0;
	b = hh1;
	c = hh2;
	d = hh3;
	e = hh4;

	
	for(int i = 0 ; i < 80 ; i++){

		if( i <= 19 ){
			f = (b & c) | ((~b) & d);
			k = 0x5A827999;
		}
		else if (i <= 39){
			f = b ^ c ^ d;
            k = 0x6ED9EBA1;
		}
		else if (i <= 59){
			f = (b & c) | (b & d) | (c & d) ;
            k = 0x8F1BBCDC;
		}
		else{
			f = b ^ c ^ d;
            k = 0xCA62C1D6;
		}

		temp = ((a << 5) ^ a >> (32-5)) + f + e + k + word[i];
        e = d;
        d = c;
        c = (b << 30) ^ (b >> 2);
        b = a;
        a = temp;

		// printf("%d - %x %x %x %x %x\n",i,a,b,c,d,e);
	}

    hh0 += a;
    hh1 += b;
    hh2 += c;
    hh3 += d;
    hh4 += e;


    snprintf(digest, 46, "%08x%08x%08x%08x%08x", hh0,hh1,hh2,hh3,hh4);

	// for(int i = 0;i < 15;i++)
	// 	printf("%d %d %d %d \n",(int)(word[i]>> 24) , (int)(word[i]>>16)%(1<<8),(int)(word[i]>>8)%(1<<8), (int)(word[i])%(1<<8) );

}
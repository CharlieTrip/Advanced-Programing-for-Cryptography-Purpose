#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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


	// Creo le variabili per le varie word che servono

	unsigned int word[1000][80] = {0};
	unsigned int wordtmp = 0;

	
	// Indici per la posizione nella stringa
	
	unsigned int posizione = 0;
	char* carattere;
	unsigned int lunghezza = 0;
	

	// Variabili per lo sha1

	unsigned int a = 0;
	unsigned int b = 0;
	unsigned int c = 0;
	unsigned int d = 0;
	unsigned int e = 0;

	unsigned int k = 0;
	unsigned int f = 0;

	unsigned int hh0,hh1,hh2,hh3,hh4;

	unsigned int temp = 0;



	// Mi salvo quanto è lunga la stringa

	lunghezza = (int) strlen(stringa);


	// Inizio a leggere la stringa e a salvarla nelle word

	carattere = stringa;

	while (*carattere !='\0'){
		word[posizione/64][(posizione % 64)/4] = word[posizione/64][(posizione % 64)/4] ^ (*carattere << (24-(8*(posizione%4))))  ;
		posizione++;

		// Quel che faccio è incastrare nella giusta word alla giusta posizione shiftandolo
		// 
		//  [0123] - [4567] - ... - []
		//  4*0+[0123] - 4*1+[0123] - ... - []

		carattere++;
	}


	// Padding
	// 10*

	word[posizione/64][(posizione % 64)/4] = word[posizione/64][(posizione % 64)/4] ^ ((1<<7) << (24-(8*(posizione%4))))  ;
	posizione ++;


	// Riempio con gli zeri

	while(((posizione) % 64) != 56){
		posizione ++;
	}

	word[posizione/64][14] = (int)(((long)8*(lunghezza))>>32);	
	word[posizione/64][15] = (int)((long)8*(lunghezza));



	// Initialize 

	hh0 = 0x67452301;
	hh1 = 0xEFCDAB89;
	hh2 = 0x98BADCFE;
	hh3 = 0x10325476;
	hh4 = 0xC3D2E1F0;




	// Questa è la traduzione pari pari del pseudocodice che si trova su Wikipedia

	for(int j = 0 ; j <= (posizione/64);j++){
	
		a = hh0;
		b = hh1;
		c = hh2;
		d = hh3;
		e = hh4;



		for(int i = 16; i < 80; i ++){
				wordtmp = (word[j][i-3] ^ word[j][i-8] ^ word[j][i-14] ^ word[j][i-16]);
				word[j][i] = wordtmp<< 1 ^ wordtmp >> 31;
			}


		
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

			temp = ((a << 5) ^ a >> (32-5)) + f + e + k + word[j][i];
	        e = d;
	        d = c;
	        c = (b << 30) ^ (b >> 2);
	        b = a;
	        a = temp;

		}

	    hh0 += a;
	    hh1 += b;
	    hh2 += c;
	    hh3 += d;
	    hh4 += e;
	}

    snprintf(digest, 46, "%08x%08x%08x%08x%08x", hh0,hh1,hh2,hh3,hh4);


}
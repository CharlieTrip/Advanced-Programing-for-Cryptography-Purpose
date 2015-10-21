#include <stdio.h>
#include <stdlib.h>


void hmac(char *stringa, char *chiave ,char *digest);


int main(int argc , char *argv[]){

	char digests[101];
	if(argc == 3){
		hmac(argv[1],argv[2],digests);
	}

	printf("%s\n",digests);
	
	return 0;
}



void hmac(char *stringa,char *chiave,char *digest){
	
	// To be implemented and commented

}
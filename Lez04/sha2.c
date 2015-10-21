#include <stdio.h>
#include <stdlib.h>


void sha2(char *stringa,char *digest);


int main(int argc , char *argv[]){

	char digests[101];
	if(argc == 2){
		sha2(argv[1],digests);
	}

	printf("%s\n",digests);
	
	return 0;
}



void sha2(char *stringa,char *digest){
	
	// To be implemented and commented

}
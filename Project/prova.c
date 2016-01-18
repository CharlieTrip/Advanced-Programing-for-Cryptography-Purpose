#include <stdio.h>
#include <stdlib.h>
#include "./common/file.c"

int main(){

	char * certificate = calloc(800,sizeof(char));
	FILE* certificate_file = fopen("cert.txt","r");
	read_channel(certificate_file,certificate);
	fclose(certificate_file);

	printf("%s\n", certificate);

	free(certificate);


	return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int print_file(char * file_name){
    
    /* Print the content of the file on display */
    
    FILE * file = fopen(file_name,"r"); // read mode
    
    if( file == NULL ){
        perror("Error while opening the file.\n");
        exit(EXIT_FAILURE);
    }
    char ch;
    while( ( ch = fgetc(file) ) != EOF )
        printf("%c", ch);
    
    fclose(file);
    return 1;
}



int main(int argc, char *argv[]){

	    // Control before to start
    
	if (!strcmp(argv[1], "-client")){
		print_file("./log/log_client.txt");
	}
	else if (!strcmp(argv[1], "-server")){
		print_file("./log/log_server.txt");
	}
    else if (!strcmp(argv[1], "-readme")){
        print_file("./README.txt");
    }
    else {
    	print_file("./mish/usagesee.txt");
    }
    return 1;
}

















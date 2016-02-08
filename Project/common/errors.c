
#include "errors.h"


void handleError(int who, FILE * log_file){

    char * client_server;

	/* Write error message on the channel in order to make finish  *
	 * the conversation with the other communicant                 *
     * the error message correspond to "33 32 30"                  */

	FILE* file = fopen("channel.txt","w");
	fprintf(file, "33 32 30");
	fclose(file);
         
	if (who == 0){
		client_server = "Client";
        printf("%s: comunication closed.\n", client_server );
		change_semaphore_CLIENT();
		fclose(log_file);
		exit(-1);
	}
	else{
        client_server = "Server";
        printf("%s: comunication closed.\n", client_server );
		change_semaphore_SERVER();
		fclose(log_file);
		exit(-1);
	}
}



void closeConversation(FILE * log_file){
    
    /* When client or server receive an error *
     * message, close their communication     */
    if (access("./semaphore/ok_server.txt", F_OK) != -1)
        remove("./semaphore/ok_server.txt");
    if (access("./semaphore/ok_client.txt", F_OK) != -1)
        remove("./semaphore/ok_client.txt");
	fclose(log_file);
	exit(-1);
}

















#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "client_states.c"



int main(){

	FILE *log_client;
	char ciphersuite_to_use[3];
	char * random_from_server = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * random_from_client = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * premaster_secret = calloc(2+RANDOM_DIM_KEY_EXCHANGE+1,sizeof(char));
	log_client = fopen("./client/log_client.txt","w");

	int state = 0;
	/* The variable 'state'indicates the state of the client, i.e.
	* state = 0 means: the client is sending through the cannel to the
	*				   server 
	* 
	* state = 1 means: the client is receiving the "hello" message from the server
	* 
	* state = 2 means: the client is receiving the certificate from the server
	*
	* state = 3 means: the client is receiving the exchanging_key from the server 
	* (only in some cases)
	*
	* state = 4 means: the client is sending its exchanging_key
	*
	* state = 5 means:
	*/
	// TODO add an input command line to make the user able to choose the protocols to use
	
	while(true){
		if (check_semaphore_CLIENT() == true){ // check if the file is exists

			if(state == 0){
				hello_client(log_client, random_from_client);
				printf("Client: hello_client\n"); // to delete
				state++;
			}
			else if(state == 1){
				receive_hello_server(log_client, ciphersuite_to_use, random_from_server);
				printf("Client: receive_hello_server\n"); // to delete
				state++;
			}
			else if(state == 2){
				receive_certificate (log_client);
				printf("Client: receive_server_certificate\n"); // to delete
				if(is_needed_keyexchange(ciphersuite_to_use)){
					state = 3; // here we see if the key_echange from server is needed or not
				}              // if not we jump a state 
				else{
					state = 4;
				}
			}
			else if(state == 3){
				//TO DO receiving_key_exchange from server; (case DHE)
				printf("Client: receive_server_key_exchange\n"); // to delete
				state++;
			}
			else if(state == 4){
				exchange_key(log_client, ciphersuite_to_use, premaster_secret, random_from_client, random_from_server);
				printf("Client: exchange_key\n"); // to delete
				state++; // here we need to see if the client has to to the change cipher,
						 // maybe with a function like "is_needed_change_cipher",
						 // if not, then just send the "client_finished" message
			}
			else if(state == 5){
				change_semaphore_CLIENT();
				printf("Client 5\n"); // to delete
				break;
			}
			
			change_semaphore_CLIENT();
		}
	}
	close_all();
	fclose(log_client);
	free(random_from_server);
	free(premaster_secret);

	return 0;
}

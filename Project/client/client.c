#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "client_states.h"

int main(int argc, char *argv[]){
    
    
    char * ciphersuite_to_use = check_input(argv);
    
    
    DH * dh;
    if(is_needed_keyexchange(ciphersuite_to_use)){
    // here we see if the key_echange from server is needed or not
         dh = DH_new();
    }
	FILE *log_client;
	char * random_from_server = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * random_from_client = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * premaster_secret = calloc(2+RANDOM_DIM_KEY_EXCHANGE+1,sizeof(char));
	unsigned char * master_secret = calloc(DIM_MASTER_SECRET+1, sizeof(unsigned char));
	log_client = fopen("log/log_client.txt","w");

	int state = 0;
	/* The variable 'state' indicates the state of the client, i.e.
	* state = 0 means: the client is sending through the cannel to the
	*				   server 
	* 
	* state = 1 means: the client receive the "hello" message from the server
	* 
	* state = 2 means: the client receive the certificate from the server
	*
	* state = 3 means: the client receive the exchanging_key from the server (only in some cases)
	*
	* state = 4 means: the client send its exchanging_key
	*
	* state = 5 means: the client send the message change cipher spec
	*
	* state = 6 means: the client send the message client finished
	*
	* state = 7 means: the client receive the message server change cipher spec
	*
	* state = 8 means: the client receive the message sever finished
	*
	*/
	
	while(true){
        usleep(100);
		if (check_semaphore_CLIENT() == true){ // check if the file is exists

			if(state == 0){
				if(!hello_client(log_client, random_from_client, ciphersuite_to_use)){
					handleError( 0, log_client);
				}
				printf("Client: hello_client\n");
				state++;
			}
			else if(state == 1){
				if(!receive_hello_server(log_client, random_from_server)){
					handleError( 0, log_client);
				}
				state++;
			}
			else if(state == 2){
				if(!receive_certificate (log_client, ciphersuite_to_use)){
					handleError( 0, log_client);
				}
				if(is_needed_keyexchange(ciphersuite_to_use)){
					state = 3; // here we see if the key_echange from server is needed or not
				}              // if not we jump a state 
				else{
					state = 4;
				}				
			}
			else if(state == 3){
				if(!receiving_key_exchange(log_client, ciphersuite_to_use, random_from_client, random_from_server, dh)){
					handleError( 0, log_client);
				}
                state++;
			}
			else if(state == 4){
				if(!exchange_key(log_client, ciphersuite_to_use, master_secret, premaster_secret, random_from_client, random_from_server, dh)){
					handleError( 0, log_client);
				}
				printf("Client: exchange_key\n");
				state++;
			}
			else if(state == 5){
				if(!change_cipher_spec(log_client)){
					handleError( 0, log_client);
				}
				printf("Client: change_cipher_spec\n");
				state++;
			}
			else if(state == 6){
				if(!client_finished(log_client, (char*) master_secret, ciphersuite_to_use)){
					handleError( 0, log_client);
				}
				printf("Client: client_finished\n");
				state++;
			}
			else if(state == 7){
				if(!receive_change_cipher_spec(log_client)){
					handleError( 0, log_client);
				}
				state++;
			}
			else if (state == 8){
				if(!receive_server_finished(log_client, master_secret, ciphersuite_to_use)){
					handleError( 0, log_client);
				}
				change_semaphore_CLIENT();
				break;
			}		
			change_semaphore_CLIENT();
		}
	}
	close_all();
    remove("channel.txt");
	fclose(log_client);
    DH_free(dh);
    free(random_from_client);
	free(random_from_server);
	free(premaster_secret);
	return 0;
}

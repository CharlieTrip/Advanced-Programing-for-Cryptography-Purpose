#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "server_states.h"

int main(int argc, char *argv[]){
    
    
    check_input(argv);
    
    DH * dh;
	FILE *log_server;
	char ciphersuite_to_use[3];
	char * random_from_server = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * random_from_client = calloc(RANDOM_DIM_HELLO+1, sizeof(char));
	char * premaster_secret = calloc(BUF_SIZE,sizeof(char));
	unsigned char * master_secret = calloc(DIM_MASTER_SECRET+1, sizeof(unsigned char));

	log_server = fopen("./log/log_server.txt","w");

    open_semaphore_to_CLIENT();

	int state = 0;

	/* The variable 'state' indicates the state of the server, i.e.
	* state = 0 means: the server read what the client has sent, choose the best ciphersuite between the disponible ones,
	*				   send the message Hello ecc... to the client
	* state = 1 means: the server send the certificate according to the chosen ciphersuite
	*
	* state = 2 means: the server compute and send the key exchange (only in case of DHE)
	* 
	* state = 3 means: the server send the message hello done
	*
	* state = 4 means: the sever receive the client key exchange, the compute the premaster secret and finally the maste secret
	*
	* state = 5 means: the server receive the message change cipher spec from the client
	*
	* state = 6 means: the server send the message change cipher spec
	*
	* state = 7 means: the server receive the message sever finished
	*
	*/

	while(true){
        usleep(100);
		if (check_semaphore_SERVER() == true){  // checks if the file is exists

			if(state == 0){
				if(!hello_server(log_server, ciphersuite_to_use, random_from_client, random_from_server)){
					handleError( 1, log_server);
				}
				printf("Server: hello_server\n");
				state++;
			}
			else if(state == 1){
				if(!send_certificate(log_server,ciphersuite_to_use)){
					handleError( 1, log_server);
				}
				printf("Server: send_certificate\n");
				if(is_needed_keyexchange(ciphersuite_to_use)){
					state = 2; // here we see if the key_echange from server is needed or not
				}              // if not we jump a state 
				else{
					state = 3;
				}
			}
			else if(state == 2){
                dh = DH_new();
				if(!server_key_exchange (log_server, ciphersuite_to_use, random_from_client, random_from_server, dh)){
					handleError( 1, log_server);
				}
				printf("Server: key_exchange\n");
				state++;
			}
			else if(state == 3){
				if(!hello_done(log_server)){
					handleError( 1, log_server);
				}
				printf("Server: hello_done\n");
				state++;
			}
			else if(state == 4){
				if(!receive_exchange_key(log_server, ciphersuite_to_use, master_secret, premaster_secret, random_from_client, random_from_server)){
					handleError( 1, log_server);
				}
				state++;
			}
			else if(state == 5){
				if(!receive_change_cipher_spec(log_server)){
					handleError( 1, log_server);
				}
				state++;
			}
			else if(state == 6){
				if(!change_cipher_spec(log_server, master_secret, ciphersuite_to_use)){
					handleError( 1, log_server);
				}
				printf("Server: change_cipher_spec\n");
				state++;
			}
			else if(state == 7){
				if(!server_finished(log_server, (char*) master_secret, ciphersuite_to_use)){
					handleError( 1, log_server);
				}
				printf("Server: server_finished\n");
				change_semaphore_SERVER();
				break;
			}
			change_semaphore_SERVER();
		}
	}
    
    free(random_from_server);
	free(random_from_client);
	fclose(log_server);

return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "client_states.c"


int main(){

	FILE *log_client;
	char ciphersuite_to_use[3];
	char * random_from_server = calloc(32, sizeof(char));

	log_client = fopen("./client/log_client.txt","w");
	open_semaphore_to_SERVER();
	char * state = calloc(50,sizeof(char));
	strcpy(state, "client_hello");

	while(true){
		if (check_semaphore_CLIENT() == true){ // check if the file is exists

			if(!strcmp(state, "client_hello")){
				if(client_hello(log_client)){
					printf("CLIENT: client_hello\n"); // to delete
					strcpy(state,"receiving_server_hello");
					change_semaphore_CLIENT();
				}	
			}
			else if(!strcmp(state,"receiving_server_hello")){
				if(client_receiving_server_hello(log_client, ciphersuite_to_use, random_from_server)){
					printf("CLIENT: received_server_hello\n"); // to delete
					strcpy(state,"receiving_certificate");
					change_semaphore_CLIENT();
				}
			}
			else if(!strcmp(state,"receiving_certificate")){
				if(client_receiving_certificate (log_client)){
					printf("CLIENT: received_server_certificate\n"); // to delete
					if(is_needed_keyexchange(ciphersuite_to_use)){
						strcpy(state,"receive_exchange_key");
					}
					else{
						strcpy(state,"exchange_key");
					}
					change_semaphore_CLIENT();
				}
				
			}
			else if(!strcmp(state,"receive_exchange_key")){
				if(exchange_key (log_client)){
				printf("CLIENT: receiveing exchange_key\n"); // to delete
				strcpy(state,"exchange_key"); //DA FINIRE
				change_semaphore_CLIENT();
				break;
				}
			}
			else if(!strcmp(state,"exchange_key")){
				if(exchange_key (log_client)){
				printf("CLIENT: exchange_key\n"); // to delete
				strcpy(state,"BLEBLEBLE"); //DA FINIRE
				change_semaphore_CLIENT();
				break;
				}
			}
			
		}
	}
	free(state);
	close_all();
	fclose(log_client);

	return 0;
}

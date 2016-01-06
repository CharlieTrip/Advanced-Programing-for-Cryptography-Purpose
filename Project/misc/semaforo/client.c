#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>


bool check_semaphore_CLIENT(){
	/* the client check if its connection is open */
	if (access("ok_client.txt", F_OK) != -1)
		return true;
	else
		return false;
}

void change_semaphore_CLIENT(){
	/* the client close its connection 
	and open the connection for the server */ 
	remove("ok_client.txt");
	fopen("ok_server.txt","w");
}





int main(){
	    
		int count = 0;
	    FILE *canale;
		fopen("ok_client.txt","w");

	while(count < 10){
		if ((check_semaphore_CLIENT() == true)){ // check if the file is exists
			canale = fopen("canale.txt","a");
			fprintf(canale, "client %d \n",count++);
			printf("client %d \n",count);
			fclose(canale);
			change_semaphore();
		}
	}
	    


return 0;
}
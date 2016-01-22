#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>


bool check_semaphore_SERVER(){
	/* the server check if its connection is open */
	if (access("ok_server.txt", F_OK) != -1)
		return true;
	else
		return false;
}

void change_semaphore_SERVER(){
	/* the server close its connection 
	and open the connection for the client */ 
	remove("ok_server.txt");
	fopen("ok_client.txt","w");
}




int main(){

	int count = 0;

    FILE *canale;

while(count < 10){


	if (check_semaphore_SERVER() == true){  // check if the file is exists
		canale = fopen("canale.txt","a");
		fprintf(canale, "server %d \n",count++);
		printf("server %d \n",count);
		fclose(canale);
		change_semaphore();
	}
}

remove("ok_server.txt");

return 0;
}
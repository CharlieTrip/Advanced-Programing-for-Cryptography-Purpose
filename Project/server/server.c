#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "../common/semaphore.c"
#include "../common/file.c"



int main(){

    FILE *channel;

	while(/*condizione da inserire*/){
		if (check_semaphore_SERVER() == true){  // check if the file is exists
			channel = fopen("../common/channel.txt","a");
						
			if (channel != NULL){
					//read data
					//computation
					//write data
				}

			fclose(channel);
			change_semaphore_SERVER();
		}
	}

	close_all();

return 0;
}
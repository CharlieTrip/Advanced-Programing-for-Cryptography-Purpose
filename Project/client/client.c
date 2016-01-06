#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "semaphore.c"


int main(){

	FILE *canale;

	while(/*condizione da inserire*/){
		if (check_semaphore_CLIENT() == true){ // check if the file is exists
			canale = fopen("canale.txt","a");
				
			if (canale != NULL){
					//read data
					//computation
					//write data
				}

			fclose(canale);
			change_semaphore_CLIENT();
		}
	}

	close_all();

	return 0;
}
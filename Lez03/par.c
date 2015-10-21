#include <stdio.h>
#include <omp.h>
#include <stdlib.h>

int main(void){


	// -O optimization : 0 default


	int id;

	#pragma omp parallel
	{
		id = omp_get_thread_num();
		printf("Hello, world %d\n", id);
	}

	return 0;
}
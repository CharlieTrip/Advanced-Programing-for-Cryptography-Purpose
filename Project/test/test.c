#include <stdio.h>
#include <stdlib.h>
#include <string.h>



int fun(int a){

	if (a == 1){
		return 0;
	}
	printf("A\n");
	return 1;


}

int main(){

	fun(2);
}
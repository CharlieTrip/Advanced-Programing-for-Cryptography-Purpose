#include <stdio.h>

int main(void){
	
	int n = 0;
	unsigned int i = 1;
	printf("Quadrati perfetti fino a : ");

	if(! scanf("%d",&n)){
		printf("Err : valori interi in input.\n");
		return 1;
	}
	
	if(n<=0){
		printf("Err : solo n positivi.\n");
		return 1;
	}
	
	for(;i<=n;i++)
		printf("%d ",(i*i));

	return 0;
}
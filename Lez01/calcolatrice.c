#include <stdio.h>

int main()
{
	float val1 = 0;
	float ans = 0;
	char scelta = 7;
				

	do{
		switch(scelta){
			case 7 :
				printf("Calcolatrice : primo valore :");
				if(scanf("%f",&val1) != 1){
					printf("Errore d'input");
					return 1;
				}
				ans = val1;
				break;
			case '+' :
				printf("%f + ", ans);
				if(scanf("%f",&val1) != 1){
					printf("Errore d'input");
					return 1;
				}
				ans = ans + val1;
				printf("%f \n",ans);
				break;
			case '-' :
				printf("%f - ", ans);
				if(scanf("%f",&val1) != 1){
					printf("Errore d'input");
					return 1;
				}
				ans = ans - val1;
				printf("%f \n",ans);
				break;
			case '*' :
				printf("%f * ", ans);
				if(scanf("%f",&val1) != 1){
					printf("Errore d'input");
					return 1;
				}
				ans = ans + val1;
				printf("%f \n",ans);
				break;
			case '/' :
				printf("%f / " , ans);
				if(scanf("%f",&val1) != 1){
					printf("Errore d'input");
					return 1;
				}
				if (val1 == 0.0){
					printf("Divisione per zero\n");
					ans = 0;
				}
				else{
					ans = ans / val1;
					printf("%f \n",ans);
				}
				break;

		}
		
		printf("\n");
		printf("Calcolatrice : comandi disponibili : attuale risposta : %f \n",ans);
		printf("q. Exit\n");

		printf("Operazione : ");
		scanf("%c",&scelta);
		

	}while (scelta != 'q');

	

	return 0;
}
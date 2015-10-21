#include <stdio.h>

const double PI = 3.1415;

int main()
{
	float lato = 0;
	float altezza = 0;
	float raggio = 0;
	float area = 0;
	unsigned int scelta = 0;



	do{
		switch(scelta){
			case 1 :
				printf("Inserisci lato : ");
				if(scanf("%f",&lato) != 1){
					printf("Errore d'input");
					return 1;
				}
				printf("Inserisci altezza : ");
				if(scanf("%f",&altezza) != 1){
					printf("Errore d'input");
					return 1;
				}
				area = lato * altezza / 2;
				printf("Area del triangolo : %f \n",area);
				break;
			case 2 :
				printf("Inserisci lato 1 : ");
				if(scanf("%f",&lato) != 1){
					printf("Errore d'input");
					return 1;
				}
				printf("Inserisci lato 2 : ");
				if(scanf("%f",&altezza) != 1){
					printf("Errore d'input");
					return 1;
				}
				area = lato * altezza;
				printf("Area del rettangolo : %f \n",area);
				break;
			case 3 :
				printf("Inserisci lato : ");
				if(scanf("%f",&lato) != 1){
					printf("Errore d'input");
					return 1;
				}
				area = lato * lato;
				printf("Area del quadrato : %f \n",area);
				break;
			case 4 :
				printf("Inserisci raggio : ");
				if(scanf("%f",&raggio) != 1){
					printf("Errore d'input");
					return 1;
				}
				area = raggio * raggio * PI;
				printf("Area del cerchio : %f \n",area);
				break;
		}

		printf("\n");
		printf("Calcola l'area della figura\n");
		printf("1. Triangolo\n");
		printf("2. Rettangolo\n");
		printf("3. Quadrato\n");
		printf("4. Cerchio\n");
		printf("5. Exit\n");

		printf("Scelta : ");
		scanf("%u",&scelta);

	}while (scelta != 5);

	

	return 0;
}
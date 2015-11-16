#include <stdio.h>
#include <gmp.h>

int main(int argc, char **argv ) {
	mpz_t x,y,mod,tmp;
	mpz_t p,q;
	int n = 100;
	mp_bitcnt_t bit = 100;
	gmp_randstate_t state;



	mpz_init(x);
	mpz_init(y);
	mpz_init(tmp);
	mpz_init(p);
	mpz_init(q);
	mpz_init(mod);

    unsigned long int seed;

    if(argc > 1){
    	printf("\n %s \n",argv[1]);
    	mpz_set_str(y,argv[1],10);
    	seed = (int) mpz_get_ui(y);
    }
    else
    	seed = 12345;

    printf("seed : %lu\n",seed);

    gmp_randinit_default (state);
    gmp_randseed_ui(state, seed);


	mpz_urandomb(p,state,bit);
	
	if (mpz_probab_prime_p(p,15) < 1)
		mpz_nextprime(p,p);

	while(mpz_mod_ui(mod,p,4)!=3){
		mpz_nextprime(p,p);
	}

	mpz_urandomb(q,state,bit);
	
	if (mpz_probab_prime_p(q,15) < 1)
		mpz_nextprime(q,q);

	while(mpz_mod_ui(mod,q,4)!=3){
		mpz_nextprime(q,q);
	}

	// We have the modulo
	mpz_mul(mod,p,q);


	// Random x0
	mpz_urandomb(y,state,10);
	mpz_gcd(tmp,y,mod);
	while(mpz_get_ui(tmp) != 1){
		mpz_init_set(y,tmp);
		mpz_gcd(tmp,y,mod);
	}

	for(int i = 0;i < n;i++){
		mpz_init_set(tmp,y);
		mpz_mul(y,tmp,tmp);
		mpz_mod(x,y,mod);	
		mpz_init_set(y,x);
		printf("%lu",mpz_mod_ui(tmp,tmp,2));
	}
	printf("\n");


	// gmp_printf("%Zd\n",y);
	// gmp_printf("%Zd\n",mod);
	// gmp_printf("%Zd\n",p);
	// gmp_printf("%Zd\n",q);

	/* free used memory */
	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(tmp);
	mpz_clear(p);
	mpz_clear(q);
	gmp_randclear(state);
	mpz_clear(mod);

	return 0;
}
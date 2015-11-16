#include <stdio.h>
#include <gmp.h>

int main(void) {
 mpz_t x,y,result;

 mpz_init(x);
 mpz_init(y);
 mpz_init(result);

 printf("1 : ");
 gmp_scanf("%Zd",x);
 printf("2 : ");
 gmp_scanf("%Zd",y);

 

 mpz_add(result, x, y);

 gmp_printf("    %Zd\n"
            "*\n"
            "    %Zd\n"
            "--------------------\n"
            "%Zd\n", x, y, result);

 /* free used memory */
 mpz_clear(x);
 mpz_clear(y);
 mpz_clear(result);

 return 0;
}
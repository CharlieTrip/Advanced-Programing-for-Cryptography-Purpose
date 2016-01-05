#include <stdio.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

BIGNUM* modExpo(BIGNUM* gen, BIGNUM* expo, BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM *test;
    BIGNUM *temp1,*temp2,*temp3,*one;
    test = BN_new();
    one = BN_new(); BN_one(one);
    temp1 = BN_new();
    temp2 = BN_new();
    temp3 = BN_new();
    int ret;

    for (BN_one(test); (ret = BN_is_zero(expo)) != 1; BN_rshift1(expo,expo)) {
        if (BN_is_bit_set(expo,0x1)) { // same as expo & 1
            BN_nnmod(temp1,test,mod,ctx);
            BN_nnmod(temp2,gen,mod,ctx);
            BN_mul(temp3,temp1,temp2,ctx);
            BN_nnmod(test,temp3,mod,ctx);
            // equivalent to test = ((test % mod) * (gen % mod)) % mod
        }
        // equivalent to gen = ((gen % mod) * (gen % mod)) % mod
        BN_nnmod(temp1,gen,mod,ctx);
        BN_mul(temp2,temp1,temp1,ctx);
        BN_nnmod(gen,temp2,mod,ctx);
    }
    return test;
}

int main() {
    BIGNUM *expo, *mod, *gen, *pubVal;
    BN_CTX *ctx;
    DH *dhparams;

    ctx = BN_CTX_new();
    expo = BN_new();
    mod = BN_new();
    gen = BN_new();
    pubVal = BN_new();

    dhparams = DH_generate_parameters(512, 5, NULL, NULL);
    gen = dhparams->g; // should be 5
    mod = dhparams->p; // should be prime

    BN_rand(expo,512,1,1); // and there is the secret value =)

    // print out the values for submission
    printf("generator: %s",BN_bn2dec(gen));
    printf("\np: %s",BN_bn2dec(mod));
    printf("\nsecret exponent: %s",BN_bn2dec(expo));
    printf("\n");

    // now calculate (gen^expo) % mod
    pubVal = modExpo(gen,expo,mod,ctx);

    // now print it out
    printf("public value is: %s\n",BN_bn2dec(pubVal));


    BN_CTX_free(ctx);
}

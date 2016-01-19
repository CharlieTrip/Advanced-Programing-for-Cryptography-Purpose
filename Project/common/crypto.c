#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>


// Certificates

int verifyCertificate(unsigned char * cert_filestr){

	const char ca_bundlestr[] = "./common/ca-bundle.pem";

	BIO              *certbio = NULL;
	BIO               *outbio = NULL;
	X509          *error_cert = NULL;
	X509                *cert = NULL;
	X509_NAME    *certsubject = NULL;
	X509_STORE         *store = NULL;
	X509_STORE_CTX  *vrfy_ctx = NULL;
	int ret;

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	certbio = BIO_new(BIO_s_file());
	outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	* Initialize the global certificate validation store object. *
	* ---------------------------------------------------------- */
	if (!(store=X509_STORE_new()))
	BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

	/* ---------------------------------------------------------- *
	* Create the context structure for the validation operation. *
	* ---------------------------------------------------------- */
	vrfy_ctx = X509_STORE_CTX_new();

	/* ---------------------------------------------------------- *
	* Load the certificate and cacert chain from file (PEM).     *
	* ---------------------------------------------------------- */
	ret = BIO_read_filename(certbio, cert_filestr);
	if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
	BIO_printf(outbio, "Error loading cert into memory\n");
	exit(-1);
	}

	ret = X509_STORE_load_locations(store, ca_bundlestr, NULL);
	if (ret != 1)
	BIO_printf(outbio, "Error loading CA cert or chain file\n");

	/* ---------------------------------------------------------- *
	* Initialize the ctx structure for a verification operation: *
	* Set the trusted cert store, the unvalidated cert, and any  *
	* potential certs that could be needed (here we set it NULL) *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

	/* ---------------------------------------------------------- *
	* Check the complete cert chain can be build and validated.  *
	* Returns 1 on success, 0 on verification failures, and -1   *
	* for trouble with the ctx object (i.e. missing certificate) *
	* ---------------------------------------------------------- */
	ret = X509_verify_cert(vrfy_ctx);
	
	/* ---------------------------------------------------------- *
	* Free up all structures                                     *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_free(vrfy_ctx);
	X509_STORE_free(store);
	X509_free(cert);
	BIO_free_all(certbio);
	BIO_free_all(outbio);

	return ret;
}

int getPubKey(unsigned char * cert_filestr){

	BIO              *certbio = NULL;
	BIO               *outbio = NULL;
	X509          *error_cert = NULL;
	X509                *cert = NULL;
	X509_NAME    *certsubject = NULL;
	X509_STORE         *store = NULL;
	X509_STORE_CTX  *vrfy_ctx = NULL;
	EVP_PKEY *key;
	int ret;

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* ---------------------------------------------------------- *
	* Create the Input/Output BIO's.                             *
	* ---------------------------------------------------------- */
	key = EVP_PKEY_new();
	certbio = BIO_new(BIO_s_file());
	outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

	/* ---------------------------------------------------------- *
	* Initialize the global certificate validation store object. *
	* ---------------------------------------------------------- */
	if (!(store=X509_STORE_new()))
	BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

	/* ---------------------------------------------------------- *
	* Create the context structure for the validation operation. *
	* ---------------------------------------------------------- */
	vrfy_ctx = X509_STORE_CTX_new();

	/* ---------------------------------------------------------- *
	* Load the certificate and cacert chain from file (PEM).     *
	* ---------------------------------------------------------- */
	ret = BIO_read_filename(certbio, cert_filestr);
	if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
	BIO_printf(outbio, "Error loading cert into memory\n");
	exit(-1);
	}

	/* ---------------------------------------------------------- *
	* Initialize the ctx structure for a verification operation: *
	* Set the trusted cert store, the unvalidated cert, and any  *
	* potential certs that could be needed (here we set it NULL) *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

	


	key = X509_get_pubkey(cert->cert_info);

	RSA * rsa;
 	
 	rsa = EVP_PKEY_get0_RSA(key);

 	printf("loj\n");


 	RSA_print(outbio, rsa, 1);


	// Linux ?
	// ret = EVP_PKEY_print_public(outbio, &key, 0 , NULL );


	/* ---------------------------------------------------------- *
	* Free up all structures                                     *
	* ---------------------------------------------------------- */
	X509_STORE_CTX_free(vrfy_ctx);
	X509_STORE_free(store);
	X509_free(cert);
	BIO_free_all(certbio);
	BIO_free_all(outbio);
	EVP_PKEY_free(key);

	return ret;
}






// RSA
// 
// Uses the format
// 
// 		--- BEGIN x---
// 			[...]
// 		--- END x---

int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int public){
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    
    if (keybio==NULL) {
        printf( "Failed to create key BIO");
        return 0;
    }

    if (public) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    
    else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    
    if (rsa == NULL) {
        printf( "Failed to create RSA");
    }
    return rsa;
}
 
int TLS_RSA_public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int TLS_RSA_private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
  
int TLS_RSA_private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int TLS_RSA_public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 



// DH [WIP]
//  http://linux.die.net/man/3/ssl_ctx_set_tmp_dh
// Pass the PEM format of DH

DH * DH_create(unsigned char * parameter){
	DH *dh= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(parameter, -1);
    
    if (keybio == NULL) {
        printf( "Failed to create parameter BIO");
        return 0;
    }

    
    dh = PEM_read_bio_DHparams(keybio, &dh , NULL , NULL);
    
    if (dh == NULL) {
        printf( "Failed to create DH");
    }
   
	return(dh);
}

int DH_generate_keys(DH * dh){
	return DH_generate_key(dh);
}

int DH_secret(DH * dh , BIGNUM * pub_key , BIGNUM * secret){
	unsigned char key[DH_size(dh)];
	if (DH_compute_key(key, pub_key, dh) == -1) return -1;
	BIGNUM *p = BN_bin2bn(key, sizeof(key), NULL);
	BN_copy(secret,p);
	return 0 ;
}




// HMAC

int HMAC_MD5(unsigned char* key ,unsigned int lkey, unsigned char* data, unsigned int ldata, unsigned char* expected , unsigned char* result){
	unsigned int result_len = 16;
	int i;
	unsigned char * results;
	static char res_hexstring[32];
	// result = HMAC(EVP_sha256(), key, 4, data, 28, NULL, NULL);
	results = HMAC(EVP_md5(), key, lkey, data, ldata, NULL, NULL);
	for (i = 0; i < result_len; i++) {
		sprintf(&(res_hexstring[i * 2]), "%02x", results[i]);
	}
	
	for (i=0; i < (result_len*2); i++) {
		result[i] = res_hexstring[i];
	}

	if (strcmp((char*) res_hexstring, (char*) expected) == 0) {
		return 0;
	} else {
		return -1;
	}
}

int HMAC_SHA2(unsigned char* key ,unsigned int lkey, unsigned char* data, unsigned int ldata, unsigned char* expected ,unsigned char* result){
	unsigned int result_len = 132;
	int i;
	unsigned char * results;
	static char res_hexstring[64];
	results = HMAC(EVP_sha256(), key, lkey, data, ldata, NULL, NULL);
	for (i = 0; i < result_len; i++) {
		sprintf(&(res_hexstring[i * 2]), "%02x", results[i]);
	}

	for (i=0; i < (result_len*2); i++) {
		result[i] = res_hexstring[i];
	}

	if (strcmp((char*) res_hexstring, (char*) expected) == 0) {
		return 0;
	} else {
		return -1;
	}
}


char * X509_to_string(X509 *cert) {

  /* transform a x509 file into a string */

    BIO *bio = NULL;
    char *string = NULL;

    if (NULL == cert) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        return NULL;
    }

    if (0 == PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return NULL;
    }

    string = (char *) malloc(bio->num_write + 1);
    if (NULL == string) {
        BIO_free(bio);
        return NULL;    
    }

    memset(string, 0, bio->num_write + 1);
    BIO_read(bio, string, bio->num_write);
    BIO_free(bio);
    return string;
}



int get_certificate(char * certificate) {

/* Get the certificate from 'cert-file.pem' file and *
 * return it as a string                             */

  BIO *certbiocle = NULL;
  BIO *certbio = NULL;
  BIO *outbio = NULL;
  FILE *cert_file;
  RSA *rsakey;
  X509 *cert = NULL;
  const char cert_filestr[] = "./cert-file.pem";

  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
  certbio = BIO_new(BIO_s_file());
  int ret;

  OpenSSL_add_all_algorithms();

  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
  }

  certificate = X509_to_PEM(cert);

  exit(0);
}


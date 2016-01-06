#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
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
DH * createDH(unsigned char * key,int public) { return 0 ;}
int DH_public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){ return 0 ;}
int DH_private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){ return 0 ;}
int DH_private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){ return 0 ;}
int DH_public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){ return 0 ;}




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

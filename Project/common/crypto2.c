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


char * X509_to_string(X509 *cert) {

  /* transform a x509 file into a string */

  BIO *bio = NULL;
  char *string = NULL;

  if (NULL == cert){
    return NULL;
  }
  bio = BIO_new(BIO_s_mem());
  if (NULL == bio){
    return NULL;
  }
  if (0 == PEM_write_bio_X509(bio, cert)){
    BIO_free(bio);
    return NULL;
  }
  string = (char *) malloc(bio->num_write + 1);
  if (NULL == string){
    BIO_free(bio);
    return NULL;    
  }
  memset(string, 0, bio->num_write + 1);
  BIO_read(bio, string, bio->num_write);
  BIO_free(bio);
  return string;
}


X509 *string_to_X509(char *string) {

/* transform a string into a x509 file */  

  X509 *cert = NULL;
  BIO *bio = NULL;
  if (NULL == string){
    return NULL;
  }
  bio = BIO_new_mem_buf(string, strlen(string));
  if (NULL == bio){
    return NULL;
  }
  cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return cert;
}



char * get_certificate() {

/* Get the certificate from 'cert-file.pem' file and *
 * return it as a string                             */

  BIO *certbio = NULL;
  FILE *cert_file;
  X509 *cert = NULL;
  const char cert_filestr[] = "./server/RSA_cert.pem";
  certbio = BIO_new(BIO_s_file());
  int ret;
  
  OpenSSL_add_all_algorithms();

  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    printf("Error loading cert into memory\n");
  }
  return X509_to_string(cert);
}








int get_pubkey(const char * pubkey_filestr, const char * cert_filestr) {

  EVP_PKEY *pkey = NULL;
  BIO              *certbio = NULL;
  X509                *cert = NULL;
  int ret;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    printf("Error loading cert into memory\n");
    return -1;
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pkey = X509_get_pubkey(cert)) == NULL)
    printf("Error getting public key from certificate\n");

  FILE *key_file = fopen(pubkey_filestr, "w");
  if(!PEM_write_PUBKEY(key_file, pkey)){
    printf("Error writing public key data in PEM format\n");
  }
  fclose(key_file);

  EVP_PKEY_free(pkey);
  X509_free(cert);
  BIO_free_all(certbio);
  return 0;
}




void chose_best_ciphersuite(char * message, char * best_chipersuite){

  int n_ciphersuite = get_n_of_blocks(message)-3;
  int ciphersuites[n_ciphersuite];
  int best;
  for (int i = 0; i < n_ciphersuite; ++i){
    ciphersuites[i] = atoi(get_nth_block(message,4+i));
  }
  best = ciphersuites[0];
  for (int i = 1; i < n_ciphersuite; ++i)
  {
    if (best<ciphersuites[i]){
      best = ciphersuites[i];
    }
  }
  sprintf(best_chipersuite, "%d", best);
}



RSA * TLS_createRSAWithFilename(char * filename, char * public_or_private){

  /* get the RSA public or private key */

  int public;
  if(!strcmp(public_or_private,"public")){
    public = 1;
  }
  else{
    public = 0;
  }
  FILE * fp = fopen(filename,"rb");
 
  if(fp == NULL){
      printf("Unable to open file %s \n",filename);
      return NULL;    
  }
  RSA *rsa= RSA_new() ;
  if(public){
      rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
  }
  else{
      rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
  }

  return rsa;
}




 
int TLS_RSA_public_encrypt(unsigned char * data, int data_len, const char * key, char *encrypted){
  RSA * pubkey = TLS_createRSAWithFilename((char *) key, "public");
  int result = RSA_public_encrypt(data_len, data,(unsigned char *) encrypted, pubkey, RSA_PKCS1_PADDING);
  if (pubkey)
    RSA_free(pubkey);
  return result;
}



int TLS_RSA_private_decrypt(unsigned char * enc_data, int data_len, const char * key, unsigned char * decrypted){
    RSA * privkey = TLS_createRSAWithFilename((char *) key,"private");
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, privkey, RSA_PKCS1_PADDING);
      if (privkey)
    RSA_free(privkey);
    return result;
}



int HMAC_SHA1(unsigned char* key, unsigned int lkey, unsigned char* data, unsigned int ldata, unsigned char* expected , unsigned char* result){
  unsigned int result_len = 20;
  int i;
  unsigned char * results;
  static char res_hexstring[40];
  // result = HMAC(EVP_sha256(), key, 4, data, 28, NULL, NULL);
  results = HMAC(EVP_sha1(), key, lkey, data, ldata, NULL, NULL);
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
  unsigned int result_len = 32;
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


int HMAC_SHA1_file(FILE* file , unsigned char* key, unsigned int lkey, unsigned char* expected , unsigned char* result){
  char *data = calloc(BUF_SIZE,sizeof(char));
  read_channel(file,data);
  return HMAC_SHA1(key,lkey,(unsigned char *) data,(unsigned int)strlen(data), expected,result);
}

int HMAC_SHA2_file(FILE* file , unsigned char* key, unsigned int lkey, unsigned char* expected , unsigned char* result){
  char *data = calloc(BUF_SIZE,sizeof(char));
  read_channel(file,data);
  return HMAC_SHA2(key,lkey, (unsigned char *) data,(unsigned int) strlen(data), expected,result);
}




int is_needed_keyexchange(char * ciphersuite_to_use){
  /* return 1 if key_exchange has to be done, 0 otherwise */

  if (atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA1) || atoi(ciphersuite_to_use) == atoi(TLS_RSA_RSA_SHA2)){
  //DEVO CAPIRE ANCORA BENE COSA FARE CON TLS_DH_RSA
    return 0;
  }
  else 
    return 1;
}



/*
int compute_master_secret(unsigned char * master_secret, char * random_from_client, char * random_from_server, char * premaster_secret) {

  char label = malloc(78+1,sizeof(char));
  strcpy(label,"master secret");
  strncat(label,random_from_client,32);
  strncat(label,random_from_server,32);
  EVP_PKEY_CTX *pctx;
  size_t outlen = sizeof(master_secret);
  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
  if (EVP_PKEY_derive_init(pctx) <= 0){
    return 0;
    printf("Error computing master key\n");
  }
  if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1()) <= 0){
    return 0;
    printf("Error computing master key\n");
  }
  if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, premaster_secret, 256) <= 0){
    return 0;
    printf("Error computing master key\n");
  }
  if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, label, 78) <= 0){
    return 0;
    printf("Error computing master key\n");
  }
  if (EVP_PKEY_derive(pctx, master_secret, &outlen) <= 0){
    return 0;
    printf("Error computing master key\n");
  }
  free(label);
  return 1;
}*/

int P_Hash_3round( const EVP_MD * evp_md, char * secret, int len_secret, char * text, int len_text, char * output){

	/* This is just an function thougth for compute the master secret, *
	 * So it has just 3 round and it return only 48 bytes and not 60   */

	// Definitions
  unsigned int result_len = 20;
  static char res_hexstring[40];
	char * seed = calloc(20+len_text+1, sizeof(char));
	char * step0;
	char * step1;
	char * step2;
	// Creating the first seed
	strcpy(seed, text); strcat(seed, text);
	// first HMAC
	step0 = (char *) HMAC(evp_md, secret, len_secret, (const unsigned char *) seed, len_text*2, NULL, NULL);
	// Creating the second seed
	memset(seed, 0, sizeof(char));
	strcpy(seed,step0); strcat(seed, text);
	// Second HMAC
	step1 = (char *) HMAC(evp_md, secret, len_secret, (const unsigned char *) seed, len_text+20, NULL, NULL);
	// Creating the tird seed
	memset(seed, 0, sizeof(char));
	strcpy(seed, step1); strcat(seed, text);
	// Tird HMAC
	step2 = (char *) HMAC(evp_md, secret, len_secret, (const unsigned char *) seed, len_text+20, NULL, NULL);
	strcpy(output, step0); strcat(output, step1); strncat(output, step2,8);
	free(seed);
	return 1;
}






int compute_master_secret(unsigned char * master_secret, char * random_from_client, char * random_from_server, char * premaster_secret, char * label) {

	char * sha1_part = calloc(48+1, sizeof(char));
	char * md5_part = calloc(48+1, sizeof(char)); 
	char * seed = calloc(78+1, sizeof(char));
	strcpy(seed, label); strcat(seed, random_from_client); strcat(seed, random_from_server);
	char * S1 = calloc(24+1, sizeof(char));
	char * S2 = calloc(24+1, sizeof(char));
  memcpy(S1, premaster_secret, 24);
  memcpy(S2, premaster_secret+24, 24);

	P_Hash_3round( EVP_sha1(), S1, 24, seed, 77, sha1_part);
	P_Hash_3round( EVP_md5(), S2, 24, seed, 77, md5_part);
	
	for(int i = 0; i<48; i++){
		master_secret[i] = (char) sha1_part[i]^md5_part[i];
	}
	free(sha1_part); free(md5_part); free(seed); free(S1); free(S2);
	return 1;
}














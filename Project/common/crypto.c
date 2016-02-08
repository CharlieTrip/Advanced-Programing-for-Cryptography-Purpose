
#include "crypto.h"


const int len_sha256 = 32;


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
  BIO_read(bio, string,(int) bio->num_write);
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
  bio = BIO_new_mem_buf(string, (int) strlen(string));
  if (NULL == bio){
    return NULL;
  }
  cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return cert;
}



char * get_certificate( char * link) {

/* Get the certificate from a pem file and *
 * return it as a string                   */
  BIO *certbio = NULL;
  X509 *cert = NULL;
  certbio = BIO_new(BIO_s_file());
  int ret;
  OpenSSL_add_all_algorithms();
  ret = (int) BIO_read_filename(certbio, link);
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
  ret = (int) BIO_read_filename(certbio, cert_filestr);
    
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
  return 1;
}




void choose_best_ciphersuite(char * message, char * best_chipersuite){

  int n_ciphersuites = get_n_of_blocks(message)-3;
  int ciphersuites[n_ciphersuites];
  int best;
  for (int i = 0; i < n_ciphersuites; ++i){
    ciphersuites[i] = atoi(get_nth_block(message,5+i));
  }
  best = ciphersuites[0];
  for (int i = 1; i < n_ciphersuites; ++i)
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



int is_needed_keyexchange(char * ciphersuite_to_use){
  /* return 1 if key_exchange has to be done, 0 otherwise */
    
  if (atoi(ciphersuite_to_use) == atoi(TLS_RSA_WITH_SHA256) ){
    return 0;
  }
  else 
    return 1;
}


int P_Hash( const EVP_MD * evp_md, int round, char * secret, int len_secret, char * text, int len_text, char * output,  int sha_len){

  /* This is just an function thougth for compute the master secret, *
   * So it has just 3 round and it return only 48 bytes and not 60   */
  // Definitions
  char * seed0 = calloc(len_text*2, sizeof(char));
  char * seed = calloc(len_text+sha_len, sizeof(char));
  char * step0;
  char * step;
  // Creating the first seed
  strncpy(seed0, text, len_text); strncat(seed0, text, len_text);
  // compute first HMAC and copy it into output
  step0 = (char *) HMAC(evp_md, secret, len_secret, (const unsigned char *) seed0, strlen(seed0), NULL, NULL);
  strncpy(output, step0, sha_len);
  // Creating the second seed
  strncpy(seed,step0,sha_len); strncat(seed, text, len_text);

  for(int i = 0; i< round-1; i++){
    // compute HMAC and copy it into output
    step = (char *) HMAC(evp_md, secret, len_secret, (const unsigned char *) seed, len_text+sha_len, NULL, NULL);
    strncat(output, step, sha_len);
    // Creating the seed
    free(seed);
    seed = calloc(len_text+sha_len, sizeof(char));
    strncpy(seed, step,sha_len); strncat(seed, text, len_text);
    }
    free(seed0); free(seed);
    return 1;
}



int compute_master_secret(unsigned char * master_secret, char * random_from_client, char * random_from_server, char * premaster_secret, char * label) {

 // if( stiamo usando sha2) {...}

	char * hash = calloc(32*3,sizeof(char));
	char * seedsha = calloc(77, sizeof(char));
	strncpy(seedsha, label,strlen(label)); strncat(seedsha, random_from_client,32); strncat(seedsha, random_from_server,32);

  // compute prs hmac
	if (!P_Hash( EVP_sha256(), 3, premaster_secret, 48, seedsha, 77, hash, len_sha256)){
        printf("Computation PRF failed\n");
    return 0;
  }

  strncpy((char*) master_secret, hash, 48);

	return 1;
}


int compute_hash_log(FILE * log, unsigned char * master_secret, unsigned int len_master_secret, unsigned char * hash_server_log){

  char *data = calloc(BUF_SIZE,sizeof(char));
  char *hash = calloc(len_sha256,sizeof(char));
  char ch;
  int i = 0;
  while( ( ch = fgetc(log) ) != EOF ){
    data[i] = ch; i++;
  }

  P_Hash( EVP_sha256(), 1, (char*) master_secret, (int) strlen((const char *)master_secret), data, i-1, (char *) hash,  len_sha256);

  stringToHex(hash, 12, (char *) hash_server_log);

  return 1;
}













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


X509 *string_to_X509(char *string) {

    X509 *cert = NULL;
    BIO *bio = NULL;

    if (NULL == string) {
        return NULL;
    }

    bio = BIO_new_mem_buf(string, strlen(string));
    if (NULL == bio) {
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























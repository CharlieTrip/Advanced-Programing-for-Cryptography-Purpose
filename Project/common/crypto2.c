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
  const char cert_filestr[] = "./server/cert-file.pem";
  certbio = BIO_new(BIO_s_file());
  int ret;
  
  OpenSSL_add_all_algorithms();

  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    printf("Error loading cert into memory\n");
  }
  return X509_to_string(cert);
}








int get_pubkey() {

  const char cert_filestr[] = "./client/cert-file.pem";
  const char pubkey_filestr[] = "./client/public_key.pem";
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


































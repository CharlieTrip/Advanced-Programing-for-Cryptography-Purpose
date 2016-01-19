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
  BIO *outbio = NULL;
  FILE *cert_file;
  X509 *cert = NULL;
  const char cert_filestr[] = "./server/cert-file.pem";
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
  certbio = BIO_new(BIO_s_file());
  int ret;
  
  OpenSSL_add_all_algorithms();

  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    BIO_free(outbio);
  }
  BIO_free(outbio);  
  return X509_to_string(cert);


}



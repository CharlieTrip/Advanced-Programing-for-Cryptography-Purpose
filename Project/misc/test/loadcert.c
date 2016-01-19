#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>




char * X509_to_PEM(X509 *cert) {

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






int main() {

  BIO *certbiocle = NULL;
  BIO *certbio = NULL;
  BIO *outbio = NULL;
  FILE *cert_file;
  RSA *rsakey;
  X509 *cert = NULL;
  const char cert_filestr[] = "cert-file.pem";

  char * certificate = calloc (800, sizeof(char));

  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
  certbio = BIO_new(BIO_s_file());
  int ret;

  /* ----------------------------------------------------------- *
  * Next function is essential to enable openssl functions       *
  * ------------------------------------------------------------ */
  OpenSSL_add_all_algorithms();

  ret = BIO_read_filename(certbio, cert_filestr);

  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
    BIO_free(outbio);
  }
  BIO_free(outbio);
  certificate = X509_to_PEM(cert);

  printf("%s\n", certificate );

  exit(0);
}





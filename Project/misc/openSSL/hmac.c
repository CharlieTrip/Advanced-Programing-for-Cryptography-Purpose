// http://www.askyb.com/cpp/openssl-hmac-hasing-example-in-cpp/
// http://stackoverflow.com/questions/13555962/md5-hmac-with-openssl

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <syslog.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() 
{
  unsigned char* key = (unsigned char*) "2012121220121212201212122012121220121212201212122012121220121212";
  unsigned char* data = (unsigned char*) "johndoejohndoejohndoejohndoejohndoejohndoejohndoejohndoejohndoejohndoejohndoejohndoe";
  unsigned char* expected = (unsigned char*) "abcd1d87dca34f334786307d0da4fcbd";
  unsigned char* result;
  // unsigned int result_len = 16;

  unsigned int result_len = 16;
  int i;
  static char res_hexstring[32];

  // result = HMAC(EVP_sha256(), key, 4, data, 28, NULL, NULL);
  result = HMAC(EVP_md5(), key, 64, data, 84, NULL, NULL);
  for (i = 0; i < result_len; i++) {
    sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
  }

  if (strcmp((char*) res_hexstring, (char*) expected) == 0) {
    printf("Test ok, result length %d\n", result_len);
  } else {
    printf("Got %s instead of %s\n", res_hexstring, expected);
  }
}
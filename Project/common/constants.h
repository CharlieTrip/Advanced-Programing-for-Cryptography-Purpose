// 
// Just constants used in the TLS protocol toy
// Reference : https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake
// 



//
// Cipher suite allowed
// For our toy, just the combination between
// DH - RSA for key exchange
// Just RSA for authentication (X509.x certificates)
// HMAC : SHA2 - SHA1
// 
// NB : the HMAC works in the TLS protocol
// ONLY then client and server has created a common secret.
// Because we stop the protocol when we have the secret,
// just the last one has the hmac control using the shared secret as key.

const char TLS_NULL_NULL_NULL[3] = "00\0";
const char TLS_DH_RSA_WITH_AES_128_CBC_SHA[3] = "01\0";
const char TLS_DH_RSA_WITH_AES_256_CBC_SHA[3] = "02\0";
const char TLS_DH_RSA_WITH_AES_128_CBC_SHA256[3] = "03\0";
const char TLS_DH_RSA_WITH_AES_256_CBC_SHA256[3] = "04\0";
const char TLS_RSA_WITH_AES_128_CBC_SHA[3] = "05\0";
const char TLS_RSA_WITH_AES_256_CBC_SHA[3] = "06\0";
const char TLS_RSA_WITH_AES_128_CBC_SHA256[3] = "07\0";
const char TLS_RSA_WITH_AES_256_CBC_SHA256[3] = "08\0";


// 
// The "content type" that can be send in our implementation

const char TLS_CHANGECIPHERSPEC[3] = "30\0";
const char TLS_ALERT[3] = "31\0";
const char TLS_HANDSHAKE[3] = "32\0";


// 
// The Message Type (for the Handshake)

const char TLS_HELLOREQUEST[2] = "0\0";
const char TLS_CLIENTHELLO[2] = "1\0";
const char TLS_SERVERHELLO[2] = "2\0";
const char TLS_SERVERCERTIFICATE[3] = "11\0";
const char TLS_SERVERKEYEXCHANGE[3] = "12\0";
const char TLS_SERVERHELLODONE[3] = "14\0";
const char TLS_CLIENTKEYEXCHANGE[3] = "16\0";
const char TLS_FINISHED[3] = "20\0";



/* NOTE: the memory allocated is one plus the length of the string
 * since we want also the \0 character 
 */

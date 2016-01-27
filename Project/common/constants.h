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


const char TLS_DH_RSA_SHA1[3] = "10\0";
const char TLS_DH_RSA_SHA2[3] = "11\0";
const char TLS_RSA_RSA_SHA1[3] = "12\0";
const char TLS_RSA_RSA_SHA2[3] = "13\0";
const char TLS_RSA_RSA_MD5[3] = "14\0";




// 
// The "content type" that can be send in our implementation

const char TLS_CHANGECIPHERSPEC[3] = "30\0";
const char TLS_ALERT[3] = "31\0";
const char TLS_HANDSHAKE[3] = "32\0";


// 
// The Message Type (for the Handshake)

const char TLS_HELLOREQUEST[3] = "33\0";
const char TLS_CLIENTHELLO[3] = "34\0";
const char TLS_SERVERHELLO[3] = "35\0";
const char TLS_SERVER_CERTIFICATE[3] = "36\0";
const char TLS_SERVERKEYEXCHANGE[3] = "37\0";
const char TLS_SERVERHELLODONE[3] = "38\0";
const char TLS_CLIENTKEYEXCHANGE[3] = "39\0";
const char TLS_FINISHED[3] = "40\0";
const char TLS_VERSION[3] = "41\0";


// So we will have our messages coded in this way:
// 
//	 Content Type - Message Type \n
//	 Message \n
// 


/* NOTE: the memory allocated is one plus the length of the string
 * since we want also the \0 character 
 */

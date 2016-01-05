// 
// Just constants used in the TLS protocol toy
// Reference : https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake
// 



//
// Cipher suite allowed
// For our toy, just the combination between
// DH - RSA for key exchange
// Just RSA for authentication (X509.x certificates)
// 
// NB : the HMAC works in the TLS protocol
// ONLY then client and server has created a common secret.
// Because we stop the protocol when we have the secret,
// there is no need to add it to the cipher suites

#define TLS_DH_RSA 1
#define TLS_RSA_RSA 2


// 
// The "content type" that can be send in our implementation

#define TLS_CHANGECIPHERSPEC 20
#define TLS_ALERT 21
#define TLS_HANDSHAKE 22


// 
// The Message Type (for the Handshake)

#define TLS_HELLOREQUEST 0
#define TLS_CLIENTHELLO 1
#define TLS_SERVERHELLO 2
#define TLS_CERTIFICATE 11
#define TLS_SERVERKEYEXCHANGE 12
#define TLS_SERVERHELLODONE 14
#define TLS_CLIENTKEYEXCHANGE 16
#define TLS_FINISHED 20



#include "common/crypto.c"


int main(int argc, char **argv){

	// 
	// Test SHA256
	// 
	// unsigned char buffer[BUFSIZ];
	// FILE *f;
	// SHA256_CTX ctx;
	// size_t len;
	// if (argc < 2) {
	// 	fprintf(stderr, "usage: %s <file>\n", argv[0]);
	// 	return 1;
	// }
	// f = fopen(argv[1], "r");
	// if (!f) {
	// 	fprintf(stderr, "couldn't open %s\n", argv[1]);
	// 	return 1;
	// }
	// SHA256_Init(&ctx);
	// do {
	// 	len = fread(buffer, 1, BUFSIZ, f);
	// 	SHA256_Update(&ctx, buffer, len);
	// } while (len == BUFSIZ);
	// SHA256_Final(buffer, &ctx);
	// fclose(f);
	// for (len = 0; len < SHA256_DIGEST_LENGTH; ++len)
	// 	printf("%02x", buffer[len]);
	// putchar('\n');



	// 
	// Test Certificati
	// 
	// printf("%d\n", verifyCertificate("./server/cert-file.pem"));



	// 
	// Test HMAC
	// 
	// int k = 0;
	// unsigned int result_len = 16;
	// unsigned char * results[65];
	// int i;
	// k = HMAC_MD5((unsigned char *)"abc",3,(unsigned char *)"abc",3,(unsigned char * )"f71cda1c893766a115234db7fdd59f63" , results);
	// printf("%s\n",results);



	// 
	// Test RSA
	// // 
	// char plainText[2048/8] = "Hello this is Ravi"; //key length : 2048
	// char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
	// "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
	// "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
	// "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
	// "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
	// "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
	// "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
	// "wQIDAQAB\n"\
	// "-----END PUBLIC KEY-----\n";
	// char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
	// "MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
	// "vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
	// "Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
	// "yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
	// "WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
	// "gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
	// "omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
	// "N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
	// "X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
	// "gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
	// "vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
	// "1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
	// "m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
	// "uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
	// "JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
	// "4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
	// "WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
	// "nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
	// "PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
	// "SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
	// "I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
	// "ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
	// "yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
	// "w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
	// "uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
	// "-----END RSA PRIVATE KEY-----\n";
	// unsigned char  encrypted[4098]={};
	// unsigned char decrypted[4098]={};
	// int encrypted_length= TLS_RSA_public_encrypt(plainText,strlen(plainText),publicKey,encrypted);
	// if(encrypted_length == -1)
	// {
	// 	exit(0);
	// }
	// printf("Encrypted length =%d\n",encrypted_length);
	// int decrypted_length = TLS_RSA_private_decrypt(encrypted,encrypted_length,privateKey, decrypted);
	// if(decrypted_length == -1)
	// {
	// 	exit(0);
	// }
	// printf("Decrypted Text =%s\n",decrypted);
	// printf("Decrypted Length =%d\n",decrypted_length);
	// encrypted_length= TLS_RSA_private_encrypt(plainText,strlen(plainText),privateKey,encrypted);
	// if(encrypted_length == -1)
	// {
	// 	exit(0);
	// }
	// printf("Encrypted length =%d\n",encrypted_length);
	// decrypted_length = TLS_RSA_public_decrypt(encrypted,encrypted_length,publicKey, decrypted);
	// if(decrypted_length == -1)
	// {
	// 	exit(0);
	// }
	// printf("Decrypted Text =%s\n",decrypted);
	// printf("Decrypted Length =%d\n",decrypted_length);

 

	// 
	// Test DH
	// 


	return 0;
}
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <math.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <stdio.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
using namespace std;

EVP_CIPHER_CTX *aesEncryptCtx;
EVP_CIPHER_CTX *aesDecryptCtx;

unsigned char *key;
unsigned char *iv;

void init(string s) {
	if(s.at(0) == 'E') {
	aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(aesEncryptCtx);
	}
	else if(s.at(0) == 'D') {
	aesDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(aesDecryptCtx);
	}
}
int calcDecodedLen(const char *b64m, const size_t len) {
	int padding = 0;
	if(b64m[len-1] == '=' && b64m[len-2] == '=')
		padding = 2;
	else if(b64m[len - 1] == '=')
		padding = 1;

	return (int)len*0.75 - padding;
}
char *b64Encode(unsigned char *message, const size_t len) {
	BIO *bio;
	BIO *b64;
	FILE *fp;

	int encsize = 4 * ceil((double)len/3);
	char *buffer = (char*)malloc(encsize+1);

	fp = fmemopen(buffer, encsize + 1, "w");
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, message, len);
	(void)BIO_flush(bio);
	BIO_free_all(bio);
	fclose(fp);
	
	return buffer;
}
int b64Decode(const char *b64m, const size_t len, unsigned char **buffer) {
	BIO *bio;
	BIO *b64;
	int declen = calcDecodedLen(b64m, len);
	*buffer = (unsigned char *)malloc(declen+1);
	cout << len << endl;
	
	FILE *fp = fmemopen((char*)b64m, len, "r");

	cout << "test" << endl;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_fp(fp, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	declen = BIO_read(bio, *buffer, len);
	(*buffer)[declen] = '\0';

	BIO_free_all(bio);
	fclose(fp);

	return declen;
}
int Encrypt(unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char *key, unsigned char *iv) {

	size_t blocklen = 0;
	size_t encMsglen = 0;

	*encMsg = (unsigned char *)malloc(msgLen + AES_BLOCK_SIZE);
	if(encMsg == NULL) return -1;
	
	if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;

	if(!EVP_EncryptUpdate(aesEncryptCtx, *encMsg, (int*)&blocklen, (unsigned char *)msg, msgLen))
		return -1;

	encMsglen += blocklen;

	if(!EVP_EncryptFinal_ex(aesEncryptCtx, *encMsg + encMsglen, (int*)&blocklen))
		return -1;

	EVP_CIPHER_CTX_cleanup(aesEncryptCtx);

	return encMsglen + blocklen;
}
int Decrypt(unsigned char *encmsg, size_t encmsgLen, unsigned char **decMsg, unsigned char *key, unsigned char *iv) {

	size_t declen = 0;
	size_t blocklen = 0;

	*decMsg = (unsigned char *)malloc(encmsgLen);
	if(decMsg == NULL) return -1;

	
	if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_cbc(), NULL, key, iv))
		return -1;


	if(!EVP_DecryptUpdate(aesDecryptCtx, (unsigned char*)*decMsg, (int*)&blocklen, encmsg, (int)encmsgLen))
		return -1;


	declen += blocklen;

	if(!EVP_DecryptFinal_ex(aesDecryptCtx, (unsigned char*)*decMsg + declen, (int*)&blocklen))
		return -1;

	declen += blocklen;

	EVP_CIPHER_CTX_cleanup(aesDecryptCtx);

	return (int)declen;
}
int main(int argc, char **argv) {

	int il_el = 10000;
	key = (unsigned char *)argv[1];
	iv = (unsigned char *)argv[2];
	char *filename = argv[3];

	string s = "";
	char buffer[300];
	FILE *fp, *enc, *dec;
	unsigned char *file;
	unsigned char *ef, *def;
	int efl, defl;;
	string ED = argv[4];
	if(ED.at(0) == 'E') {
		string e = "E";
		init(e);
		fp = fopen(filename, "r");
		enc = fopen("enc", "w+");
		while( ! feof(fp) ) {
			if (fread(buffer, 1, 128, fp) != 0 ) {
				s = buffer;
				s[s.length()-1] = '\0';
				cout << "S: " << s << endl;
				file = (unsigned char *)s.c_str();
				if((efl = Encrypt(file, s.length(), &ef, key, iv)) == -1) {
					fprintf(stderr, "Encryption failed");
					return 1;
				}
				char *b64buffer = b64Encode(ef, efl);
				ef = (unsigned char *)b64buffer;
				cout << "buffer: " << buffer << "\nefl: " << efl << "\nef: " << ef << endl;
				fputs((const char *)ef, enc);
				memset(buffer, 0, 300);
			}
		}
		fclose(fp);
		fclose(enc);
 
		char allbuffer[il_el];
		unsigned char *tofn;
		string sb = "";

		enc = fopen("enc", "r");
		fread(allbuffer, 1, il_el, enc);
		fclose(enc);

		sb = allbuffer;
		sb[sb.length()] = '\0';
		tofn = (unsigned char *)sb.c_str();

		fp = fopen(filename, "w");
		fputs((const char *)tofn, fp);
		fclose(fp);
	}
	else if(ED.at(0) == 'D') {
		string d = "D";
		init(d);
		fp = fopen(filename, "r");
		dec = fopen("dec", "w+");
		while ( ! feof(fp) ) {
			if(fread(buffer, 1, 192, fp) != 0) {
				s = buffer;
				s[s.length()] = '\0';
				file = (unsigned char *)s.c_str();

				unsigned char *binbuffer;
				cout << "buffer1: " << buffer << "\nefl1: " << efl << "\nfile1: " << file << endl;
				efl = b64Decode((char*)file, s.length(), &binbuffer);
				file = binbuffer;
				cout << "buffer2: " << buffer << "\nefl2: " << efl << "\nfile2: " << file << endl;
				if((defl = Decrypt(file, efl, &def, key, iv)) == -1 ) {
					fprintf(stderr, "Decryption failed");
					return 1;
				}
				fputs((const char *)def, dec);
				memset(buffer, 0, 300);
			}
		}
		fclose(fp);
		fclose(dec);

		char allbuffer[il_el];
		unsigned char *tofn;
		string sb = "";

		dec = fopen("dec", "r");
		fread(allbuffer, 1, il_el, dec);
		fclose(dec);

		sb = allbuffer;
		sb[sb.length()] = '\0';
		tofn = (unsigned char *)sb.c_str();

		fp = fopen(filename, "w");
		fputs((const char *)tofn, fp);
		fclose(fp);
	}
	remove("enc");
	remove("dec");
	return 0;
}

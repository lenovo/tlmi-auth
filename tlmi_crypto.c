/*
 * File: tlmi_crypto.c
 * Implement APIs needed for doing all the crypto operations
 *
 *  Copyright @ 2022 Lenovo. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include "tlmi_crypto.h"

#define CERT_REQ_REVISION    1

#define CERT_REQ_TYPE_LOGON    0
#define CERT_REQ_TYPE_RESET    1
#define CERT_REQ_TYPE_GENERIC  2

#define OTP_LEN     16

#define SIG_16(A, B)        ((A) | (B << 8))
#define SIG_32(A, B, C, D)  (SIG_16 (A, B) | (SIG_16 (C, D) << 16))
#define CBBR_SIG   SIG_32('C', 'B', 'B', 'R')

#pragma pack(1)
typedef struct {
	unsigned int   Signature;          // 'CBBR'  (Certificate Based BIOS Request)
	unsigned int   Length;             // Length of this request
	unsigned char  Revision;           // Revision of this structure
	unsigned short Type;               // Type of this request
	char           Serial[SERIAL_LEN]; // Machine serial number
	char           OTP[OTP_LEN];       // One time password
} CERT_REQUEST;
#pragma pack()

static const int max_key_size = 4096;
static int quiet_mode = 0;
static int verbose_mode = 0;
static int key_passwd_len = 0;
static char key_passwd_buf[MAX_PSWD] = {0};

void print_dbg(const char *format, ...) {
	va_list va;

	if (!verbose_mode)
		return;

	va_start(va, format);
	vprintf(format, va);
	va_end(va);
}

void print_info(const char *format, ...) {
	va_list va;

	if (quiet_mode)
		return;

	va_start(va, format);
	vprintf(format, va);
	va_end(va);
}

void set_key_passwd(char* passwd)
{
	strncpy(key_passwd_buf, passwd, MAX_PSWD);
	key_passwd_len = strnlen(key_passwd_buf, MAX_PSWD);
}

void set_printmode(int quiet, int verbose)
{
	quiet_mode = quiet;
	verbose_mode = verbose;
}

static char *bin2hex(const unsigned char *bin, size_t len)
{
	char   *out;
	size_t  i;

	if (bin == NULL || len == 0)
		return NULL;

	out = (char *)malloc(len * 2 + 1);
	if (!out)
		return NULL;

	for (i = 0; i<len; i++) {
		out[i * 2] = "0123456789ABCDEF"[bin[i] >> 4];
		out[i * 2 + 1] = "0123456789ABCDEF"[bin[i] & 0x0F];
	}
	out[len * 2] = '\0';

	return out;
}

static int hexchr2bin(const char hex, char *out)
{
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9')
		*out = hex - '0';
	else if (hex >= 'A' && hex <= 'F')
		*out = hex - 'A' + 10;
	else if (hex >= 'a' && hex <= 'f')
		*out = hex - 'a' + 10;
	else
		return 0;

	return 1;
}

static size_t hexs2bin(const char *hex, unsigned char **out)
{
	size_t len;
	size_t i;
	char   b1;
	char   b2;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	*out = (unsigned char *)malloc(len);
	if (!*out)
		return 0;

	memset(*out, 'A', len);
	for (i = 0; i<len; i++) {
		if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2))
			return 0;
		(*out)[i] = (b1 << 4) | b2;
	}
	return len;
}

static int Base64Encode(const unsigned char* buffer, size_t length, char** base64Text,
			size_t* certLen)
{
	BIO *bio, *b64;
	BUF_MEM *bptr;
	char *buff;

	b64 = BIO_new(BIO_f_base64());
	if (!b64) 
		return -1;
	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		BIO_free(b64);
		return -1;
	}
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line

	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bptr);

	buff = (char *)malloc(bptr->length + 1);
	if (!buff) {
		BIO_free_all(bio);
		return -1;
	}
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;
	*certLen = bptr->length;

	BIO_free_all(bio);

	*base64Text = buff;
	return 0;
}

static int password_callback(char *buf, int bufsiz, int verify, void *u)
{
	strncpy(buf, key_passwd_buf, bufsiz);
	return key_passwd_len;
}

static RSA *create_RSA(unsigned char * key, int ispub)
{
	RSA *rsa = NULL;
	BIO *keybio;

	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL) {
		fprintf(stderr, "Error: Memory allocation error\n");
		return 0;
	}
	if (ispub)
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	else {
		if (key_passwd_len > 0)
			rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, password_callback, NULL);
		else
			rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL)
		fprintf(stderr, "Error: Failed to read key file.\n");
	else {
		print_dbg("RSA modules: %d\n", RSA_size(rsa));
		print_dbg("RSA bits: %d\n", RSA_bits(rsa));
	}

	return rsa;
}

static int read_keyfile(char *filename, RSA **rsa, int ispub)
{
	FILE *fp = NULL;
	char *keybuf;
	int filesz = 0;
	int ret;

	// Read key from file
	fp = fopen(filename, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s\n", filename);
		return -1;
	}
	// get file size
	fseek(fp, 0, SEEK_END);
	filesz = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	keybuf = (char *)calloc(max_key_size + 1, 1); /* Null-terminate */
	if (!keybuf) {
		fclose(fp);
		return -1;
	}
	ret = fread(keybuf, 1, (size_t)filesz, fp);
	fclose(fp);
	if (ret != filesz) {
		fprintf(stderr, "cannot read %s\n", filename);
		return -1;
	}

	// Create an RSA object from key
	*rsa = create_RSA((unsigned char *)keybuf, ispub);

	free(keybuf);

	if (*rsa == NULL)
		return -1;
	return 0;
}

static int RSASign(RSA* rsa,
	const unsigned char* Msg,
	size_t MsgLen,
	unsigned char** EncMsg,
	size_t* MsgLenEnc)
{
	EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
	EVP_PKEY* priKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priKey, rsa);

	if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0)
		return -1;
	if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
		return -1;
	if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0)
		return -1;

	*EncMsg = (unsigned char*)malloc(*MsgLenEnc);
	if (!*EncMsg) {
		EVP_MD_CTX_free(m_RSASignCtx);
		return -1;
	}

	if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
		return -1;
	EVP_MD_CTX_free(m_RSASignCtx);

	return 0;
}

int wmi_sign(char *keyfile, char *wmistr, char **base64sig, size_t *certLen)
{
	int ret;
	RSA *rsa;
	unsigned char *encString;
	size_t encLen;

	print_info("Signing WMI string...\n");

	if (read_keyfile(keyfile, &rsa, 0) != 0)
		return -1;

	// Sign string
	ret = RSASign(rsa, (unsigned char *)wmistr, strlen(wmistr), &encString, &encLen);
	if (ret != 0) {
		fprintf(stderr, "Error: Failed to sign WMI string\n");
		RSA_free(rsa);
		return ret;
	}

	Base64Encode(encString, encLen, base64sig, certLen);

	RSA_free(rsa);
	return ret;
}

int unlock_request(char *keyfile, char *request)
{
	CERT_REQUEST req;
	RSA *rsa;
	int ret = 0;
	unsigned char *encrypted;
	int len;
	char otp[OTP_LEN + 1];
	char serial[SERIAL_LEN];
	unsigned char *buf;
	int type;

	memset(otp, 0, sizeof(otp));
	memset(serial, 0, sizeof(serial));

	if (read_keyfile(keyfile, &rsa, 0) != 0)
		return -1;

	// Decrypt request.
	buf = (unsigned char *)calloc(RSA_size(rsa), 1);
	if (!buf)
		return -1;

	hexs2bin(request, &encrypted);
	len = RSA_size(rsa);
	ret = RSA_private_decrypt(len, encrypted, buf, rsa, RSA_PKCS1_OAEP_PADDING);
	if (ret == -1) {
		fprintf(stderr, "Error: Failed to decrypt request data.\n");
		print_dbg("%s\n", ERR_error_string(ERR_get_error(), NULL));
		free(encrypted);
		free(buf);
		RSA_free(rsa);
		return -1;
	}

	memcpy(&req, buf, sizeof(req));

	// Validate request
	if ((req.Signature != CBBR_SIG) || req.Revision > CERT_REQ_REVISION) {
		fprintf(stderr, "Error: Invalid request data.\n");
		free(encrypted);
		free(buf);
		RSA_free(rsa);
		return -1;
	}

	type = req.Type;
	if (type == CERT_REQ_TYPE_LOGON)
		print_info("Generating logon code...\n");
	else if (type == CERT_REQ_TYPE_RESET)
		print_info("Generating reset code...\n");
	else
		print_info("Generating unlock code...\n");

	memcpy(otp, req.OTP, OTP_LEN);
	memcpy(serial, req.Serial, 8);

	if (req.Type != type) {
		fprintf(stderr, "Error: Invalid request type\n");
		ret = -1;
	}

	print_info("Machine Serial: %s\n", serial);
	print_info("Unlock code: ");
	printf("%s", otp);

	free(encrypted);
	free(buf);
	RSA_free(rsa);

	return ret;
}

int unlock_file_request(char *keyfile, char *reqfile)
{
	FILE *fp;
	int filesz;
	char *reqString;
	char *p;
	int ret = 0;

	/* read certificate from file */
	fp = fopen(reqfile, "r");
	if (!fp) {
		fprintf(stderr, "cannot open %s\n", reqfile);
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	filesz = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// read file
	reqString = (char *)calloc((long)filesz + 1, 1);
	if (!reqString) {
		fclose(fp);
		return -1;
	}

	p = reqString;
	while ((*p = fgetc(fp)) != EOF)
		p++;
	fclose(fp);
	reqString[filesz] = 0;

	ret = unlock_request(keyfile, reqString);
	free(reqString);

	return ret;
}

static int RsaEncryptDataTest (void *Pubkey, void *Data, int Length)
{
	RSA *rsa;
	unsigned char *buf;
	int len;

	// Create an RSA object from key
	rsa = create_RSA((unsigned char *)Pubkey, 1);
	if (rsa == NULL)
		return -1;

	// Encrypt data
	buf = (unsigned char *)calloc(RSA_size(rsa), 1);
	if (!buf) {
		RSA_free(rsa);
		return -1;
	}
	len = RSA_public_encrypt(Length, (unsigned char *)Data, buf, rsa, RSA_PKCS1_OAEP_PADDING);
	free(buf);
	RSA_free(rsa);

	if (len == -1)
		return -1;
	return 0;
}

static int pkey_encryption_test(EVP_PKEY *pkey)
{
	CERT_REQUEST req;
	BIO *pubBio = NULL;
	int publen;
	char *Pubkey;
	int ret;
	char tempOtp[] = "1234567890123456";

	print_info("Running encryption test..\n");

	pubBio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(pubBio, pkey);
	publen = BIO_pending(pubBio);
	Pubkey = (char *)calloc(publen + 1, 1);
	if (!Pubkey) {
		BIO_free(pubBio);
		return -1;
	}
	BIO_read(pubBio, Pubkey, publen);

	// Make test request
	req.Signature = CBBR_SIG;
	req.Length = sizeof(CERT_REQUEST);
	req.Revision = CERT_REQ_REVISION;
	req.Type = CERT_REQ_TYPE_GENERIC;
	memcpy(req.OTP, tempOtp, OTP_LEN);

	// Encrypt request
	ret = RsaEncryptDataTest (Pubkey, &req, sizeof(CERT_REQUEST));

	free(Pubkey);
	BIO_free(pubBio);
	return ret;
}

#define BUF_LEN 256

int cert_format_pem(char *certFile, char **base64cert, size_t *certLen)
{
	FILE *fp;
	int filesz = 0;
	void *certBuf;
	BIO* certBio;
	X509* cert;
	char *p;
	int check;
	size_t ret;
	char buf[BUF_LEN];
	int nid;
	ASN1_OBJECT *paobj;
	EVP_PKEY *pkey;
	//BIO *outBio = NULL;
	int len;
	unsigned char *der;
	unsigned char *tmp;

	print_info("Parsing a PEM encoded certificate file...\n");

	/* read certificate from file */
	fp = fopen(certFile, "r");
	if (!fp) {
		fprintf(stderr, "cannot open %s\n", certFile);
		return -1;
	}
	// get file size
	fseek(fp, 0, SEEK_END);
	filesz = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// read file
	certBuf = calloc((long)filesz + 1, 1);
	if (!certBuf) {
		fclose(fp);
		return -1;
	}
	ret = fread(certBuf, 1, (size_t)filesz, fp);
	fclose(fp);
	if (ret != filesz) {
		fprintf(stderr, "cannot read %s\n", certFile);
		return -1;
	}

	*certLen = (size_t)filesz;
	certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, certBuf, *certLen);

	cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
	if (!cert) {
		fprintf(stderr, "unable to parse certificate in memory\n");
		return -1;
	}

	// Validate input certificate
	// X509 Certificate Subject and Issueer
	check = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf, BUF_LEN);
	if(check > 0)
		print_info(" Subject : %s\n", buf);
	check = X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_organizationName, buf, BUF_LEN);
	if(check > 0)
		print_info(" Issuer  : %s\n", buf);

	// RSA
	X509_PUBKEY_get0_param(&paobj, NULL, 0, NULL, X509_get_X509_PUBKEY(cert));
	nid = OBJ_obj2nid(paobj);
	if (nid == NID_undef) {
		fprintf(stderr, "unable to find specified signature algorithm name.\n");
		return -1;
	}
	if (nid != NID_rsaEncryption) {
		fprintf(stderr, "unsupported encryption algorithm. it must be RSA algorithm.\n");
		return -1;
	}

	// Public key
	pkey = X509_get_pubkey(cert);
	if (pkey == NULL) {
		fprintf(stderr, "failed to get public key from certificate.\n");
		return -1;
	}

	// Key length
	print_info(" Public Key\n");
	print_info(" %d bit RSA key\n", EVP_PKEY_bits(pkey));
	if (EVP_PKEY_bits(pkey) != 2048) {
		fprintf(stderr, "RSA key size must be 2048 bit.\n");
		return -1;
	}

	// Encryption test.
	if (pkey_encryption_test(pkey) != 0) {
		fprintf(stderr, "failed to run encryption test.\n");
		return -1;
	}

	// Dump public key
	//outBio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	//PEM_write_bio_PUBKEY(outBio, pkey);
	//BIO_free(outBio);

	// Convert PEM format to DER
	len = i2d_X509(cert, NULL);
	der = (unsigned char *)malloc(len);
	if (der == NULL) {
		fprintf(stderr, "memory allocation error\n");
		return -1;
	}
	tmp = der;

	i2d_X509(cert, &tmp);
	Base64Encode(der, len, base64cert, certLen);

	free(der);
	BIO_free(certBio);
	X509_free(cert);

	return 0;
}


int cert_format_der(char *certFile, char **base64cert, size_t *certLen)
{
	FILE *fp;
	int filesz = 0;
	void *certBuf;
	BIO* certBio;
	X509* cert;
	int check;
	char buf[BUF_LEN];
	int nid;
	ASN1_OBJECT *paobj;
	EVP_PKEY *pkey;
	//BIO *outBio = NULL;
	unsigned char *tmp;
	size_t ret;

	print_info("Parsing a DER encoded certificate file...\n");

	/* read certificate from binary file */
	fp = fopen(certFile, "rb");
	if (!fp) {
		fprintf(stderr, "cannot open %s\n", certFile);
		return -1;
	}
	// get file size
	fseek(fp, 0, SEEK_END);
	filesz = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// read file
	certBuf = calloc((size_t)(filesz + 1), 1);
	if (!certBuf) {
		fclose(fp);
		return -1;
	}

	ret = fread(certBuf, 1, (size_t)filesz, fp);
	fclose(fp);
	if (ret != filesz) {
		fprintf(stderr, "cannot read %s\n", certFile);
		return -1;
	}

	certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, certBuf, filesz);

	cert = d2i_X509_bio(certBio, NULL);
	if (!cert) {
		fprintf(stderr, "unable to parse certificate in memory\n");
		return -1;
	}

	// Validate input certificate
	// X509 Certificate Subject and Issuuer
	check = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf, BUF_LEN);
	if (check > 0)
		print_info(" Subject : %s\n", buf);
	check = X509_NAME_get_text_by_NID(X509_get_issuer_name(cert), NID_organizationName, buf, BUF_LEN);
	if (check > 0)
		print_info(" Issuer  : %s\n", buf);

	// RSA
	X509_PUBKEY_get0_param(&paobj, NULL, 0, NULL, X509_get_X509_PUBKEY(cert));
	nid = OBJ_obj2nid(paobj);
	if (nid == NID_undef) {
		fprintf(stderr, "unable to find specified signature algorithm name.\n");
		return -1;
	}
	if (nid != NID_rsaEncryption) {
		fprintf(stderr, "unsupported encryption algorithm. it must be RSA algorithm.\n");
		return -1;
	}

	// Public key
	pkey = X509_get_pubkey(cert);
	if (pkey == NULL) {
		fprintf(stderr, "failed to get public key from certificate.\n");
		return -1;
	}

	// Key length
	print_info(" Public Key\n");
	print_info(" %d bit RSA key\n", EVP_PKEY_bits(pkey));
	if (EVP_PKEY_bits(pkey) != 2048) {
		fprintf(stderr, "RSA key size must be 2048 bit.\n");
		return -1;
	}

	// Encryption test.
	if (pkey_encryption_test(pkey) != 0) {
		fprintf(stderr, "failed to run encryption test.\n");
		return -1;
	}

	// Dump public key
	//outBio  = BIO_new_fp(stdout, BIO_NOCLOSE);
	//PEM_write_bio_PUBKEY(outBio, pkey);
	//BIO_free(outBio);

	tmp = (unsigned char *)certBuf;

	i2d_X509(cert, &tmp);
	Base64Encode((unsigned char *)certBuf, filesz, base64cert, certLen);

	BIO_free(certBio);
	X509_free(cert);

	return 0;
}

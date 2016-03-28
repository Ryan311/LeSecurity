#ifndef __AES_ENCRYPT_H
#define __AES_ENCRYPT_H


// AES Encrypt
void AesEncrypt(
	unsigned long KeyLen,
	unsigned char *pKey,
	unsigned char *pPlainTextData,
	unsigned char *pEncryptedData
	);

void AES_128(
	unsigned char *pKey,
	unsigned char *pPlainTextData,
	unsigned char *pEncryptedData
	);

void AES_128_Test(void);

#endif
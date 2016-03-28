#ifndef __AES_CMAC_H
#define __AES_CMAC_H

void AES_CMAC(
	unsigned char *key, 
	unsigned char *input, 
	int length, 
	unsigned char *mac
);

int AES_CMAC_Test(void);

#endif
/****************************************************************/
/* AES-CMAC with AES-128 bit                                    */
/* CMAC     Algorithm described in SP800-38B                    */
/* Author: Junhyuk Song (junhyuk.song@samsung.com)              */
/*         Jicheol Lee  (jicheol.lee@samsung.com)               */
/****************************************************************/
#include "stdafx.h"
#include "aes_encrypt.h"
#include "crypto_helper.h"

/* For CMAC Calculation */
unsigned char const_Rb[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};

unsigned char const_Zero[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/* AES-CMAC Generation Function */
void leftshift_onebit(unsigned char *input, unsigned char *output)
{
	int         i;
	unsigned char overflow = 0;
	for (i = 15; i >= 0; i--) {
		output[i] = input[i] << 1;
		output[i] |= overflow;
		overflow = (input[i] & 0x80) ? 1 : 0;
	}
	return;
}

void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2)
{
	unsigned char L[16];
	unsigned char Z[16];
	unsigned char tmp[16];
	int i;
	for (i = 0; i < 16; i++) Z[i] = 0;
	AES_128(key, Z, L);
	if ((L[0] & 0x80) == 0) { /* If MSB(L) = 0, then K1 = L << 1 */
		leftshift_onebit(L, K1);
	}
	else {    /* Else K1 = ( L << 1 ) (+) Rb */
		leftshift_onebit(L, tmp);
		xor_128(tmp, const_Rb, K1);
	}
	if ((K1[0] & 0x80) == 0) {
		leftshift_onebit(K1, K2);
	}
	else {
		leftshift_onebit(K1, tmp);
		xor_128(tmp, const_Rb, K2);
	}
	return;
}

void padding(unsigned char *lastb, unsigned char *pad, int length)
{
	int         j;
	/* original last block */
	for (j = 0; j < 16; j++) {
		if (j < length) {
			pad[j] = lastb[j];
		}
		else if (j == length) {
			pad[j] = 0x80;
		}
		else {
			pad[j] = 0x00;
		}
	}
}
void AES_CMAC(unsigned char *key, unsigned char *input, int length, unsigned char *mac)
{
	unsigned char       X[16], Y[16], M_last[16], padded[16];
	unsigned char       K1[16], K2[16];
	int         n, i, flag;
	generate_subkey(key, K1, K2);
	n = (length + 15) / 16;       /* n is number of rounds */
	if (n == 0) {
		n = 1;
		flag = 0;
	}
	else {
		if ((length % 16) == 0) { /* last block is a complete block */
			flag = 1;
		}
		else { /* last block is not complete block */
			flag = 0;
		}
	}

	if (flag) { /* last block is complete block */
		xor_128(&input[16 * (n - 1)], K1, M_last);
	}
	else {
		padding(&input[16 * (n - 1)], padded, length % 16);
		xor_128(padded, K2, M_last);
	}

	for (i = 0; i < 16; i++) X[i] = 0;

	for (i = 0; i < n - 1; i++) {
		xor_128(X, &input[16 * i], Y); /* Y := Mi (+) X  */
		AES_128(key, Y, X);      /* X := AES-128(KEY, Y); */
	}

	xor_128(X, M_last, Y);
	AES_128(key, Y, X);
	for (i = 0; i < 16; i++) {
		mac[i] = X[i];
	}
}


/************************************************************************************/
//				Function Tester
/************************************************************************************/
/**
	The following test vectors are referenced from RFC4493.
	K                     2b7e1516 28aed2a6 abf71588 09cf4f3c
	Subkey Generation
	AES_128(key,0)        7df76b0c 1ab899b3 3e42f047 b91b546f
	K1                    fbeed618 35713366 7c85e08f 7236a8de
	K2                    f7ddac30 6ae266cc f90bc11e e46d513b

	Example 1: Len = 0
	M              <empty string>
	AES_CMAC       bb1d6929 e9593728 7fa37d12 9b756746

	Example 2: Len = 16
	M              6bc1bee2 2e409f96 e93d7e11 7393172a
	AES_CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c

	Example 3: Len = 40
	M0             6bc1bee2 2e409f96 e93d7e11 7393172a
	M1             ae2d8a57 1e03ac9c 9eb76fac 45af8e51
	M2             30c81c46 a35ce411
	AES_CMAC       dfa66747 de9ae630 30ca3261 1497c827

	Example 4: Len = 64
	M0             6bc1bee2 2e409f96 e93d7e11 7393172a
	M1             ae2d8a57 1e03ac9c 9eb76fac 45af8e51
	M2             30c81c46 a35ce411 e5fbc119 1a0a52ef
	M3             f69f2445 df4f9b17 ad2b417b e66c3710
	AES_CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
*/
int AES_CMAC_Test(void)
{
	unsigned char L[16], K1[16], K2[16], T[16];
	unsigned char M[64] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};
	unsigned char key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};
	printf("--------------------------------------------------\n");
	printf("K              "); print128(key); printf("\n");
	printf("\nSubkey Generation\n");

	AES_128(key, const_Zero, L);
	printf("AES_128(key,0) "); print128(L); printf("\n");

	generate_subkey(key, K1, K2);
	printf("K1             "); print128(K1); printf("\n");
	printf("K2             "); print128(K2); printf("\n");

	printf("\nExample 1: len = 0\n");
	printf("M              "); printf("<empty string>\n");
	AES_CMAC(key, M, 0, T);
	printf("AES_CMAC       "); print128(T); printf("\n");

	printf("\nExample 2: len = 16\n");
	printf("M              "); print_hex("                ", M, 16);
	AES_CMAC(key, M, 16, T);
	printf("AES_CMAC       "); print128(T); printf("\n");

	printf("\nExample 3: len = 40\n");
	printf("M              "); print_hex("               ", M, 40);
	AES_CMAC(key, M, 40, T);
	printf("AES_CMAC       "); print128(T); printf("\n");

	printf("\nExample 4: len = 64\n");
	printf("M              "); print_hex("               ", M, 64);
	AES_CMAC(key, M, 64, T);
	printf("AES_CMAC       "); print128(T); printf("\n");
	printf("--------------------------------------------------\n");
	return 0;
}




#include "stdafx.h"

/* Basic Functions */
void xor_128(unsigned char *a, unsigned char *b, unsigned char *out)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		out[i] = a[i] ^ b[i];
	}
}

unsigned short __GetUnalignedU16(const unsigned char *P)
{
	return P[0] | P[1] << 8;
}

unsigned long __GetUnalignedU32(const unsigned char *P)
{
	return P[0] | P[1] << 8 | P[2] << 16 | P[3] << 24;
}

unsigned long long  __GetUnalignedU64(const unsigned char *P)
{
	return (unsigned long long)__GetUnalignedU32(P + 4) << 32 |
		__GetUnalignedU32(P);
}


unsigned short GetUnalignedU16(const void *P)
{
	return __GetUnalignedU16((const unsigned char *)P);
}

unsigned long GetUnalignedU32(const void *P)
{
	return __GetUnalignedU32((const unsigned char *)P);
}

unsigned long long GetUnalignedU64(const void *P)
{
	return __GetUnalignedU64((const unsigned char *)P);
}


void __PutUnalignedU16(unsigned short Val, unsigned char *P)
{
	*P++ = (unsigned char)Val;
	*P++ = (unsigned char)(Val >> 8);
}

void __PutUnalignedU32(unsigned long Val, unsigned char *P)
{
	__PutUnalignedU16((unsigned short)(Val >> 16), P + 2);
	__PutUnalignedU16((unsigned short)(Val), P);
}

void __PutUnalignedU64(unsigned long long Val, unsigned char *P)
{
	__PutUnalignedU32((unsigned long)(Val >> 32), P + 4);
	__PutUnalignedU32((unsigned long)Val, P);
}

void PutUnalignedU16(unsigned short Val, unsigned char *P)
{
	__PutUnalignedU16(Val, P);
}

void PutUnalignedU32(unsigned long Val, unsigned char *P)
{
	__PutUnalignedU32(Val, P);
}

void PutUnalignedU64(unsigned long long Val, unsigned char *P)
{
	__PutUnalignedU64(Val, P);
}


void print_hex(char *str, unsigned char *buf, int len)
{
	int     i;
	for (i = 0; i < len; i++) {
		if ((i % 16) == 0 && i != 0) printf(str);
		printf("%02x", buf[i]);
		if ((i % 4) == 3) printf(" ");
		if ((i % 16) == 15) printf("\n");
	}
	if ((i % 16) != 0) printf("\n");
}

void print128(unsigned char *bytes)
{
	int j;
	for (j = 0; j < 16; j++) {
		printf("%02x", bytes[j]);
		if ((j % 4) == 3) printf(" ");
	}
}

void print96(unsigned char *bytes)
{
	int j;
	for (j = 0; j < 12; j++) {
		printf("%02x", bytes[j]);
		if ((j % 4) == 3) printf(" ");
	}
}

void print32(unsigned char *bytes)
{
	int j;
	for (j = 0; j < 4; j++) {
		printf("%02x", bytes[j]);
	}
}

void printBytes(unsigned char *bytes, int n)
{
	int j;
	for (j = 0; j < n; j++) {
		printf("%02x", bytes[j]);
		if ((j % 4) == 3) printf(" ");
	}
}
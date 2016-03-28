#ifndef __CRYPTO_HELPER
#define __CRYPTO_HELPER

void xor_128(unsigned char *a, unsigned char *b, unsigned char *out);

void print_hex(char *str, unsigned char *buf, int len);
void printBytes(unsigned char *bytes, int n);
void print128(unsigned char *bytes);
void print96(unsigned char *bytes);
void print32(unsigned char *bytes);

unsigned short __GetUnalignedU16(const unsigned char *P);
unsigned long __GetUnalignedU32(const unsigned char *P);
unsigned long long  __GetUnalignedU64(const unsigned char *P);
unsigned short GetUnalignedU16(const void *P);
unsigned long GetUnalignedU32(const void *P);
unsigned long long GetUnalignedU64(const void *P);
void __PutUnalignedU16(unsigned short Val, unsigned char *P);
void __PutUnalignedU32(unsigned long Val, unsigned char *P);
void __PutUnalignedU64(unsigned long long Val, unsigned char *P);
void PutUnalignedU16(unsigned short Val, unsigned char *P);
void PutUnalignedU32(unsigned long Val, unsigned char *P);
void PutUnalignedU64(unsigned long long Val, unsigned char *P);
#endif
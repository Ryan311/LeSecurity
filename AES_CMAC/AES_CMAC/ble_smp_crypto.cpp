#include "stdafx.h"
#include "aes_encrypt.h"
#include "aes_cmac.h"
#include "crypto_helper.h"

/*********************Legacy Pairing***********************************/
/*
* Security function e
*
* Security function e generates 128-bit encryptedData from a 128-bit key
* and 128-bit plaintextData using the AES-128-bit block cypher:
*
*   encryptedData = e(key, plaintextData)
*
* The most significant octet of key corresponds to key[0], the most
* significant octet of plaintextData corresponds to in[0] and the
* most significant octet of encryptedData corresponds to out[0].
*
*/
void Bt_SMP_e(
	unsigned char *pKey,
	unsigned char *pPlainTextData,
	unsigned char *pEncryptedData
	)
{
	AES_128(pKey, pPlainTextData, pEncryptedData);
}

/*
* Random Address Hash function ah
*
* The random address hash function ah is used to generate a hash value
* that is used in resolvable private addresses.
*
* The following are inputs to the random address hash function ah:
*
*   k is 128 bits
*   r is 24 bits
*   padding is 104 bits
*
* r is concatenated with padding to generate r' which is used as the
* 128-bit input parameter plaintextData to security function e:
*
*   r' = padding || r
*
* The least significant octet of r becomes the least significant octet
* of râ€™ and the most significant octet of padding becomes the most
* significant octet of r'.
*
* For example, if the 24-bit value r is 0x423456 then r' is
* 0x00000000000000000000000000423456.
*
* The output of the random address function ah is:
*
*   ah(k, r) = e(k, r') mod 2^24
*
* The output of the security function e is then truncated to 24 bits by
* taking the least significant 24 bits of the output of e as the result
* of ah.
*/
void Bt_SMP_ah(
	unsigned char k[16],
	unsigned char r[3],
	unsigned char hash[3]
	)
{
	unsigned char rp[16];
	unsigned char encrypted[16];

	/* r' = padding || r */
	memset(rp, 0, 16);
	memcpy(rp+13, r, 3);

	/* e(k, r') */
	Bt_SMP_e(k, rp, encrypted);

	/* ah(k, r) = e(k, r') mod 2^24 */
	memcpy(hash, encrypted+13, 3);
}

/*
* Confirm value generation function c1
*
* During the pairing process confirm values are exchanged. This confirm
* value generation function c1 is used to generate the confirm values.
*
* The following are inputs to the confirm value generation function c1:
*
*   k is 128 bits
*   r is 128 bits
*   pres is 56 bits
*   preq is 56 bits
*   iat is 1 bit
*   ia is 48 bits
*   rat is 1 bit
*   ra is 48 bits
*   padding is 32 bits of 0
*
* iat is concatenated with 7-bits of 0 to create iat' which is 8 bits
* in length. iat is the least significant bit of iat'
*
* rat is concatenated with 7-bits of 0 to create rat' which is 8 bits
* in length. rat is the least significant bit of rat'
*
* pres, preq, rat' and iat' are concatenated to generate p1 which is
* XORed with r and used as 128-bit input parameter plaintextData to
* security function e:
*
*   p1 = pres || preq || rat' || iat'
*
* The octet of iat' becomes the least significant octet of p1 and the
* most significant octet of pres becomes the most significant octet of
* p1.
*
* ra is concatenated with ia and padding to generate p2 which is XORed
* with the result of the security function e using p1 as the input
* paremter plaintextData and is then used as the 128-bit input
* parameter plaintextData to security function e:
*
*   p2 = padding || ia || ra
*
* The least significant octet of ra becomes the least significant octet
* of p2 and the most significant octet of padding becomes the most
* significant octet of p2.
*
* The output of the confirm value generation function c1 is:
*
*   c1(k, r, preq, pres, iat, rat, ia, ra) = e(k, e(k, r XOR p1) XOR p2)
*
* The 128-bit output of the security function e is used as the result
* of confirm value generation function c1.
*/
void Bt_SMP_c1(
	unsigned char k[16], 
	unsigned char r[16], 
	unsigned char pres[7],
	unsigned char preq[7],
	unsigned char iat,
	unsigned char ia[6],
	unsigned char rat,
	unsigned char ra[6],
	unsigned char res[16]
	)
{
	unsigned char p1[16], p2[16];

	/* p1 = pres || preq || _rat || _iat */
	memcpy(p1, pres, 7);
	memcpy(p1 + 7, preq, 7);
	p1[14] = rat;
	p1[15] = iat;

	/* p2 = padding || ia || ra */
	memset(p2, 0, 16);
	memcpy(p2 + 4, ia, 6);
	memcpy(p2 + 10, ra, 6);

	/* res = r XOR p1 */
	xor_128(r, p1, res);

	/* res = e(k, res) */
	Bt_SMP_e(k, res, res);

	/* res = res XOR p2 */
	xor_128(res, p2, res);

	/* res = e(k, res) */
	Bt_SMP_e(k, res, res);
}

/*
* Key generation function s1
*
* The key generation function s1 is used to generate the STK during the
* pairing process.
*
* The following are inputs to the key generation function s1:
*
*   k is 128 bits
*   r1 is 128 bits
*   r2 is 128 bits
*
* The most significant 64-bits of r1 are discarded to generate r1' and
* the most significant 64-bits of r2 are discarded to generate r2'.
*
* r1' is concatenated with r2' to generate r' which is used as the
* 128-bit input parameter plaintextData to security function e:
*
*   r' = r1' || r2'
*
* The least significant octet of r2' becomes the least significant
* octet of r' and the most significant octet of r1' becomes the most
* significant octet of r'.
*
* The output of the key generation function s1 is:
*
*   s1(k, r1, r2) = e(k, r')
*
* The 128-bit output of the security function e is used as the result
* of key generation function s1.
*/
void Bt_SMP_s1(
	unsigned char k[16],
	unsigned char r1[16],
	unsigned char r2[16],
	unsigned char res[16]
	)
{
	memcpy(res, r1+8, 8);
	memcpy(res + 8, r2+8, 8);

	Bt_SMP_e(k, res, res);
}

/*********************LE Security Connections******************************/
// LE Secure Connections Confirm Value Generation Function f4
void Bt_SMP_f4(
	unsigned char u[32], 
	unsigned char v[32], 
	unsigned char x[16], 
	unsigned char z, 
	unsigned char res[16]
)
{
	unsigned char m[65];

	memcpy(&m[0], u, 32);
	memcpy(&m[32], v, 32);
	m[64] = z;

	AES_CMAC(x, m, sizeof(m), res);
}

// LE Secure Connections Key Generation Function f5
void Bt_SMP_f5(
	unsigned char w[32], 
	unsigned char n1[16], 
	unsigned char n2[16], 
	unsigned char a1[7], 
	unsigned char a2[7], 
	unsigned char mackey[16], 
	unsigned char ltk[16]
)
{
	unsigned char btle[4] = { 0x62, 0x74, 0x6c, 0x65 };	//keyID: "btle" 
	unsigned char salt[16] = { 0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38, 0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x60, 0x83, 0xBE };
	unsigned char length[2] = { 0x01, 0x00 };
	unsigned char m[53], t[16];

	AES_CMAC(salt, w, 32, t);

	memcpy(&m[1], btle, 4);
	memcpy(&m[5], n1, 16);
	memcpy(&m[21], n2, 16);
	memcpy(&m[37], a1, 7);
	memcpy(&m[44], a2, 7);
	memcpy(&m[51], length, 2);

	m[0] = 0; /* Counter */
	AES_CMAC(t, m, sizeof(m), mackey);

	m[0] = 1; /* Counter */
	AES_CMAC(t, m, sizeof(m), ltk);
}

//LE Secure Connections Check Value Generation Function f6
void Bt_SMP_f6(
	unsigned char w[16],
	unsigned char n1[16],
	unsigned char n2[16],
	unsigned char r[16],
	unsigned char io_cap[3],
	unsigned char a1[7],
	unsigned char a2[7],
	unsigned char res[16]
)
{
	unsigned char m[65];

	memcpy(&m[0], n1, 16);
	memcpy(&m[16], n2, 16);
	memcpy(&m[32], r, 16);
	memcpy(&m[48], io_cap, 3);
	memcpy(&m[51], a1, 7);
	memcpy(&m[58], a2, 7);

	AES_CMAC(w, m, sizeof(m), res);
}

//  LE Secure Connections Numeric Comparison Value Generation Function g2
void Bt_SMP_g2(
	unsigned char u[32],
	unsigned char v[32],
	unsigned char x[16],
	unsigned char y[16],
	unsigned char val[4]
	)
{
	unsigned char m[80], tmp[16];

	memcpy(&m[0], u, 32);
	memcpy(&m[32], v, 32);
	memcpy(&m[64], y, 16);

	AES_CMAC(x, m, sizeof(m), tmp);

	memcpy(val, &tmp[12], 4);
	//*val = GetUnalignedU32(&tmp[12]);
	//*val %= 1000000;
}

//Link Key Conversion Function h6
void Bt_SMP_h6(
	unsigned char w[32],
	unsigned char keyID[4],
	unsigned char res[16]
	)
{
	AES_CMAC(w, keyID, 4, res);
}


/************************************************************************************/
//				Function Tester
/************************************************************************************/
/**
	iat		0x01
	rat		0x00
	preq	0x07071000000101
	pres	0x05000800000302
	p1		0x05000800000302070710000001010001		// p1 = pres || preq || rat’ || iat’

	ia		0xA1A2A3A4A5A6
	ra		0xB1B2B3B4B5B6
	p2		0x00000000A1A2A3A4A5A6B1B2B3B4B5B6		// p2 = padding || ia || ra

	k		0x00000000000000000000000000000000
	r		0x5783D52156AD6F0E6388274EC6702EE0
	c1		0x1e1e3fef878988ead2a74dc5bef13b86

*/
void Bt_SMP_c1_Test()
{
	unsigned char k[16] = { 0 };
	unsigned char r[16] = { 0x57, 0x83, 0xD5, 0x21, 0x56, 0xAD, 0x6F, 0x0E, 0x63, 0x88, 0x27, 0x4E, 0xC6, 0x70, 0x2E, 0xE0 };
	unsigned char iat = 0x01;
	unsigned char rat = 0x00;
	unsigned char preq[7] = { 0x07, 0x07, 0x10, 0x00, 0x00, 0x01, 0x01 };
	unsigned char pres[7] = { 0x05, 0x00, 0x08, 0x00, 0x00, 0x03, 0x02 };
	unsigned char ia[6] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6 };
	unsigned char ra[6] = { 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6 };
	unsigned char res[16] = { 0 };

	printf("--------------------------------------------------\n");
	printf("k              "); print128(k); printf("\n");
	printf("r              "); print128(r); printf("\n");
	printf("pres           "); printBytes(pres, sizeof(pres)); printf("\n");
	printf("preq           "); printBytes(preq, sizeof(preq)); printf("\n");
	printf("iat            "); printBytes(&iat, 1); printf("\n");
	printf("ia             "); printBytes(ia, sizeof(ia)); printf("\n");
	printf("rat            "); printBytes(&rat, 1); printf("\n");
	printf("ra             "); printBytes(ra, sizeof(ra)); printf("\n");
	Bt_SMP_c1(k, r, pres, preq, iat, ia, rat, ra, res);
	printf("\nBt_SMP_c1      "); print128(res); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	r1		0x000F0E0D0C0B0A091122334455667788
	r2		0x010203040506070899AABBCCDDEEFF00
	r1’		0x1122334455667788
	r2’		0x99AABBCCDDEEFF00
	r’		0x112233445566778899AABBCCDDEEFF00	// r’ = r1’ || r2’
	k		0x00000000000000000000000000000000

	s1		0x9a1fe1f0e8b0f49b5b4216ae796da062	// s1(k, r1, r2) = e(k, r’)
*/
void Bt_SMP_s1_Test()
{
	unsigned char k[16] = { 0 };
	unsigned char r1[16] = { 0x00, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	unsigned char r2[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
	unsigned char s1[16] = { 0 };
	
	printf("--------------------------------------------------\n");
	printf("k              "); print128(k); printf("\n");
	printf("r1             "); print128(r1); printf("\n");
	printf("r2             "); print128(r2); printf("\n");
	Bt_SMP_s1(k, r1, r2, s1);
	printf("\nBt_SMP_s1      "); print128(s1); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	IRK            ec0234a3 57c8ad05 341010a6 0a397d9b
	prand          00000000 00000000 00000000 00708194
	M              00000000 00000000 00000000 00708194
	AES_128        159d5fb7 2ebe2311 a48c1bdc c40dfbaa
	ah             0dfbaa
*/
void Bt_SMP_ah_Test()
{
	unsigned char k[16] = { 0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b };
	unsigned char r[3] = { 0x70, 0x81, 0x94 };
	unsigned char hash[3] = { 0 };

	printf("--------------------------------------------------\n");
	printf("k              "); print128(k); printf("\n");
	printf("r              "); printBytes(r, sizeof(r)); printf("\n");
	Bt_SMP_ah(k, r, hash);
	printf("\nBt_SMP_ah      "); printBytes(hash, sizeof(hash)); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	U				20b003d2 f297be2c 5e2c83a7 e9f9a5b9
					eff49111 acf4fddb cc030148 0e359de6
	V				55188b3d 32f6bb9a 900afcfb eed4e72a
					59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
	X				d5cb8454 d177733e ffffb2ec 712baeab
	Z				0x00

	M0				20b003d2 f297be2c 5e2c83a7 e9f9a5b9
	M1				eff49111 acf4fddb cc030148 0e359de6
	M2				55188b3d 32f6bb9a 900afcfb eed4e72a
	M3				59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
					00
	AES_CMAC        f2c916f1 07a9bd1c f1eda1be a974872d
*/
void Bt_SMP_f4_Test()
{
	unsigned char x[16] = { 0xd5, 0xcb, 0x84, 0x54, 0xd1, 0x77, 0x73, 0x3e, 0xff, 0xff, 0xb2, 0xec, 0x71, 0x2b, 0xae, 0xab };
	unsigned char u[32] = { 0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c, 0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9,
							0xef, 0xf4, 0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb, 0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6 };
	unsigned char v[32] = { 0x55, 0x18, 0x8b, 0x3d, 0x32, 0xf6, 0xbb, 0x9a, 0x90, 0x0a, 0xfc, 0xfb, 0xee, 0xd4, 0xe7, 0x2a,
							0x59, 0xcb, 0x9a, 0xc2, 0xf1, 0x9d, 0x7c, 0xfb, 0x6b, 0x4f, 0xdd, 0x49, 0xf4, 0x7f, 0xc5, 0xfd };
	unsigned char z = 0x00;
	unsigned char res[16] = { 0 };

	printf("--------------------------------------------------\n");
	printf("x              "); print128(x); printf("\n");
	printf("u              "); printBytes(u, sizeof(u)); printf("\n");
	printf("v              "); printBytes(v, sizeof(v)); printf("\n");
	printf("z              "); printBytes(&z, 1); printf("\n");
	Bt_SMP_f4(u, v, x, z, res);
	printf("\nBt_SMP_f4      "); print128(res); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	DHKey(W)       ec0234a3 57c8ad05 341010a6 0a397d9b
				   99796b13 b4f866f1 868d34f3 73bfa698
	T              3c128f20 de883288 97624bdb 8dac6989
	keyID          62746c65
	N1             d5cb8454 d177733e ffffb2ec 712baeab
	N2             a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
	A1             00561237 37bfce
	A2             00a71370 2dcfc1
	Length         0100

	(LTK)
	M0             0162746c 65d5cb84 54d17773 3effffb2
	M1             ec712bae aba6e8e7 cc25a75f 6e216583
	M2             f7ff3dc4 cf005612 3737bfce 00a71370
	M3             2dcfc101 00
	AES_CMAC       69867911 69d7cd23 980522b5 94750a38

	(MacKey)
	M0             0062746c 65d5cb84 54d17773 3effffb2
	M1             ec712bae aba6e8e7 cc25a75f 6e216583
	M2             f7ff3dc4 cf005612 3737bfce 00a71370
	M3             2dcfc101 00
	AES_CMAC       2965f176 a1084a02 fd3f6a20 ce636e20
*/
void Bt_SMP_f5_Test()
{
	unsigned char w[32] = { 0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b,
							0x99, 0x79, 0x6b, 0x13, 0xb4, 0xf8, 0x66, 0xf1, 0x86, 0x8d, 0x34, 0xf3, 0x73, 0xbf, 0xa6, 0x98 };
	unsigned char n1[16] = { 0xd5, 0xcb, 0x84, 0x54,0xd1, 0x77, 0x73, 0x3e, 0xff, 0xff, 0xb2, 0xec, 0x71, 0x2b, 0xae, 0xab };
	unsigned char n2[16] = { 0xa6, 0xe8, 0xe7, 0xcc, 0x25, 0xa7, 0x5f, 0x6e, 0x21, 0x65, 0x83, 0xf7, 0xff, 0x3d, 0xc4, 0xcf };
	unsigned char a1[7] = { 0x00, 0x56, 0x12, 0x37, 0x37, 0xbf, 0xce };
	unsigned char a2[7] = { 0x00, 0xa7, 0x13, 0x70, 0x2d, 0xcf, 0xc1 };

	unsigned char Ltk[16] = { 0 };
	unsigned char MacKey[16] = { 0 };

	printf("--------------------------------------------------\n");
	printf("w              "); printBytes(w, sizeof(w)); printf("\n");
	printf("n1             "); printBytes(n1, sizeof(n1)); printf("\n");
	printf("n2             "); printBytes(n2, sizeof(n2)); printf("\n");
	printf("a1             "); printBytes(a1, sizeof(a1)); printf("\n");
	printf("a2             "); printBytes(a2, sizeof(a2)); printf("\n");
	Bt_SMP_f5(w, n1, n2, a1, a2, MacKey, Ltk);
	printf("\nLtk            "); print128(Ltk); printf("\n");
	printf("MacKey         "); print128(MacKey); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	N1             d5cb8454 d177733e ffffb2ec 712baeab
	N2             a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
	MacKey         2965f176 a1084a02 fd3f6a20 ce636e20
	R              12a3343b b453bb54 08da42d2 0c2d0fc8
	IOcap          010102
	A1             00561237 37bfce
	A2             00a71370 2dcfc1

	M0             d5cb8454 d177733e ffffb2ec 712baeab
	M1             a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
	M2             12a3343b b453bb54 08da42d2 0c2d0fc8
	M3             01010200 56123737 bfce00a7 13702dcf
	M4             c1
	AES_CMAC       e3c47398 9cd0e8c5 d26c0b09 da958f61
*/
void Bt_SMP_f6_Test()
{
	unsigned char w[16] = { 0x29, 0x65, 0xf1, 0x76, 0xa1, 0x08, 0x4a, 0x02, 0xfd, 0x3f, 0x6a, 0x20, 0xce, 0x63, 0x6e, 0x20 };	// MacKey from f5
	unsigned char n1[16] = { 0xd5, 0xcb, 0x84, 0x54, 0xd1, 0x77, 0x73, 0x3e, 0xff, 0xff, 0xb2, 0xec, 0x71, 0x2b, 0xae, 0xab };
	unsigned char n2[16] = { 0xa6, 0xe8, 0xe7, 0xcc, 0x25, 0xa7, 0x5f, 0x6e, 0x21, 0x65, 0x83, 0xf7, 0xff, 0x3d, 0xc4, 0xcf };
	unsigned char r[16] = { 0x12, 0xa3, 0x34, 0x3b, 0xb4, 0x53, 0xbb, 0x54, 0x08, 0xda, 0x42, 0xd2, 0x0c, 0x2d, 0x0f, 0xc8 };
	unsigned char io_cap[3] = { 0x01, 0x01, 0x02 };
	unsigned char a1[16] = { 0x00, 0x56, 0x12, 0x37, 0x37, 0xbf, 0xce };
	unsigned char a2[16] = { 0x00, 0xa7, 0x13, 0x70, 0x2d, 0xcf, 0xc1 };

	unsigned char res[16] = { 0 };

	printf("--------------------------------------------------\n");
	printf("w              "); printBytes(w, sizeof(w)); printf("\n");
	printf("n1             "); printBytes(n1, sizeof(n1)); printf("\n");
	printf("n2             "); printBytes(n2, sizeof(n2)); printf("\n");
	printf("r              "); printBytes(r, sizeof(r)); printf("\n");
	printf("io_cap         "); printBytes(io_cap, sizeof(io_cap)); printf("\n");
	printf("a1             "); printBytes(a1, sizeof(a1)); printf("\n");
	printf("a2             "); printBytes(a2, sizeof(a2)); printf("\n");
	Bt_SMP_f6(w, n1, n2, r, io_cap, a1, a2, res);
	printf("\nBt_SMP_f6      "); print128(res); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	U              20b003d2 f297be2c 5e2c83a7 e9f9a5b9
				   eff49111 acf4fddb cc030148 0e359de6
	V              55188b3d 32f6bb9a 900afcfb eed4e72a
				   59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
	X              d5cb8454 d177733e ffffb2ec 712baeab
	Y              a6e8e7cc 25a75f6e 216583f7 ff3dc4cf

	M0             20b003d2 f297be2c 5e2c83a7 e9f9a5b9
	M1             eff49111 acf4fddb cc030148 0e359de6
	M2             55188b3d 32f6bb9a 900afcfb eed4e72a
	M3             59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd
	M4             a6e8e7cc 25a75f6e 216583f7 ff3dc4cf
	AES_CMAC       1536d18d e3d20df9 9b7044c1 2f9ed5ba
	g2             2f9ed5ba
*/
void Bt_SMP_g2_Test()
{
	unsigned char u[32] = { 0x20, 0xb0, 0x03, 0xd2, 0xf2, 0x97, 0xbe, 0x2c, 0x5e, 0x2c, 0x83, 0xa7, 0xe9, 0xf9, 0xa5, 0xb9, 
							0xef, 0xf4, 0x91, 0x11, 0xac, 0xf4, 0xfd, 0xdb, 0xcc, 0x03, 0x01, 0x48, 0x0e, 0x35, 0x9d, 0xe6 };
	unsigned char v[32] = { 0x55, 0x18, 0x8b, 0x3d, 0x32, 0xf6, 0xbb, 0x9a, 0x90, 0x0a, 0xfc, 0xfb, 0xee, 0xd4, 0xe7, 0x2a, 
							0x59, 0xcb, 0x9a, 0xc2, 0xf1, 0x9d, 0x7c, 0xfb, 0x6b, 0x4f, 0xdd, 0x49, 0xf4, 0x7f, 0xc5, 0xfd };
	unsigned char x[16] = { 0xd5, 0xcb, 0x84, 0x54, 0xd1, 0x77, 0x73, 0x3e, 0xff, 0xff, 0xb2, 0xec, 0x71, 0x2b, 0xae, 0xab };
	unsigned char y[16] = { 0xa6, 0xe8, 0xe7, 0xcc, 0x25, 0xa7, 0x5f, 0x6e, 0x21, 0x65, 0x83, 0xf7, 0xff, 0x3d, 0xc4, 0xcf };

	unsigned char g2Value[4] = { 0 };

	printf("--------------------------------------------------\n");
	printf("u              "); printBytes(u, sizeof(u)); printf("\n");
	printf("v              "); printBytes(v, sizeof(v)); printf("\n");
	printf("x              "); printBytes(x, sizeof(x)); printf("\n");
	printf("y              "); printBytes(y, sizeof(y)); printf("\n");
	Bt_SMP_g2(u, v, x, y, g2Value);
	printf("\nBt_SMP_g2      "); print32(g2Value); printf("\n");
	printf("--------------------------------------------------\n");
}

/**
	Key            ec0234a3 57c8ad05 341010a6 0a397d9b
	keyID          6c656272
	M              6c656272
	AES_CMAC       2d9ae102 e76dc91c e8d3a9e2 80b16399
*/
void Bt_SMP_h6_Test()
{
	unsigned char w[16] = { 0xec, 0x02, 0x34, 0xa3, 0x57, 0xc8, 0xad, 0x05, 0x34, 0x10, 0x10, 0xa6, 0x0a, 0x39, 0x7d, 0x9b };
	unsigned char keyID[4] = { 0x6c, 0x65, 0x62, 0x72 };
	unsigned char res[16] = { 0 };

	printf("--------------------------------------------------\n");
	printf("w              "); printBytes(w, sizeof(w)); printf("\n");
	printf("keyID          "); printBytes(keyID, sizeof(keyID)); printf("\n");
	Bt_SMP_h6(w, keyID, res);
	printf("\nBt_SMP_h6      "); print128(res); printf("\n");
	printf("--------------------------------------------------\n");
}
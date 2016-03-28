#ifndef __BLE_SMP_CRYPTO_H
#define __BLE_SMP_CRYPTO_H

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
	);

void Bt_SMP_ah(
	unsigned char k[16],
	unsigned char r[3],
	unsigned char hash[3]
	);

void Bt_SMP_f4(
	unsigned char u[32],
	unsigned char v[32],
	unsigned char x[16],
	unsigned char z,
	unsigned char res[16]
	);

void Bt_SMP_f5(
	unsigned char w[32],
	unsigned char n1[16],
	unsigned char n2[16],
	unsigned char a1[7],
	unsigned char a2[7],
	unsigned char mackey[16],
	unsigned char ltk[16]
	);

void Bt_SMP_f6(
	unsigned char w[16],
	unsigned char n1[16],
	unsigned char n2[16],
	unsigned char r[16],
	unsigned char io_cap[3],
	unsigned char a1[7],
	unsigned char a2[7],
	unsigned char res[16]
	);

void Bt_SMP_g2(
	unsigned char u[32],
	unsigned char v[32],
	unsigned char x[16],
	unsigned char y[16],
	unsigned char val[4]
	);

// Function tester
void Bt_SMP_c1_Test();
void Bt_SMP_s1_Test();
void Bt_SMP_ah_Test();
void Bt_SMP_f4_Test();
void Bt_SMP_f5_Test();
void Bt_SMP_f6_Test();
void Bt_SMP_g2_Test();
void Bt_SMP_h6_Test();
#endif
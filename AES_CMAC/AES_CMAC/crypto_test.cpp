#include "stdafx.h"
#include "aes_encrypt.h"
#include "aes_cmac.h"
#include "aes_encrypt.h"
#include "ble_smp_crypto.h"

void print_help(void)
{
	printf("/*********************************************/\n");
	printf("LE SMP crypto functions tester:\n");
	printf("	BLECryptoFuncs.exe  [test number]\n");
	printf("	[test number]:\n");
	printf("			1			AES_128\n");
	printf("			2			SMP_ah\n");
	printf("			3			SMP_c1\n");
	printf("			4			SMP_s1\n");
	printf("			5			AES_CMAC\n");
	printf("			6			SMP_f4\n");
	printf("			7			SMP_f5\n");
	printf("			8			SMP_f6\n");
	printf("			9			SMP_g2\n");
	printf("			a			SMP_h6\n");
	printf("			h			Help\n");
	printf("			q			Quit\n");
	printf("/*********************************************/\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	printf("This is BLE smp test app");
	print_help();

	int op;
	do{
		printf("Enter the test number:");
		op = getchar();
		if (op == 'q') break;
		switch (op)
		{
		case '1':
			AES_128_Test();
			break;
		case '2':
			Bt_SMP_ah_Test();
			break;
		case '3':
			Bt_SMP_c1_Test();
			break;
		case '4':
			Bt_SMP_s1_Test();
			break;
		case '5':
			AES_CMAC_Test();
			break;
		case '6':
			Bt_SMP_f4_Test();
			break;
		case '7':
			Bt_SMP_f5_Test();
			break;
		case '8':
			Bt_SMP_f6_Test();
			break;
		case '9':
			Bt_SMP_g2_Test();
			break;
		case 'a':
			Bt_SMP_h6_Test();
			break;
		case 'h':
			print_help();
		default:
			print_help();
			break;
		}
		getchar();
	} while (true);
	return 1;
}
#include "SSL.h"
#include "myopenssl.h"
#include "http/http.h"

/* 
 * Main execution command, command line arguments must specify
 * one of these commands.
 */
CmdTable gCmdTable; 

static void pUsage()
{
	printf("Run stdio server:\n");
	printf("./runSSL r_server -port [PORT] -cert [CERT]\n");
	printf("Run http server:\n");
	printf("./runSSL r_server -port [PORT] -cert [CERT] -http [VER]\n");
	
	printf("Run stdio client:\n");
	printf("./runSSL r_client -ip [ip] -port [PORT] -cipher [cid]\n");
	printf("Run http client:\n");
	printf("./runSSL r_client -ip [ip] -port [PORT] -http [VER]"
		" -proc [PROC_NUM] -cipher [cid]\n");
	printf("cipher id:\n");
	printf("1: TLS_RSA_WITH_RC4_128_SHA\n");
	printf("2: TLS_RSA_WITH_3DES_EDE_CBC_SHA\n");
	printf("3: TLS_RSA_WITH_AES_256_CBC_SHA\n");
	printf("4: TLS_RSA_WITH_CAMELLIA_128_CBC_SHA\n");
	printf("Run above cmds with OpenSSL: Add -openssl\n");
}
/*
 * Parse command line arguments. On success, zero will be
 * returned, else -1 will be returned;
 */
static int parseCmd(int argc, char **argv)
{
	int cc = -1;
	
	memset(&gCmdTable, 0, sizeof(CmdTable));

	for (argc--, argv++; argc>0; argc--, argv++) {
		if (strcmp(*argv, "r_server") == 0) {
			gCmdTable.execCb = &sslSvrEnt;
		} else if (strcmp(*argv, "r_client") == 0) {
			gCmdTable.execCb = &s31ClnEnt;
		} else if (strcmp(*argv, "g_cert") == 0) {
		} else if (strcmp(*argv, "t_cipher") == 0) {
		} else if (strcmp(*argv, "p_usage") == 0) {
			pUsage();
			goto bail_w_usage;
		} else if (strncmp(*argv, "rsa", 3) == 0) {
			gCmdTable.crypto = 1;
			if (strcmp((*argv)+3, "_enc") == 0) {
			//	gCmdTable.execCb = &rsaEncryptCb;
			
			} else if (strcmp((*argv)+3, "_dec") == 0) {
			//	gCmdTable.execCb = &rsaDecryptCb;
			} else {
				printf("rsa needs encryption/decryption command\n");
				goto bail_w_usage;
			}
			gCmdTable.cryptoFiles = 
					(void *) calloc(1, sizeof(RSAFiles));
		} else if (strcmp(*argv, "-in") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				printf("No specified in file\n");
				goto bail_w_usage;
			}
//			switch (gCmdTable.crypto) {
//				case 1: //rsa
//					if (gCmdTable.execCb == rsaDecryptCb) {
//						((RSAFiles *)gCmdTable.cryptoFiles)->cipher_f =
//							fopen(*argv, "r+");
//					} else {
//						((RSAFiles *)gCmdTable.cryptoFiles)->plain_f =
//							fopen(*argv, "r+");
//					}
//					break;
//			}
		} else if (strcmp(*argv, "-pbKey") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				printf("No specified public key file\n");
				goto bail_w_usage;
			}
			((RSAFiles *)gCmdTable.cryptoFiles)->pbKey_f =
					fopen(*argv, "r");
		} else if (strcmp(*argv, "-pvKey") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				printf("No specified private key file\n");
				goto bail_w_usage;
			}
			((RSAFiles *)gCmdTable.cryptoFiles)->pvKey_f =
					fopen(*argv, "r");
		} else if (strcmp(*argv, "-modulus") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				printf("No specified modulus key file\n");
				goto bail_w_usage;
			}
			((RSAFiles *)gCmdTable.cryptoFiles)->mod_f =
					fopen(*argv, "r");
		} else if(strcmp(*argv, "-out") == 0) {
			argv++;
			argc--;
			if (argc == 0) {
				printf("No specified out file\n");
				goto bail_w_usage;
			}
/*			switch (gCmdTable.crypto) {
				case 1: //rsa
					if (gCmdTable.execCb == rsaDecryptCb) {
						((RSAFiles *)gCmdTable.cryptoFiles)->plain_f =
							fopen(*argv, "r+");
					} else {
						((RSAFiles *)gCmdTable.cryptoFiles)->cipher_f =
							fopen(*argv, "r+");
					}
					break;
			}*/
		} else if (strcmp(*argv, "-ip") == 0) {
			argv++;
			argc--;
			char *ptr = *argv;
			int dotNum = 0;
			for (; *ptr != '\0' && *ptr != ' '; ptr++) {
				int part = atoi(ptr);
				if ((part == 0 && *ptr != '0') || part > 255) {
					printf("Wrong IP address format\n");
					goto bail_w_usage;
				}
				while (*ptr != '.' && *ptr != '\0')
					ptr++;
				if (*ptr == '.')
					dotNum++;
				else if (*ptr == '\0')
					break;
			}
			if (dotNum != 3) {
				printf("Wrong IP address format\n");
				goto bail_w_usage;
			} else {
				gCmdTable.ipAddr = strdup(*argv);
			}
		} else if(strcmp(*argv, "-port") == 0) {
			argv++;
			argc--;
			gCmdTable.port = atoi(*argv);
			if (gCmdTable.port < 1024 || gCmdTable.port > 65535) {
				printf("Usage port between 1024 and 65535\n");
			}
		} else if (strcmp(*argv, "-cert") == 0) {
			argv++;
			argc--;
			gCmdTable.certPath = strdup(*argv);
		} else if (strcmp(*argv, "ssl31") == 0 || 
				   strcmp(*argv, "tls10") == 0) 
		{
			; //Default entry is tls1.0 or ssl3.1, no effect
		} else if (strcmp(*argv, "ssl30") == 0) {
			;
		} else if (strcmp(*argv, "-http") == 0) {
			argv++;
			argc--;
			gCmdTable.httpVer = atoi(*argv);

			if (gCmdTable.execCb == &sslSvrEnt)
				gCmdTable.execCb = &sslHttpSvrEnt;
			else if (gCmdTable.execCb == &s31ClnEnt) {
				gCmdTable.execCb = &sslHttpClnEnt;
			} else {
				printf("Please specify r_server or r_client\n");
				goto bail_w_usage;
			}

			if (gCmdTable.httpVer != 10 && gCmdTable.httpVer != 11) {
				goto bail_w_usage;
			}

		} else if (strcmp(*argv, "-proc") == 0) {
			if (gCmdTable.execCb != &sslHttpClnEnt) {
				goto bail_w_usage;
			}
			argv++;
			argc--;
			gCmdTable.clnProcNum = atoi(*argv);
		} else if (strcmp(*argv, "-cipher") == 0) {
			if (gCmdTable.execCb != &sslHttpClnEnt &&
				gCmdTable.execCb != &s31ClnEnt) 
			{
				goto bail_w_usage;
			}
			
			short ciphers[] = {4, 0x05, 0x0A, 0x35, 0x41};
			
			argv++;
			argc--;
			clnCipherList[1] = ciphers[atoi(*argv)];
		} else if (strcmp(*argv, "-openssl") == 0) {
			gCmdTable.modeOpenSSL = 1;
		} else if (strcmp(*argv, "-help") == 0) {
			pUsage();
		} else {
			printf("Invalid Command:%s\n", *argv);
			goto bail_w_usage;
		}
	}
	if (gCmdTable.execCb == NULL) {
		printf("Main execution command required\n");
		goto bail_w_usage;
	}

	cc = 1;	// success
	goto bail_wo_usage;

bail_w_usage:
	pUsage();
bail_wo_usage:
	return cc;
}

static void freeCmdTable()
{
	if (gCmdTable.ipAddr)
		free(gCmdTable.ipAddr);
	if (gCmdTable.certPath)
		free(gCmdTable.certPath);
}

int main(int argc, char *argv[])
{
	int exec;

	memset(&gCmdTable, 0, sizeof(CmdTable));
	
	if (parseCmd(argc, argv) < 0) {
		printf("Parsing command line arguments failed\n");
		exit(0);
	}
	
	gCmdTable.execCb((void *)&gCmdTable);
	freeCmdTable();
	return 0;
}

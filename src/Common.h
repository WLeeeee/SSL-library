#ifndef _COMMON_H_
#define _COMMON_H_

#define MSG_LIMIT 32768

/* SSL server and client number */
#define SSL_SERVER						0x11111111
#define SSL_CLIENT						0x22222222

typedef enum {
	false = 0, true = !false
} bool;

typedef unsigned char			u1;
typedef unsigned short			u2;
typedef unsigned int			u4;
typedef unsigned long long int	u8;
typedef signed char				s1;
typedef signed short			s2;
typedef signed int				s4;
typedef signed long long int	s8;

typedef void (*ExecEntry)(void *);

typedef struct CmdTable {
	char *ipAddr;
	int port;
	void *cryptoFiles;
	int crypto;
	ExecEntry execCb;
	char *certPath;
	int httpVer;
	int clnProcNum;
	bool modeOpenSSL;
} CmdTable;

#endif

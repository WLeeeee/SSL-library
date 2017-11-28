#ifndef _HTTP_H_
#define _HTTP_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#include "SSL.h"

/* SERVER SIDE MACRO */
#define SERVER_MAX_LISTEN	65536

/* CLIENT SIDE MACRO */
#define BILLION 1000000000L

void sslHttpSvrEnt(void *pCmdTable);
void sslHttpClnEnt(void *pCmdTable);

#endif

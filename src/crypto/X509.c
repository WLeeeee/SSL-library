#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "X509.h"

typedef struct DERCstr {
	u1 *pData;
	int class;
	int tag;
	int curLen;
	int dataLen;
	struct DERCstr *prev, *next;
} DERCstr;

typedef struct DERPri {
	u1 *pData;
	int dataLen;
	int tag;
} DERPri;

static int parseIDOct(u1 **ptr, DERCstr **cstr, DERPri *pri)
{
	int idOct = (int)(**ptr);
	int tag = idOct & 0x1F;

	(*ptr)++;
	/* constructed */
	if (idOct & 0x20) {
		(*cstr) = (DERCstr *) malloc(sizeof(DERCstr));
		(*cstr)->class = (idOct & 0xC0) >> 6;
		(*cstr)->tag = tag;
		(*cstr)->next = NULL;
		(*cstr)->prev = NULL;
		return 1;
	} else {
		pri->tag = tag;
		return 0;
	}
}
/* 
 * This function computes how many subsequent octets in this
 * segment and return the computed number. Then the buffer
 * pointer will be moved from length octets to the beginning 
 * of the contents octets.
 */
static int parseLenOct(u1 **ptr)
{
	int iniOct = (int)(**ptr);
	int dataLen = -1;

	(*ptr)++;
	if ((iniOct & 0x80) == 0) {
		/* definite short form */
		dataLen = iniOct;
	} else {
		iniOct &= 0x7F;
		if (iniOct != 0) {
			/* 
			 * definite long form
			 * Here we assume the maximum length of octets will not
			 * exceed 4-bytes signed integer, else octet length parsing
			 * error will occur.
			 */
			if (iniOct > MAX_LENGTH_OCTETS) {
				printf("Invalid length octets:Max=4, Cur=%d\n", 
					   iniOct);
				goto bail;
			}
			int i;
			for (i=iniOct-1, dataLen=0; i>=0; i--) {
				dataLen |= (**ptr) << (i << 3);
				(*ptr)++;
			}
		} else {
			/* indefinite form */
			dataLen = 0;
		}
	}
bail:
	return dataLen;
}

void pushCstr(DERCstr **top, DERCstr *new)
{
	if (*top == NULL) {
		*top = new;
	} else {
		(*top)->next = new;
		new->prev = (*top);
		(*top) = (*top)->next;
	}
}

void popCstr(DERCstr **top)
{
	if ((*top)->prev != NULL) {	
		(*top) = (*top)->prev;
		free((*top)->next);
	} else { // *top is the last element
		free(*top);
		(*top) = NULL;
	}
}

static TBSCert *parseTBSCert(u1 **rawData)
{
	DERPri priData[MAX_ELEMENT_NUM];
	int priIdx = 0;
	DERCstr *top = NULL;
	u1 *pData, *ptr;
	TBSCert *pTBSCert;

	pTBSCert = (TBSCert *) malloc(sizeof(TBSCert));
	memset(pTBSCert, 0, sizeof(TBSCert));

	/*
	 * First must be constructed data of TBSCert
	 */
	pData = ptr = (*rawData);
	if (parseIDOct(&ptr, &top, NULL) != 1) {
		printf("Invalid TBS certificate\n");
		goto bail;
	}
	top->dataLen = top->curLen = parseLenOct(&ptr);
	top->pData = ptr;

	while (top != NULL) {
		DERCstr *newCstr = NULL;

		pData = ptr;
		int flag = parseIDOct(&ptr, &newCstr, &priData[priIdx]);

		if (flag == 1) {	/* constructed encoding */
			if((newCstr->dataLen = newCstr->curLen = 
						parseLenOct(&ptr)) < 0)
			{
				goto bail;
			}
			/* new structure length */
			top->curLen -= (ptr - pData);
			newCstr->pData = ptr;
			pushCstr(&top, newCstr);
		} else {			/* primitive encoding*/
			if((priData[priIdx].dataLen = parseLenOct(&ptr)) < 0)
				goto bail;
			priData[priIdx].pData = ptr;
			ptr += priData[priIdx].dataLen;
			top->curLen -= (ptr - pData);
		}
		/* pop constructed data from stack */
		if (top->curLen == 0) {
			do {
				int topLen = top->dataLen;
				popCstr(&top);
				if (top == NULL)
					break;
				top->curLen -= topLen;
			} while (top->curLen == 0);
		}
	}

	/*
	 * Begin filling data into TBS certificate
	 */

	*rawData = ptr;
bail:
	return pTBSCert;

}

static void freeTBSCert(TBSCert *pTBSCert)
{
	free(pTBSCert);
}

/* 
 * Function used to parse the certificate with x509
 * struct. 
 */
CertX509 *parseCertX509(u1 *x509)
{
	CertX509 *pCert;
	DERCstr *certCstr = NULL;
	u1 *ptr = x509;

	pCert = (CertX509 *) malloc(sizeof(CertX509));
	memset(pCert, 0, sizeof(CertX509));

	/* parse x509 certificate header */
	if (parseIDOct(&ptr, &certCstr, NULL) != 1) {
		printf("Invalid x509 certificate\n");
		goto bail;
	}
	certCstr->dataLen = parseLenOct(&ptr);
	
	/* 1st element of x509 sequence */
	if ((pCert->tbsCert = parseTBSCert(&ptr)) == NULL)
		goto bail;

	/* 2nd element of x509 sequence */

	/* 3rd element of x509 sequence */
	
	return pCert;
bail:
	printf("Parsing x509 failed\n");
	if (pCert->tbsCert) {
		freeTBSCert(pCert->tbsCert);
	}
	return NULL;
}

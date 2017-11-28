#ifndef _X509_H_
#define _X509_H_
#include "../Common.h"
#include "ASN1Def.h"

#define MAX_LENGTH_OCTETS 4
#define MAX_ELEMENT_NUM 128

typedef struct IssuerInfo {
	/* Attributes below MUST be implemented. */
	char *country;
	char *org;
	char *orgUnit;
	char *distNameQualifier;
	char *state;
	char *commonName;
	int serialNumLen;
	u1 *serialNum;
	/* Attributes below SHOULD be implemented */
	char *locality;
	char *title;
	char *surName;
	char *givenName;
	char *pseudonym;
	char *genQualifier;
} IssuerInfo;

typedef struct AlgorithmID {
	ASN1ObjectID *algorithm;
	/* algorithm's parameters */
	void *parameters;
} AlgorithmID;

typedef struct SubjectPubKeyInfo {
	AlgorithmID *algorithm;
	int keyLen;
	char *publicKey;
} SubjectPubKeyInfo;

typedef struct TBSCert {
	/* Total length of this sequence, counted in bytes */
	int seqLen;
	/* 
	 * the version of the encoded certificate
	 * v1 = 0, v2 = 1, v3 = 2
	 */
	ASN1Integer version;
	/* the size of serial number may up to 20 bytes*/
	ASN1Integer serialNum;
	AlgorithmID *signature;
	/* issuer's information */
	IssuerInfo *issuer;
	/* validity: 2 attributes for certificate time */
	char *notBefore;
	char *notAfter;
	/* subject information */
	IssuerInfo *subject;
	/* subject public key information */
	SubjectPubKeyInfo *pkeyInfo;
	/* If present, version must be v2 or v3 */
	char *issuerUID;
	/* If present, version must be v2 or v3 */
	char *subjectUID;
	/* 
	 * If present, version must be v3.
	 *
	 * Every extension will be stored as a string, then all 
	 * extensions will be stored in this string table. This 
	 * is because there are too many extensions, and only 
	 * the information which is important will be stored in
	 * temporary variable when we are parsing the x509 struct.
	 */
} TBSCert;

typedef struct CertX509 {
	/* TBSCertificate */
	TBSCert *tbsCert;
	/* AlgorithmIdentifier */
	AlgorithmID *sigAlgorithm;
	/* Signature value */
	ASN1BitString *sigValue;
} CertX509;

CertX509 *parseCertX509(u1 *x509);

#endif

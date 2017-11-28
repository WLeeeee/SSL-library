#ifndef _ASN1_DEF_H
#define _ASN1_DEF_H
/* 
 * Structures of all basic type of ASN1 are defined 
 * in this file. Compound type such as SEQUENCE, SET
 * will not be defined. That is, data with these types 
 * will be stored in base ASN1 type for further processing.
 */


/* Type define universal types in ASN1 */
#define ASN1Integer				ASN1String
#define ASN1Enumreated			ASN1String
#define ASN1BitString			ASN1String
#define ASN1OctetString			ASN1String
#define ASN1PrintableString		ASN1String
#define ASN1T61String			ASN1String
#define ASN1IA5String			ASN1String
#define ASN1UTCTime				ASN1String
#define ASN1GeneralizedTime		ASN1String
#define ASN1Time				ASN1String
#define ASN1GeneralSting		ASN1String
#define ASN1UniversalString		ASN1String
#define ASN1BmpString			ASN1String
#define ASN1VisibleString		ASN1String
#define ASN1UTF8String			ASN1String
#define ASN1ObjectID			ASN1String
#define ASN1Boolean				int
#define ASN1NULL				int

#define TagClass_Universal		0x00
#define TagClass_Application	0x01
#define TagClass_CtxSpecific	0x02
#define TagClass_Private		0x03

/* Define the tag number of universal types */
#define Tag_ASN1EOC				0x00
#define Tag_ASN1Boolean			0x01
#define Tag_ASN1Integer			0x02
#define Tag_ASN1BitString		0x03
#define Tag_ASN1OctetString		0x04
#define Tag_ASN1NULL			0x05
#define Tag_ASN1ObjectID		0x06
#define Tag_ASN1Enumerated		0x0A
#define Tag_ASN1UTF8String		0x0C
#define Tag_ASN1Sequence		0x10
#define Tag_ASN1Set				0x11
#define	Tag_ASN1PrintableString	0x13
#define Tag_ASN1T61String		0x14
#define Tag_ASN1IA5String		0x16
#define Tag_ASN1UTCTime			0x17
#define Tag_ASN1GeneralizedTime	0x18
#define Tag_ASN1GeneralString	0x1B
#define Tag_ASN1UniversalString	0x1C
#define Tag_ASN1BmpString		0x1E


/* This is the base type can be used to hold everything */
typedef struct ASN1String {
	int type;
	int length;
	char *data;
} ASN1String;

/* 
 * If the number of contents in the encoding data is not 
 * known until runtime, data will be stored in this table
 * for further processing.
 */
typedef struct ASN1StringTable {
	int tableSize;
	ASN1String **table;
} ASN1StringTable;

#endif

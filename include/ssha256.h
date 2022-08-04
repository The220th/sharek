/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SSHA256_H
#define SSHA256_H

/**
 * The code was taken from here:
 * https://github.com/B-Con/crypto-algorithms
 * - and changed
*/

/*************************** HEADER FILES ***************************/
#include <memory.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

/**
 * len of param hash must be SHA256_BLOCK_SIZE
*/
void calc_256hash(const char *bytes, size_t bytes_len, unsigned char *hash);

/**
 * len of param hash must be SHA256_BLOCK_SIZE
*/
void calc_file_hash(const char *fileName, unsigned char *hash);

#endif   // SSHA256_H

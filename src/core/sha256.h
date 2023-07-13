#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest
#define SHA256_SIZE_BYTES    (32)

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD_SHA;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE ctxdata[64];  // current 512-bit chunk of message data, just like a buffer
	WORD_SHA datalen;   // sign the data length of current chunk
	unsigned long long bitlen;  // the bit length of the total message
	WORD_SHA state[8];  // store the middle state of hash abstract
} SHA256_ctx;

/*********************** FUNCTION DECLARATIONS **********************/
void SHA256_INIT(SHA256_ctx *ctx);
void SHA256_UPDATE(SHA256_ctx *ctx, const BYTE data[], size_t len);
void SHA256_FINAL(SHA256_ctx *ctx, BYTE hash[]);

void sha256(const void *data, size_t len, BYTE *hash);
void hex( const BYTE *sSrc,  char *sDest, int nSrcLen ) ;

#endif   // SHA256_H

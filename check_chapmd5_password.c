#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*	$OpenBSD: md5.h,v 1.3 2014/11/16 17:39:09 tedu Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#define	MD5_BLOCK_LENGTH		64
#define	MD5_DIGEST_LENGTH		16

typedef struct MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t count;			/* number of bits, mod 2^64 */
	u_int8_t buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} MD5_CTX;

__BEGIN_DECLS
static void	 MD5Init(MD5_CTX *);
static void	 MD5Update(MD5_CTX *, const void *, size_t)
		__attribute__((__bounded__(__string__,2,3)));
static void	 MD5Final(u_int8_t [MD5_DIGEST_LENGTH], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_LENGTH)));
static void	 MD5Transform(u_int32_t [4], const u_int8_t [MD5_BLOCK_LENGTH])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_BLOCK_LENGTH)));
__END_DECLS


/*	$OpenBSD: md5.c,v 1.4 2014/12/28 10:04:35 tedu Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.	This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */



#define PUT_64BIT_LE(cp, value) do {					\
	(cp)[7] = (value) >> 56;					\
	(cp)[6] = (value) >> 48;					\
	(cp)[5] = (value) >> 40;					\
	(cp)[4] = (value) >> 32;					\
	(cp)[3] = (value) >> 24;					\
	(cp)[2] = (value) >> 16;					\
	(cp)[1] = (value) >> 8;						\
	(cp)[0] = (value); } while (0)

#define PUT_32BIT_LE(cp, value) do {					\
	(cp)[3] = (value) >> 24;					\
	(cp)[2] = (value) >> 16;					\
	(cp)[1] = (value) >> 8;						\
	(cp)[0] = (value); } while (0)

static u_int8_t PADDING[MD5_BLOCK_LENGTH] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void
MD5Init(MD5_CTX *ctx)
{
	ctx->count = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void
MD5Update(MD5_CTX *ctx, const void *inputptr, size_t len)
{
	const uint8_t *input = inputptr;
	size_t have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (size_t)((ctx->count >> 3) & (MD5_BLOCK_LENGTH - 1));
	need = MD5_BLOCK_LENGTH - have;

	/* Update bitcount */
	ctx->count += (u_int64_t)len << 3;

	if (len >= need) {
		if (have != 0) {
			memcpy(ctx->buffer + have, input, need);
			MD5Transform(ctx->state, ctx->buffer);
			input += need;
			len -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		while (len >= MD5_BLOCK_LENGTH) {
			MD5Transform(ctx->state, input);
			input += MD5_BLOCK_LENGTH;
			len -= MD5_BLOCK_LENGTH;
		}
	}

	/* Handle any remaining bytes of data. */
	if (len != 0)
		memcpy(ctx->buffer + have, input, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void
MD5Final(unsigned char digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx)
{
	u_int8_t count[8];
	size_t padlen;
	int i;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64BIT_LE(count, ctx->count);

	/* Pad out to 56 mod 64. */
	padlen = MD5_BLOCK_LENGTH -
	    ((ctx->count >> 3) & (MD5_BLOCK_LENGTH - 1));
	if (padlen < 1 + 8)
		padlen += MD5_BLOCK_LENGTH;
	MD5Update(ctx, PADDING, padlen - 8);		/* padlen - 8 <= 64 */
	MD5Update(ctx, count, 8);

	for (i = 0; i < 4; i++)
		PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
	bzero(ctx, sizeof(*ctx));	/* in case it's sensitive */
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
MD5Transform(u_int32_t state[4], const u_int8_t block[MD5_BLOCK_LENGTH])
{
	u_int32_t a, b, c, d, in[MD5_BLOCK_LENGTH / 4];

#if BYTE_ORDER == LITTLE_ENDIAN
	memcpy(in, block, sizeof(in));
#else
	for (a = 0; a < MD5_BLOCK_LENGTH / 4; a++) {
		in[a] = (u_int32_t)(
		    (u_int32_t)(block[a * 4 + 0]) |
		    (u_int32_t)(block[a * 4 + 1]) <<  8 |
		    (u_int32_t)(block[a * 4 + 2]) << 16 |
		    (u_int32_t)(block[a * 4 + 3]) << 24);
	}
#endif

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD5STEP(F1, a, b, c, d, in[ 0] + 0xd76aa478,  7);
	MD5STEP(F1, d, a, b, c, in[ 1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[ 2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[ 3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[ 4] + 0xf57c0faf,  7);
	MD5STEP(F1, d, a, b, c, in[ 5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[ 6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[ 7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[ 8] + 0x698098d8,  7);
	MD5STEP(F1, d, a, b, c, in[ 9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122,  7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[ 1] + 0xf61e2562,  5);
	MD5STEP(F2, d, a, b, c, in[ 6] + 0xc040b340,  9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[ 0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[ 5] + 0xd62f105d,  5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453,  9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[ 4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[ 9] + 0x21e1cde6,  5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6,  9);
	MD5STEP(F2, c, d, a, b, in[ 3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[ 8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905,  5);
	MD5STEP(F2, d, a, b, c, in[ 2] + 0xfcefa3f8,  9);
	MD5STEP(F2, c, d, a, b, in[ 7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[ 5] + 0xfffa3942,  4);
	MD5STEP(F3, d, a, b, c, in[ 8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[ 1] + 0xa4beea44,  4);
	MD5STEP(F3, d, a, b, c, in[ 4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[ 7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6,  4);
	MD5STEP(F3, d, a, b, c, in[ 0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[ 3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[ 6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[ 9] + 0xd9d4d039,  4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2 ] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[ 0] + 0xf4292244,  6);
	MD5STEP(F4, d, a, b, c, in[7 ] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5 ] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3,  6);
	MD5STEP(F4, d, a, b, c, in[3 ] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1 ] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8 ] + 0x6fa87e4f,  6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6 ] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4 ] + 0xf7537e82,  6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2 ] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9 ] + 0xeb86d391, 21);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}


/*
 * Copyright (c) 2017 Igor Popov <ipopovi@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(check_chapmd5_password);

#define PPP_CHAP_MD5_MAX_CHALLENGE	64

static int
char2int(char input) {
    if (input >= '0' && input <= '9')
	return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
	return input - 'a' + 10;
    elog(WARNING, "wrong input: char2int([%c])", input);
    return -1;
}
                    
/* 
    This function assumes src to be a zero terminated sanitized string with
    an even number of [0-9a-f] characters, and target to be sufficiently large
*/
static int
hex2bin(const char* src, unsigned char* target) {
    int num_converted = 0;
    while (src[0] && src[1]) {
	*(target++) = (char2int(src[0])<<4) | char2int(src[1]);
        src += 2;
        num_converted++;
    }
    return num_converted;
}

static void
bin2hex(uint8 *b, size_t b_len, char *s)
{
    static const char *hex = "0123456789abcdef";
    int q, w;
                                                
    for (q = 0, w = 0; q < b_len; q++) {
        s[w++] = hex[(b[q] >> 4) & 0x0F];
        s[w++] = hex[b[q] & 0x0F];
    }
    s[w] = '\0';
}

int static
digest_cmp(uint8_t const *a, uint8_t const *b, size_t length)
{
    int result = 0;
    size_t i;
                
    for (i = 0; i < length; i++) {
        result |= a[i] ^ b[i];
    }
        
    return result;          /* 0 is OK, !0 is !OK, just like memcmp */
}

Datum
check_chapmd5_password(PG_FUNCTION_ARGS) {
    bool result = false;
    char *chap_password = NULL, *chap_challenge = NULL, *clear_password = NULL;
    unsigned char arr_chap_challenge[PPP_CHAP_MD5_MAX_CHALLENGE] = { 0 }, arr_chap_password[MD5_DIGEST_LENGTH+1] = { 0 };
    int chap_password_len, chap_challenge_len;
    char md5string[MD5_DIGEST_LENGTH+1] = { 0 };

    /*	Get arguments.  If we declare our function as STRICT, then
	this check is superfluous. */
    if (PG_NARGS() != 3 || PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2)) {
	PG_RETURN_NULL();
    }

    chap_password  = text_to_cstring(PG_GETARG_TEXT_PP(0));
    chap_challenge = text_to_cstring(PG_GETARG_TEXT_PP(1));
    clear_password = text_to_cstring(PG_GETARG_TEXT_PP(2));
    
    chap_password_len  = hex2bin(chap_password, arr_chap_password);
    chap_challenge_len = hex2bin(chap_challenge, arr_chap_challenge);

    elog(DEBUG2, "clear passwd [%s], chap_challenge [%s], chap_challenge_len [%d] [%d], chap_password [%s], chap_password_len [%d] [%d]",
	clear_password,
	chap_challenge, chap_challenge_len, strlen(chap_challenge),
	chap_password, chap_password_len, strlen(chap_password));

    if (chap_password_len == MD5_DIGEST_LENGTH + 1) {
	unsigned char md5hash[MD5_DIGEST_LENGTH] = { 0 };
	MD5_CTX ctx;

	/* Generate hash of ID, secret, challenge */
	MD5Init(&ctx);
	MD5Update(&ctx, arr_chap_password, 1);
	MD5Update(&ctx, clear_password, strlen(clear_password));
	MD5Update(&ctx, arr_chap_challenge, chap_challenge_len);
	MD5Final(md5hash, &ctx);

	bin2hex(md5hash, MD5_DIGEST_LENGTH, md5string);

	/* Test if our hash matches the peer's response */
	if (digest_cmp(md5hash, arr_chap_password+1, MD5_DIGEST_LENGTH) == 0) {
	    /* Access granted */
	    result = true;
	    elog(DEBUG2, "memcmp([%s], [%s], MD5_DIGEST_LENGTH) == 0", md5string, chap_password+1);
	} else {
	    elog(DEBUG2, "memcmp([%s], [%s], MD5_DIGEST_LENGTH) != 0", md5string, chap_password+1);
	}
    } else {
	/* Access denied */
	elog(WARNING, "wrong input: chap_password_len[%d] != MD5_DIGEST_LENGTH + 1", chap_password_len);
    }

    if (chap_password) {
	pfree(chap_password);
    }
    if (chap_challenge) {
	pfree(chap_challenge);
    }
    if (clear_password) {
	pfree(clear_password);
    }

    PG_RETURN_BOOL(result);
}

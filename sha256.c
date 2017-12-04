/*
 * Copyright (c) 2017, Tadeu Bastos
 *
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define nelem(x) (sizeof(x) / sizeof(*x))

#define BLOCKSIZE 64 /* 256 / 8 */
#define BUFSIZE (256 * BLOCKSIZE)

/* SHA-256 constants (FIPS 180-4, Section 4.2.2) */
static const uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* SHA-256 initial hash value (FIPS 180-4, Section 5.3.3) */
static const uint32_t H_0[] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19, 
};

static uint64_t		preprocessing(uint8_t **, uint64_t, uint32_t []);
static void		computation(uint8_t *, uint64_t, uint32_t []);

static inline uint32_t	ROTR(uint32_t, uint32_t);
static inline uint32_t	Ch(uint32_t, uint32_t, uint32_t);
static inline uint32_t	Maj(uint32_t, uint32_t, uint32_t);
static inline uint32_t	Sigma_0(uint32_t);
static inline uint32_t	Sigma_1(uint32_t); 
static inline uint32_t	sigma_0(uint32_t);
static inline uint32_t	sigma_1(uint32_t);

static inline uint64_t	htobe64(uint64_t);
static inline uint32_t	htobe32(uint32_t);

/*
 * main() reads stdin while allocating an adequate buffer. Once the read is
 * complete, it calculates the input's SHA-256 checksum and prints it to stdout.
 */
int
main(void)
{
	uint64_t N = 0, l = 0;
	uint32_t H[8];
	uint8_t *M = NULL;
	size_t k = 0;

	do {
		if (l % BUFSIZE == 0) {
			if ((uint64_t)(l + BUFSIZE) <= l)
				errx(1, "%s: overflow", __func__);
			if ((M = realloc(M, l + BUFSIZE)) == NULL)
				err(1, "%s: realloc()", __func__);
		}
		k = fread(M + l, sizeof(*M), BUFSIZE - l % BUFSIZE, stdin);
		if (k == 0 && ferror(stdin))
			err(1, "%s: fread()", __func__);
		l += k;
	} while (!feof(stdin));
	N = preprocessing(&M, l, H);
	computation(M, N, H);
	printf("%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32
	    "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "%08" PRIx32 "\n",
	    H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
	free(M);

	return (0);
}

/*
 * SHA-256 preprocessing (FIPS 180-4, Sections 5.1.1 and 5.2.1)
 */
uint64_t
preprocessing(uint8_t **M, uint64_t l, uint32_t H[])
{
	unsigned int i;
	uint64_t rl, *a;

	rl = 8 * (BLOCKSIZE - sizeof(uint64_t));
	rl -= 8 * l + 1;
	rl %= 8 * BLOCKSIZE;
	rl += 8 * (l + sizeof(uint64_t)) + 1;
	rl /= 8;
	if ((uint64_t)rl <= l)
		errx(1, "%s: overflow", __func__);
	if ((*M = realloc(*M, rl)) == NULL)
		err(1, "%s: realloc()", __func__);
	memset(*M + l, 0, rl - l); 
	(*M)[l] = 01 << 7;
	a = (uint64_t *)(*M + rl - sizeof(uint64_t));
	*a = htobe64(l * 8);
	for (i = 0; i < 8; i++)
		H[i] = H_0[i];

	return rl / BLOCKSIZE;
}

/*
 * SHA-256 hash computation (FIPS 180-4, Section 6.2.2)
 */
void
computation(uint8_t *M, uint64_t N, uint32_t H[])
{
	unsigned int i, t;
	uint32_t T_1, T_2;
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t W[64];
	uint32_t *Mi;

	Mi = (uint32_t *)M;
	for (i = 1; i <= N; i++, Mi += BLOCKSIZE / sizeof(uint32_t)) {
		for (t = 0; t < 16; t++)
			W[t] = htobe32(Mi[t]);
		for (;t < 64; t++)
			W[t] = sigma_1(W[t - 2]) + W[t - 7] +
			    sigma_0(W[t - 15]) + W[t - 16];
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];
		for (t = 0; t < 64; t++) {
			T_1 = h + Sigma_1(e) + Ch(e, f, g) + K[t] + W[t];
			T_2 = Sigma_0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T_1;
			d = c;
			c = b;
			b = a;
			a = T_1 + T_2;
		}
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}
}

/*
 * Circular right shift operation ROTR^n(x) (FIPS 180-4, Section 3.2.4)
 */
uint32_t
ROTR(uint32_t n, uint32_t x)
{
	return (x >> n | x << (32 - n));
}

/*
 * Function Ch(x, y, z) (FIPS 180-4, Section 4.1.2, Function 4.2)
 */
uint32_t
Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (~x & z));
}

/*
 * Function Maj(x, y, z) (FIPS 180-4, Section 4.1.2, Function 4.3)
 */
uint32_t
Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

/*
 * Function \Sigma_0^256(x) (FIPS 180-4, Section 4.1.2, Function 4.4)
 */
uint32_t
Sigma_0(uint32_t x)
{
	return (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x));
}

/*
 * Function \Sigma_1^256(x) (FIPS 180-4, Section 4.1.2, Function 4.5)
 */
uint32_t
Sigma_1(uint32_t x)
{
	return (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x));
}

/*
 * Function \sigma_0^256(x) (FIPS 180-4, Section 4.1.2, Function 4.6)
 */
uint32_t
sigma_0(uint32_t x)
{
	return (ROTR(7, x) ^ ROTR(18, x) ^ x >> 3);
}

/*
 * Function \sigma_1^256(x) (FIPS 180-4, Section 4.1.2, Function 4.7)
 */
uint32_t
sigma_1(uint32_t x)
{
	return (ROTR(17, x) ^ ROTR(19, x) ^ x >> 10);
}

/*
 * Host-to-big endian conversion, unsigned 64-bit integer
 */
uint64_t
htobe64(uint64_t n)
{
	return ((n >> 0 & 0377) << 56)
	    + ((n >> 8 & 0377) << 48)
	    + ((n >> 16 & 0377) << 40)
	    + ((n >> 24 & 0377) << 32)
	    + ((n >> 32 & 0377) << 24)
	    + ((n >> 40 & 0377) << 16)
	    + ((n >> 48 & 0377) << 8)
	    + ((n >> 56 & 0377) << 0);
}

/*
 * Host-to-big endian conversion, unsigned 32-bit integer
 */
uint32_t
htobe32(uint32_t n)
{
	return ((n >> 0 & 0377) << 24)
	    + ((n >> 8 & 0377) << 16)
	    + ((n >> 16 & 0377) << 8)
	    + ((n >> 24 & 0377) << 0);
}

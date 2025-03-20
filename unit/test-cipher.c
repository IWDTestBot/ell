/*
 * Embedded Linux library
 * Copyright (C) 2015  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <alloca.h>
#include <stdio.h>

#include <ell/ell.h>

#include "ell/useful.h"

#define FIXED_STR  "The quick brown fox jumps over the lazy dog. " \
		   "Jackdaws love my big sphinx of quartz. "       \
		   "Pack my box with five dozen liquor jugs. "     \
		   "How razorback-jumping frogs can level six piqued gymnasts!"
#define FIXED_LEN  (strlen(FIXED_STR))

#define KEY_STR "This key has exactly _32_ bytes!"
#define KEY_LEN (strlen(KEY_STR))

static void test_unsupported(const void *data)
{
	struct l_cipher *cipher;

	cipher = l_cipher_new(42, KEY_STR, KEY_LEN);
	assert(!cipher);
}

static void test_aes(const void *data)
{
	struct l_cipher *cipher;
	char buf[256];
	size_t real_len;
	int r;

	cipher = l_cipher_new(L_CIPHER_AES, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);
	/* AES is a block cipher, so pad out to next 16-byte boundary */
	real_len = align_len(FIXED_LEN, 16);
	memset(buf + FIXED_LEN, 0, real_len - FIXED_LEN);

	assert(l_cipher_encrypt(cipher, buf, buf, real_len));

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	assert(l_cipher_decrypt(cipher, buf, buf, real_len));

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

static void test_aes_ctr(const void *data)
{
	struct l_cipher *cipher;
	uint8_t iv[16] = { 0 };
	char buf[256];
	int r;

	cipher = l_cipher_new(L_CIPHER_AES_CTR, KEY_STR, KEY_LEN);
	assert(cipher);

	assert(l_cipher_set_iv(cipher, iv, sizeof(iv)));

	memcpy(buf, FIXED_STR, FIXED_LEN);
	assert(l_cipher_encrypt(cipher, buf, buf, FIXED_LEN));

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	assert(l_cipher_set_iv(cipher, iv, sizeof(iv)));
	assert(l_cipher_decrypt(cipher, buf, buf, FIXED_LEN));

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

struct cipher_test {
	enum l_cipher_type type;
	const char *key;
	const char *iv;
	const char *plaintext;
	const char *ciphertext;
};

static const struct cipher_test ecb_aes128_nist = {
	.type		= L_CIPHER_AES,
	.key		= "2B7E151628AED2A6ABF7158809CF4F3C",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "3AD77BB40D7A3660A89ECAF32466EF97"
			  "F5D3D58503B9699DE785895A96FDBAAF"
			  "43B1CD7F598ECE23881B00E3ED030688"
			  "7B0C785E27E8AD3F8223207104725DD4",
};

static const struct cipher_test ecb_aes192_nist = {
	.type		= L_CIPHER_AES,
	.key		= "8E73B0F7DA0E6452C810F32B809079E5"
			  "62F8EAD2522C6B7B",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "BD334F1D6E45F25FF712A214571FA5CC"
			  "974104846D0AD3AD7734ECB3ECEE4EEF"
			  "EF7AFD2270E2E60ADCE0BA2FACE6444E"
			  "9A4B41BA738D6C72FB16691603C18E0E",
};

static const struct cipher_test ecb_aes256_nist = {
	.type		= L_CIPHER_AES,
	.key		= "603DEB1015CA71BE2B73AEF0857D7781"
			  "1F352C073B6108D72D9810A30914DFF4",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "F3EED1BDB5D2A03C064B5A7E3DB181F8"
			  "591CCB10D410ED26DC5BA74A31362870"
			  "B6ED21B99CA6F4F9F153E7B1BEAFED1D"
			  "23304B7A39F9F3FF067D8D8F9E24ECC7",
};

static const struct cipher_test cbc_aes128_nist = {
	.type		= L_CIPHER_AES_CBC,
	.key		= "2B7E151628AED2A6ABF7158809CF4F3C",
	.iv		= "000102030405060708090A0B0C0D0E0F",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "7649ABAC8119B246CEE98E9B12E9197D"
			  "5086CB9B507219EE95DB113A917678B2"
			  "73BED6B8E3C1743B7116E69E22229516"
			  "3FF1CAA1681FAC09120ECA307586E1A7",
};

static const struct cipher_test cbc_aes192_nist = {
	.type		= L_CIPHER_AES_CBC,
	.key		= "8E73B0F7DA0E6452C810F32B809079E5"
			  "62F8EAD2522C6B7B",
	.iv		= "000102030405060708090A0B0C0D0E0F",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "4F021DB243BC633D7178183A9FA071E8"
			  "B4D9ADA9AD7DEDF4E5E738763F69145A"
			  "571B242012FB7AE07FA9BAAC3DF102E0"
			  "08B0E27988598881D920A9E64F5615CD",
};

static const struct cipher_test cbc_aes256_nist = {
	.type		= L_CIPHER_AES_CBC,
	.key		= "603DEB1015CA71BE2B73AEF0857D7781"
			  "1F352C073B6108D72D9810A30914DFF4",
	.iv		= "000102030405060708090A0B0C0D0E0F",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "F58C4C04D6E5F1BA779EABFB5F7BFBD6"
			  "9CFC4E967EDB808D679F777BC6702C7D"
			  "39F23369A9D9BACFA530E26304231461"
			  "B2EB05E2C39BE9FCDA6C19078C6A9D1B",
};

static const struct cipher_test ctr_aes128_nist = {
	.type		= L_CIPHER_AES_CTR,
	.key		= "2B7E151628AED2A6ABF7158809CF4F3C",
	.iv		= "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "874D6191B620E3261BEF6864990DB6CE"
			  "9806F66B7970FDFF8617187BB9FFFDFF"
			  "5AE4DF3EDBD5D35E5B4F09020DB03EAB"
			  "1E031DDA2FBE03D1792170A0F3009CEE",
};

static const struct cipher_test ctr_aes192_nist = {
	.type		= L_CIPHER_AES_CTR,
	.key		= "8E73B0F7DA0E6452C810F32B809079E5"
			  "62F8EAD2522C6B7B",
	.iv		= "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "1ABC932417521CA24F2B0459FE7E6E0B"
			  "090339EC0AA6FAEFD5CCC2C6F4CE8E94"
			  "1E36B26BD1EBC670D1BD1D665620ABF7"
			  "4F78A7F6D29809585A97DAEC58C6B050",
};

static const struct cipher_test ctr_aes256_nist = {
	.type		= L_CIPHER_AES_CTR,
	.key		= "603DEB1015CA71BE2B73AEF0857D7781"
			  "1F352C073B6108D72D9810A30914DFF4",
	.iv		= "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
	.plaintext	= "6BC1BEE22E409F96E93D7E117393172A"
			  "AE2D8A571E03AC9C9EB76FAC45AF8E51"
			  "30C81C46A35CE411E5FBC1191A0A52EF"
			  "F69F2445DF4F9B17AD2B417BE66C3710",
	.ciphertext	= "601EC313775789A5B7A7F504BBF3D228"
			  "F443E3CA4D62B59ACA84E990CACAF5C5"
			  "2B0930DAA23DE94CE87017BA2D84988D"
			  "DFC9C58DB67AADA613C2DD08457941A6",
};

static void test_encrypt(const void *data)
{
	const struct cipher_test *test = data;
	unsigned char *key;
	size_t key_len;
	struct l_cipher *cipher;
	unsigned char *plaintext;
	size_t plaintext_len;
	unsigned char *ciphertext;
	unsigned char *expected;
	size_t expected_len;
	bool result;

	key = l_util_from_hexstring(test->key, &key_len);
	assert(key);

	cipher = l_cipher_new(test->type, key, key_len);
	assert(cipher);

	if (test->iv) {
		unsigned char *iv;
		size_t iv_len;

		iv = l_util_from_hexstring(test->iv, &iv_len);
		assert(iv);

		result = l_cipher_set_iv(cipher, iv, iv_len);
		assert(result);

		l_free(iv);
	}

	plaintext = l_util_from_hexstring(test->plaintext, &plaintext_len);
	assert(plaintext);

	ciphertext = l_malloc(plaintext_len);

	result = l_cipher_encrypt(cipher, plaintext, ciphertext, plaintext_len);
	assert(result);

	expected = l_util_from_hexstring(test->ciphertext, &expected_len);
	assert(expected);
	assert(expected_len == plaintext_len);
	assert(!memcmp(ciphertext, expected, expected_len));

	l_free(expected);
	l_free(ciphertext);
	l_free(plaintext);
	l_cipher_free(cipher);
	l_free(key);
}

static void test_decrypt(const void *data)
{
	const struct cipher_test *test = data;
	unsigned char *key;
	size_t key_len;
	struct l_cipher *cipher;
	unsigned char *ciphertext;
	size_t ciphertext_len;
	unsigned char *plaintext;
	unsigned char *expected;
	size_t expected_len;
	bool result;

	key = l_util_from_hexstring(test->key, &key_len);
	assert(key);

	cipher = l_cipher_new(test->type, key, key_len);
	assert(cipher);

	if (test->iv) {
		unsigned char *iv;
		size_t iv_len;

		iv = l_util_from_hexstring(test->iv, &iv_len);
		assert(iv);

		result = l_cipher_set_iv(cipher, iv, iv_len);
		assert(result);

		l_free(iv);
	}

	ciphertext = l_util_from_hexstring(test->ciphertext, &ciphertext_len);
	assert(ciphertext);

	plaintext = l_malloc(ciphertext_len);

	result = l_cipher_decrypt(cipher, ciphertext, plaintext, ciphertext_len);
	assert(result);

	expected = l_util_from_hexstring(test->plaintext, &expected_len);
	assert(expected);
	assert(expected_len == ciphertext_len);
	assert(!memcmp(plaintext, expected, expected_len));

	l_free(expected);
	l_free(plaintext);
	l_free(ciphertext);
	l_cipher_free(cipher);
	l_free(key);
}

struct aead_test_vector {
	enum l_aead_cipher_type type;
	char *aad;
	char *plaintext;
	char *key;
	char *nonce;
	char *ciphertext;
	char *tag;
};

static const struct aead_test_vector ccm_long_nonce = {
	.type = L_AEAD_CIPHER_AES_CCM,
	.aad =
	"333b6b8fda49c6e671bad05c7e2cafa88bd47f9b0aef1a358bc87d04f26f6c82",
	.plaintext =
	"1293201eb30ddd693b2eb23c1e6c20d5add2202afc71679ca2eba14f73b77bcd",
	.key = "fa536cf6c309d45c1baaa658f674758d",
	.nonce = "e0c5241bf0014ca88511d73a30",
	.ciphertext =
	"2e54ebaa38da9a2b03a1147495565c31d07e793b01fd28b2adeacac6f76ae84e",
	.tag = "e0a03b982c5afc8a937373d7d2b0e7a3"
};

static const struct aead_test_vector ccm_short_nonce = {
	.type = L_AEAD_CIPHER_AES_CCM,
	.plaintext =
	"a3b3fdf26d213f83c5f656b00f77253b68959c188767d584914887602c787595",
	.aad =
	"fcc20524894b4603fefb8029eff485a513ce4753d0d3a27c3a2c69088fa7fab7",
	.key = "7d84efac51291e868c7b7702181a3936",
	.nonce = "1bb3e62620462a",
	.ciphertext =
	"3222192ee773cef4a87175b73b3875320f18b7e016d17d52fb01f0f6ca10bb5f",
	.tag = "ee007aafe91135c39855ebf3db96d7ff"
};

static const struct aead_test_vector ccm_no_aad = {
	.type = L_AEAD_CIPHER_AES_CCM,
	.plaintext =
	"90795fffab99cffdeee5cadafe448ea4df74c480f9d7e1e481ee49adeee2732a",
	.key = "7b3da7d5ef41b5eef19cf8fb4ca19519",
	.nonce = "96722de7516afb",
	.ciphertext =
	"9160dd0e0a8ddd13bf4acb0c6f3cf4794c5459d36a378cfb4a31e6b00840d78a",
	.tag = "efd1dc938802cd845a16f32a60eabd0f"
};

/* https://tools.ietf.org/html/draft-mcgrew-gcm-test-01 */

static const struct aead_test_vector gcm_test1 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "000043218765432100000000",
	.plaintext =
	"45000048699a000080114db7c0a80102c0a801010a9bf15638d3010000010000"
	"00000000045f736970045f756470037369700963796265726369747902646b00"
	"0021000101020201",
	/* 128-bit key */
	.key = "4c80cdefbb5d10da906ac73c3613a634",
	.nonce = "2e443b684956ed7e3b244cfe",
	.ciphertext =
	"fecf537e729d5b07dc30df528dd22b768d1b98736696a6fd348509fa13ceac34"
	"cfa2436f14a3f3cf65925bf1f4a13c5d15b21e1884f5ff6247aeabb786b93bce"
	"61bc17d768fd9732",
	.tag = "459018148f6cbe722fd04796562dfdb4",
};

static const struct aead_test_vector gcm_test2 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "0000a5f80000000a",
	.plaintext =
	"45000028a4ad4000400678800a01038f0a010612802306b8cb712602dd6bb03e"
	"501016d075680001",
	/* 192-bit key */
	.key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
	.nonce = "cafebabefacedbaddecaf888",
	.ciphertext =
	"a5b1f8066029aea40e598b8122de02420938b3ab33f828e687b8858b5bfbdbd0"
	"315b27452144cc77",
	.tag = "95457b9652037f5318027b5b4cd7a636",
};

static const struct aead_test_vector gcm_test3 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "4a2cbfe300000002",
	.plaintext =
	"4500003069a6400080062690c0a801029389155e0a9e008b2dc57ee000000000"
	"7002400020bf0000020405b40101040201020201",
	/* 256-bit key */
	.key =
	"abbccddef00112233445566778899aababbccddef00112233445566778899aab",
	.nonce = "112233440102030405060708",
	.ciphertext =
	"ff425c9b724599df7a3bcd510194e00d6a78107f1b0b1cbf06efae9d65a5d763"
	"748a637985771d347f0545659f14e99def842d8e",
	.tag = "b335f4eecfdbf831824b4c4915956c96",
};

static const struct aead_test_vector gcm_test4 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "0000000000000001",
	.plaintext =
	"4500003c99c500008001cb7a40679318010101010800075c0200440061626364"
	"65666768696a6b6c6d6e6f707172737475767761626364656667686901020201",
	.key = "00000000000000000000000000000000",
	.nonce = "000000000000000000000000",
	.ciphertext =
	"4688daf2f973a392732909c331d56d60f694abaa414b5e7ff5fdcdfff5e9a284"
	"456476492719ffb64de7d9dca1e1d894bc3bd57873ed4d181d19d4d5c8c18af3",
	.tag = "f821d496eeb096e98ad2b69e4799c71d",
};

static const struct aead_test_vector gcm_test5 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "335467aeffffffff",
	.plaintext = "01020201",
	.key = "7d773d00c144c525ac619d18c84a3f47",
	.nonce = "d966426743457e9182443bc6",
	.ciphertext = "437f866b",
	.tag = "cb3f699fe9b0822bac961c4504bef270",
};

static const struct aead_test_vector gcm_test6 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad =
	"0000432100000007000000000000000045000030da3a00008001df3bc0a80005"
	"c0a800010800c6cd020007006162636465666768696a6b6c6d6e6f7071727374"
	"01020201",
	.key = "4c80cdefbb5d10da906ac73c3613a634",
	.nonce = "22433c640000000000000000",
	.tag = "f2a9a836e155106aa8dcd618e4099aaa",
};

static void test_aead(const void *data)
{
	struct l_aead_cipher *cipher;
	char *encbuf;
	size_t encbuflen;
	char *decbuf;
	size_t decbuflen;
	int r;
	bool success;
	const struct aead_test_vector *tv = data;

	size_t ptlen = 0;
	uint8_t *pt = NULL;
	size_t aadlen = 0;
	uint8_t *aad = NULL;
	size_t keylen;
	uint8_t *key = l_util_from_hexstring(tv->key, &keylen);
	size_t noncelen;
	uint8_t *nonce = l_util_from_hexstring(tv->nonce, &noncelen);
	size_t ctlen = 0;
	uint8_t *ct = NULL;
	size_t taglen;
	uint8_t *tag = l_util_from_hexstring(tv->tag, &taglen);

	if (tv->plaintext) {
		pt = l_util_from_hexstring(tv->plaintext, &ptlen);
		assert(pt);
	}

	if (tv->ciphertext) {
		ct = l_util_from_hexstring(tv->ciphertext, &ctlen);
		assert(ct);
	}

	if (tv->aad) {
		aad = l_util_from_hexstring(tv->aad, &aadlen);
		assert(aad);
	}

	assert(key);
	assert(nonce);
	assert(tag);

	decbuflen = ptlen;
	decbuf = alloca(decbuflen);
	memset(decbuf, 0, decbuflen);

	encbuflen = ctlen + taglen;
	encbuf = alloca(encbuflen);
	memset(encbuf, 0, encbuflen);

	cipher = l_aead_cipher_new(tv->type, key, keylen, taglen);
	assert(cipher);

	success = l_aead_cipher_encrypt(cipher, pt, ptlen, aad, aadlen,
					nonce, noncelen, encbuf, encbuflen);
	if (!success) {
		printf("* Some kernel versions before v4.9 have a known AEAD\n"
			"* bug. If the system running this test is using a\n"
			"* v4.8 or earlier kernel, a failure here is likely\n"
			"* due to that kernel bug.\n");
	}
	assert(success);

	assert(memcmp(encbuf, ct, ctlen) == 0);
	assert(memcmp(encbuf + ctlen, tag, taglen) == 0);

	success = l_aead_cipher_decrypt(cipher, encbuf, encbuflen, aad, aadlen,
					nonce, noncelen, decbuf, decbuflen);
	assert (success);

	r = memcmp(decbuf, pt, ptlen);
	assert(!r);

	l_aead_cipher_free(cipher);

	if (tv->plaintext)
		l_free(pt);

	l_free(key);
	l_free(aad);
	l_free(nonce);

	if (tv->ciphertext)
		l_free(ct);

	l_free(tag);
}

/* https://en.wikipedia.org/wiki/RC4 */
static const struct cipher_test arc4_test1 = {
	.type		= L_CIPHER_ARC4,
	.key		= "4B6579",			/* "Key" */
	.plaintext	= "506C61696E74657874",		/* "Plaintext" */
	.ciphertext	= "BBF316E8D940AF0AD3",
};

static const struct cipher_test arc4_test2 = {
	.type		= L_CIPHER_ARC4,
	.key		= "57696B69",			/* "Wiki" */
	.plaintext	= "7065646961",			/* "pedia" */
	.ciphertext	= "1021BF0420",
};

static const struct cipher_test arc4_test3 = {
	.type		= L_CIPHER_ARC4,
	.key		= "536563726574",		   /* "Secret" */
	.plaintext	= "41747461636B206174206461776E",  /* "Attack at .." */
	.ciphertext	= "45A01F645FC35B383552544B9BF5",
};

/* RFC2268 Section 5 (where Effective key length == 8 * Key length) */
static const struct cipher_test rc2_test1 = {
	.type		= L_CIPHER_RC2_CBC,
	.key		= "ffffffffffffffff",
	.plaintext	= "ffffffffffffffff",
	.ciphertext	= "278b27e42e2f0d49",
};

static const struct cipher_test rc2_test2 = {
	.type		= L_CIPHER_RC2_CBC,
	.key		= "3000000000000000",
	.plaintext	= "1000000000000001",
	.ciphertext	= "30649edf9be7d2c2",
};

static const struct cipher_test rc2_test3 = {
	.type		= L_CIPHER_RC2_CBC,
	.key		= "88bca90e90875a7f0f79c384627bafb2",
	.plaintext	= "0000000000000000",
	.ciphertext	= "2269552ab0f85ca6",
};

#define add_encrypt_test(name, data) l_test_add_data_func(name, data, \
					test_encrypt, L_TEST_FLAG_ALLOW_FAILURE)
#define add_decrypt_test(name, data) l_test_add_data_func(name, data, \
					test_decrypt, L_TEST_FLAG_ALLOW_FAILURE)

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	l_test_add_func("aes", test_aes, L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_func("aes_ctr", test_aes_ctr, L_TEST_FLAG_ALLOW_FAILURE);

	if (l_aead_cipher_is_supported(L_AEAD_CIPHER_AES_CCM)) {
		l_test_add("aes_ccm long nonce", test_aead, &ccm_long_nonce);
		l_test_add("aes_ccm short nonce", test_aead, &ccm_short_nonce);
		l_test_add("aes_ccm no AAD", test_aead, &ccm_no_aad);
	}

	if (l_aead_cipher_is_supported(L_AEAD_CIPHER_AES_GCM)) {
		l_test_add("aes_gcm test 1", test_aead, &gcm_test1);
		l_test_add("aes_gcm test 2", test_aead, &gcm_test2);
		l_test_add("aes_gcm test 3", test_aead, &gcm_test3);
		l_test_add("aes_gcm test 4", test_aead, &gcm_test4);
		l_test_add("aes_gcm test 5", test_aead, &gcm_test5);
		l_test_add("aes_gcm test 6", test_aead, &gcm_test6);
	}

	add_encrypt_test("ARC4/encrypt/test 1", &arc4_test1);
	add_decrypt_test("ARC4/decrypt/test 1", &arc4_test1);
	add_encrypt_test("ARC4/encrypt/test 2", &arc4_test2);
	add_decrypt_test("ARC4/decrypt/test 2", &arc4_test2);
	add_encrypt_test("ARC4/encrypt/test 3", &arc4_test3);
	add_decrypt_test("ARC4/decrypt/test 3", &arc4_test3);

	add_encrypt_test("RC2/encrypt/test 1", &rc2_test1);
	add_decrypt_test("RC2/decrypt/test 1", &rc2_test1);
	add_encrypt_test("RC2/encrypt/test 2", &rc2_test2);
	add_decrypt_test("RC2/decrypt/test 2", &rc2_test2);
	add_encrypt_test("RC2/encrypt/test 3", &rc2_test3);
	add_decrypt_test("RC2/decrypt/test 3", &rc2_test3);

	add_encrypt_test("AES-128/encrypt/NIST", &ecb_aes128_nist);
	add_decrypt_test("AES-128/decrypt/NIST", &ecb_aes128_nist);
	add_encrypt_test("AES-192/encrypt/NIST", &ecb_aes192_nist);
	add_decrypt_test("AES-192/decrypt/NIST", &ecb_aes192_nist);
	add_encrypt_test("AES-256/encrypt/NIST", &ecb_aes256_nist);
	add_decrypt_test("AES-256/decrypt/NIST", &ecb_aes256_nist);
	add_encrypt_test("CBC-AES-128/encrypt/NIST", &cbc_aes128_nist);
	add_decrypt_test("CBS-AES-128/decrypt/NIST", &cbc_aes128_nist);
	add_encrypt_test("CBC-AES-192/encrypt/NIST", &cbc_aes192_nist);
	add_decrypt_test("CBS-AES-192/decrypt/NIST", &cbc_aes192_nist);
	add_encrypt_test("CBC-AES-256/encrypt/NIST", &cbc_aes256_nist);
	add_decrypt_test("CBS-AES-256/decrypt/NIST", &cbc_aes256_nist);
	add_encrypt_test("CTR-AES-128/encrypt/NIST", &ctr_aes128_nist);
	add_decrypt_test("CTR-AES-128/decrypt/NIST", &ctr_aes128_nist);
	add_encrypt_test("CTR-AES-192/encrypt/NIST", &ctr_aes192_nist);
	add_decrypt_test("CTR-AES-192/decrypt/NIST", &ctr_aes192_nist);
	add_encrypt_test("CTR-AES-256/encrypt/NIST", &ctr_aes256_nist);
	add_decrypt_test("CTR-AES-256/decrypt/NIST", &ctr_aes256_nist);

	return l_test_run();
}

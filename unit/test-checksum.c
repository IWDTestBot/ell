/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <alloca.h>
#include <assert.h>

#include <ell/ell.h>

static char FIXED_STR[] =
	"The quick brown fox jumps over the lazy dog. "
	"Jackdaws love my big sphinx of quartz. "
	"Pack my box with five dozen liquor jugs. "
	"How razorback-jumping frogs can level six piqued gymnasts!";

#define FIXED_LEN  (strlen (FIXED_STR))

static void test_unsupported(const void *data)
{
	struct l_checksum *checksum;

	checksum = l_checksum_new(42);
	assert(!checksum);
}

static void test_md4(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_MD4);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring("be3de05811bec433af48270014a8df0e",
						&expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_md5(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_MD5);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring("407b72260377f77f8e63e13dc09bda2c",
						&expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_sha1(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[20];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring(
		"8802f1d217906250585b75187b1ebfbb5c6cbcae", &expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_sha256(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[32];
	unsigned char *expected;
	size_t expectlen;

	checksum = l_checksum_new(L_CHECKSUM_SHA256);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	expected = l_util_from_hexstring(
		"df3a0c35d5345d6d792415c1310bd458"
		"9cdf68bac96ed599d6bb0c1545ffc86c", &expectlen);
	assert(expectlen == sizeof(digest));
	assert(!memcmp(digest, expected, expectlen));

	l_free(expected);
	l_checksum_free(checksum);
}

static void test_reset(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];

	checksum = l_checksum_new(L_CHECKSUM_MD5);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_reset(checksum);
	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_get_digest(checksum, digest, sizeof(digest));

	l_checksum_free(checksum);
}

static void test_updatev(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest1[20];
	unsigned char digest2[20];
	struct iovec iov[2];

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_get_digest(checksum, digest1, sizeof(digest1));

	iov[0].iov_base = FIXED_STR;
	iov[0].iov_len = FIXED_LEN / 2;

	iov[1].iov_base = FIXED_STR + FIXED_LEN / 2;
	iov[1].iov_len = FIXED_LEN - FIXED_LEN / 2;

	l_checksum_updatev(checksum, iov, 2);
	l_checksum_get_digest(checksum, digest2, sizeof(digest2));

	assert(!memcmp(digest1, digest2, sizeof(digest1)));

	l_checksum_free(checksum);
}

struct sha_test {
	enum l_checksum_type type;
	const char *msg;
	const char *hash;
};

static const struct sha_test sha1_test1 = {
	.type	= L_CHECKSUM_SHA1,
	.msg	= "abc",
	.hash	= "a9993e364706816aba3e25717850c26c"
		  "9cd0d89d",
};

static const struct sha_test sha1_test2 = {
	.type	= L_CHECKSUM_SHA1,
	.msg	= "",
	.hash	= "da39a3ee5e6b4b0d3255bfef95601890"
		  "afd80709",
};

static const struct sha_test sha1_test3 = {
	.type	= L_CHECKSUM_SHA1,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "84983e441c3bd26ebaae4aa1f95129e5"
		  "e54670f1",
};

static const struct sha_test sha1_test4 = {
	.type	= L_CHECKSUM_SHA1,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "a49b2446a02c645bf419f995b6709125"
		  "3a04a259",
};

static const struct sha_test sha224_test1 = {
	.type	= L_CHECKSUM_SHA224,
	.msg	= "abc",
	.hash	= "23097d223405d8228642a477bda255b3"
		  "2aadbce4bda0b3f7e36c9da7",
};

static const struct sha_test sha224_test2 = {
	.type	= L_CHECKSUM_SHA224,
	.msg	= "",
	.hash	= "d14a028c2a3a2bc9476102bb288234c4"
		  "15a2b01f828ea62ac5b3e42f",
};

static const struct sha_test sha224_test3 = {
	.type	= L_CHECKSUM_SHA224,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "75388b16512776cc5dba5da1fd890150"
		  "b0c6455cb4f58b1952522525",
};

static const struct sha_test sha224_test4 = {
	.type	= L_CHECKSUM_SHA224,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "c97ca9a559850ce97a04a96def6d99a9"
		  "e0e0e2ab14e6b8df265fc0b3",
};

static void test_sha(const void *data)
{
	const struct sha_test *test = data;
	size_t msg_len;
	struct l_checksum *checksum;
	unsigned char *digest;
	size_t digest_len;
	unsigned char *expected;
	size_t expected_len;

	checksum = l_checksum_new(test->type);
	assert(checksum);

	digest_len = l_checksum_digest_length(test->type);
	digest = l_malloc(digest_len);

	msg_len = strlen(test->msg);
	l_checksum_update(checksum, test->msg, msg_len);

	l_checksum_get_digest(checksum, digest, digest_len);

	expected = l_util_from_hexstring(test->hash, &expected_len);
	assert(expected);
	assert(expected_len == digest_len);
	assert(!memcmp(digest, expected, expected_len));

	l_free(expected);
	l_free(digest);
	l_checksum_free(checksum);
}

struct aes_cmac_test_vector {
	char *plaintext;
	char *key;
	char *ciphertext;
};

/* Hash AES_CMAC tests based on Bluetooth Mesh published sample data */
static const struct aes_cmac_test_vector aes_cmac_test1 = {
	.plaintext = "74657374",
	.key = "00000000000000000000000000000000",
	.ciphertext = "b73cefbd641ef2ea598c2b6efb62f79c",
};

static const struct aes_cmac_test_vector aes_cmac_test2 = {
	.plaintext = "f7a2a44f8e8a8029064f173ddc1e2b00",
	.key = "4f90480c1871bfbffd16971f4d8d10b1",
	.ciphertext = "2ea6467aa3378c4c545eda62935b9b86",
};

static void test_aes_cmac(const void *data)
{
	struct l_checksum *checksum;
	char *encbuf;
	size_t encbuflen;
	char *decbuf;
	size_t decbuflen;
	int r;
	bool success;
	const struct aes_cmac_test_vector *tv = data;

	size_t ptlen;
	uint8_t *pt = l_util_from_hexstring(tv->plaintext, &ptlen);
	size_t keylen;
	uint8_t *key = l_util_from_hexstring(tv->key, &keylen);
	size_t ctlen;
	uint8_t *ct = l_util_from_hexstring(tv->ciphertext, &ctlen);

	assert(pt);
	assert(ct);
	assert(key);

	encbuflen = ctlen;
	encbuf = alloca(encbuflen);
	memset(encbuf, 0, encbuflen);
	decbuflen = ptlen;
	decbuf = alloca(decbuflen);
	memset(decbuf, 0, decbuflen);

	checksum = l_checksum_new_cmac_aes(key, keylen);
	assert(checksum);

	success = l_checksum_update(checksum, pt, ptlen);
	assert(success);

	ctlen = l_checksum_get_digest(checksum, encbuf, encbuflen);
	assert(ctlen == encbuflen);

	r = memcmp(encbuf, ct, ctlen);
	assert(!r);

	l_checksum_free(checksum);

	l_free(pt);
	l_free(key);
	l_free(ct);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	l_test_add_func("md4-1", test_md4, L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_func("md5-1", test_md5, L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_func("sha1-1", test_sha1, L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_func("sha256-1", test_sha256, L_TEST_FLAG_ALLOW_FAILURE);

	l_test_add_func("checksum reset", test_reset,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_func("checksum updatev", test_updatev,
						L_TEST_FLAG_ALLOW_FAILURE);

	l_test_add_data_func("SHA-1/1", &sha1_test1, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-1/2", &sha1_test2, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-1/3", &sha1_test3, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-1/4", &sha1_test4, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-224/1", &sha224_test1, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-224/2", &sha224_test2, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-224/3", &sha224_test3, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("SHA-224/4", &sha224_test4, test_sha,
						L_TEST_FLAG_ALLOW_FAILURE);

	l_test_add_data_func("aes-cmac-1", &aes_cmac_test1, test_aes_cmac,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("aes-cmac-2", &aes_cmac_test2, test_aes_cmac,
						L_TEST_FLAG_ALLOW_FAILURE);

	return l_test_run();
}

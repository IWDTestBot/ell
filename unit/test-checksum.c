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

static const struct sha_test sha256_test1 = {
	.type	= L_CHECKSUM_SHA256,
	.msg	= "abc",
	.hash	= "ba7816bf8f01cfea414140de5dae2223"
		  "b00361a396177a9cb410ff61f20015ad",
};

static const struct sha_test sha256_test2 = {
	.type	= L_CHECKSUM_SHA256,
	.msg	= "",
	.hash	= "e3b0c44298fc1c149afbf4c8996fb924"
		  "27ae41e4649b934ca495991b7852b855",
};

static const struct sha_test sha256_test3 = {
	.type	= L_CHECKSUM_SHA256,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "248d6a61d20638b8e5c026930c3e6039"
		  "a33ce45964ff2167f6ecedd419db06c1",
};

static const struct sha_test sha256_test4 = {
	.type	= L_CHECKSUM_SHA256,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "cf5b16a778af8380036ce59e7b049237"
		  "0b249b11e8f07a51afac45037afee9d1",
};

static const struct sha_test sha384_test1 = {
	.type	= L_CHECKSUM_SHA384,
	.msg	= "abc",
	.hash	= "cb00753f45a35e8bb5a03d699ac65007"
		  "272c32ab0eded1631a8b605a43ff5bed"
		  "8086072ba1e7cc2358baeca134c825a7",
};

static const struct sha_test sha384_test2 = {
	.type	= L_CHECKSUM_SHA384,
	.msg	= "",
	.hash	= "38b060a751ac96384cd9327eb1b1e36a"
		  "21fdb71114be07434c0cc7bf63f6e1da"
		  "274edebfe76f65fbd51ad2f14898b95b",
};

static const struct sha_test sha384_test3 = {
	.type	= L_CHECKSUM_SHA384,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "3391fdddfc8dc7393707a65b1b470939"
		  "7cf8b1d162af05abfe8f450de5f36bc6"
		  "b0455a8520bc4e6f5fe95b1fe3c8452b",
};

static const struct sha_test sha384_test4 = {
	.type	= L_CHECKSUM_SHA384,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "09330c33f71147e83d192fc782cd1b47"
		  "53111b173b3b05d22fa08086e3b0f712"
		  "fcc7c71a557e2db966c3e9fa91746039",
};

static const struct sha_test sha512_test1 = {
	.type	= L_CHECKSUM_SHA512,
	.msg	= "abc",
	.hash	= "ddaf35a193617abacc417349ae204131"
		  "12e6fa4e89a97ea20a9eeee64b55d39a"
		  "2192992a274fc1a836ba3c23a3feebbd"
		  "454d4423643ce80e2a9ac94fa54ca49f",
};

static const struct sha_test sha512_test2 = {
	.type	= L_CHECKSUM_SHA512,
	.msg	= "",
	.hash	= "cf83e1357eefb8bdf1542850d66d8007"
		  "d620e4050b5715dc83f4a921d36ce9ce"
		  "47d0d13c5d85f2b0ff8318d2877eec2f"
		  "63b931bd47417a81a538327af927da3e",
};

static const struct sha_test sha512_test3 = {
	.type	= L_CHECKSUM_SHA512,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "204a8fc6dda82f0a0ced7beb8e08a416"
		  "57c16ef468b228a8279be331a703c335"
		  "96fd15c13b1b07f9aa1d3bea57789ca0"
		  "31ad85c7a71dd70354ec631238ca3445",
};

static const struct sha_test sha512_test4 = {
	.type	= L_CHECKSUM_SHA512,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "8e959b75dae313da8cf4f72814fc143f"
		  "8f7779c6eb9f7fa17299aeadb6889018"
		  "501d289e4900f7e4331b99dec4b5433a"
		  "c7d329eeb6dd26545e96e55b874be909",
};

static const struct sha_test sha3_224_test1 = {
	.type	= L_CHECKSUM_SHA3_224,
	.msg	= "abc",
	.hash	= "e642824c3f8cf24ad09234ee7d3c766f"
		  "c9a3a5168d0c94ad73b46fdf",
};

static const struct sha_test sha3_224_test2 = {
	.type	= L_CHECKSUM_SHA3_224,
	.msg	= "",
	.hash	= "6b4e03423667dbb73b6e15454f0eb1ab"
		  "d4597f9a1b078e3f5b5a6bc7",
};

static const struct sha_test sha3_224_test3 = {
	.type	= L_CHECKSUM_SHA3_224,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "8a24108b154ada21c9fd5574494479ba"
		  "5c7e7ab76ef264ead0fcce33",
};

static const struct sha_test sha3_224_test4 = {
	.type	= L_CHECKSUM_SHA3_224,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "543e6868e1666c1a643630df77367ae5"
		  "a62a85070a51c14cbf665cbc",
};

static const struct sha_test sha3_256_test1 = {
	.type	= L_CHECKSUM_SHA3_256,
	.msg	= "abc",
	.hash	= "3a985da74fe225b2045c172d6bd390bd"
		  "855f086e3e9d525b46bfe24511431532",
};

static const struct sha_test sha3_256_test2 = {
	.type	= L_CHECKSUM_SHA3_256,
	.msg	= "",
	.hash	= "a7ffc6f8bf1ed76651c14756a061d662"
		  "f580ff4de43b49fa82d80a4b80f8434a",
};

static const struct sha_test sha3_256_test3 = {
	.type	= L_CHECKSUM_SHA3_256,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "41c0dba2a9d6240849100376a8235e2c"
		  "82e1b9998a999e21db32dd97496d3376",
};

static const struct sha_test sha3_256_test4 = {
	.type	= L_CHECKSUM_SHA3_256,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "916f6061fe879741ca6469b43971dfdb"
		  "28b1a32dc36cb3254e812be27aad1d18",
};

static const struct sha_test sha3_384_test1 = {
	.type	= L_CHECKSUM_SHA3_384,
	.msg	= "abc",
	.hash	= "ec01498288516fc926459f58e2c6ad8d"
		  "f9b473cb0fc08c2596da7cf0e49be4b2"
		  "98d88cea927ac7f539f1edf228376d25",
};

static const struct sha_test sha3_384_test2 = {
	.type	= L_CHECKSUM_SHA3_384,
	.msg	= "",
	.hash	= "0c63a75b845e4f7d01107d852e4c2485"
		  "c51a50aaaa94fc61995e71bbee983a2a"
		  "c3713831264adb47fb6bd1e058d5f004",
};

static const struct sha_test sha3_384_test3 = {
	.type	= L_CHECKSUM_SHA3_384,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "991c665755eb3a4b6bbdfb75c78a492e"
		  "8c56a22c5c4d7e429bfdbc32b9d4ad5a"
		  "a04a1f076e62fea19eef51acd0657c22",
};

static const struct sha_test sha3_384_test4 = {
	.type	= L_CHECKSUM_SHA3_384,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "79407d3b5916b59c3e30b09822974791"
		  "c313fb9ecc849e406f23592d04f625dc"
		  "8c709b98b43b3852b337216179aa7fc7",
};

static const struct sha_test sha3_512_test1 = {
	.type	= L_CHECKSUM_SHA3_512,
	.msg	= "abc",
	.hash	= "b751850b1a57168a5693cd924b6b096e"
		  "08f621827444f70d884f5d0240d2712e"
		  "10e116e9192af3c91a7ec57647e39340"
		  "57340b4cf408d5a56592f8274eec53f0",
};

static const struct sha_test sha3_512_test2 = {
	.type	= L_CHECKSUM_SHA3_512,
	.msg	= "",
	.hash	= "a69f73cca23a9ac5c8b567dc185a756e"
		  "97c982164fe25859e0d1dcc1475c80a6"
		  "15b2123af1f5f94c11e3e9402c3ac558"
		  "f500199d95b6d3e301758586281dcd26",
};

static const struct sha_test sha3_512_test3 = {
	.type	= L_CHECKSUM_SHA3_512,
	.msg	= "abcdbcdecdefdefgefghfghighijhijk"
		  "ijkljklmklmnlmnomnopnopq",
	.hash	= "04a371e84ecfb5b8b77cb48610fca818"
		  "2dd457ce6f326a0fd3d7ec2f1e91636d"
		  "ee691fbe0c985302ba1b0d8dc78c0863"
		  "46b533b49c030d99a27daf1139d6e75e",
};

static const struct sha_test sha3_512_test4 = {
	.type	= L_CHECKSUM_SHA3_512,
	.msg	= "abcdefghbcdefghicdefghijdefghijk"
		  "efghijklfghijklmghijklmnhijklmno"
		  "ijklmnopjklmnopqklmnopqrlmnopqrs"
		  "mnopqrstnopqrstu",
	.hash	= "afebb2ef542e6579c50cad06d2e578f9"
		  "f8dd6881d7dc824d26360feebf18a4fa"
		  "73e3261122948efcfd492e74e82e2189"
		  "ed0fb440d187f382270cb455f21dd185",
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

#define add_sha_test(name, data) l_test_add_data_func(name, data, \
					test_sha, L_TEST_FLAG_ALLOW_FAILURE)

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

	add_sha_test("SHA-1/1", &sha1_test1);
	add_sha_test("SHA-1/2", &sha1_test2);
	add_sha_test("SHA-1/3", &sha1_test3);
	add_sha_test("SHA-1/4", &sha1_test4);
	add_sha_test("SHA-224/1", &sha224_test1);
	add_sha_test("SHA-224/2", &sha224_test2);
	add_sha_test("SHA-224/3", &sha224_test3);
	add_sha_test("SHA-224/4", &sha224_test4);
	add_sha_test("SHA-256/1", &sha256_test1);
	add_sha_test("SHA-256/2", &sha256_test2);
	add_sha_test("SHA-256/3", &sha256_test3);
	add_sha_test("SHA-256/4", &sha256_test4);
	add_sha_test("SHA-384/1", &sha384_test1);
	add_sha_test("SHA-384/2", &sha384_test2);
	add_sha_test("SHA-384/3", &sha384_test3);
	add_sha_test("SHA-384/4", &sha384_test4);
	add_sha_test("SHA-512/1", &sha512_test1);
	add_sha_test("SHA-512/2", &sha512_test2);
	add_sha_test("SHA-512/3", &sha512_test3);
	add_sha_test("SHA-512/4", &sha512_test4);
	add_sha_test("SHA-3-224/1", &sha3_224_test1);
	add_sha_test("SHA-3-224/2", &sha3_224_test2);
	add_sha_test("SHA-3-224/3", &sha3_224_test3);
	add_sha_test("SHA-3-224/4", &sha3_224_test4);
	add_sha_test("SHA-3-256/1", &sha3_256_test1);
	add_sha_test("SHA-3-256/2", &sha3_256_test2);
	add_sha_test("SHA-3-256/3", &sha3_256_test3);
	add_sha_test("SHA-3-256/4", &sha3_256_test4);
	add_sha_test("SHA-3-384/1", &sha3_384_test1);
	add_sha_test("SHA-3-384/2", &sha3_384_test2);
	add_sha_test("SHA-3-384/3", &sha3_384_test3);
	add_sha_test("SHA-3-384/4", &sha3_384_test4);
	add_sha_test("SHA-3-512/1", &sha3_512_test1);
	add_sha_test("SHA-3-512/2", &sha3_512_test2);
	add_sha_test("SHA-3-512/3", &sha3_512_test3);
	add_sha_test("SHA-3-512/4", &sha3_512_test4);

	l_test_add_data_func("aes-cmac-1", &aes_cmac_test1, test_aes_cmac,
						L_TEST_FLAG_ALLOW_FAILURE);
	l_test_add_data_func("aes-cmac-2", &aes_cmac_test2, test_aes_cmac,
						L_TEST_FLAG_ALLOW_FAILURE);

	return l_test_run();
}

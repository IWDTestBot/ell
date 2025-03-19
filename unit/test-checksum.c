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

struct hmac_sha_test {
	const char *key;
	const char *data;
	enum l_checksum_type type;
	const char *hash;
	size_t h_len;
};

/* RFC 2104 - Appendix -- Sample Code - Test 1 */
static const struct hmac_sha_test hmac_md5_test1 = {
	.key	= "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
	.data	= "4869205468657265",
	.type	= L_CHECKSUM_MD5,
	.hash	= "9294727a3638bb1c13f48ef8158bfc9d",
};

/* RFC 2104 - Appendix -- Sample Code - Test 2 */
static const struct hmac_sha_test hmac_md5_test2 = {
	.key	= "4a656665",
	.data	= "7768617420646f2079612077616e7420"
		  "666f72206e6f7468696e673f",
	.type	= L_CHECKSUM_MD5,
	.hash	= "750c783e6ab0b503eaa86e310a5db738",
};

/* RFC 2104 - Appendix -- Sample Code - Test 3 */
static const struct hmac_sha_test hmac_md5_test3 = {
	.key	= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	.data	= "dddddddddddddddddddddddddddddddd"
		  "dddddddddddddddddddddddddddddddd"
		  "dddddddddddddddddddddddddddddddd"
		  "dddd",
	.type	= L_CHECKSUM_MD5,
	.hash	= "56be34521d144c88dbb8c733f0e8b3f6",
};

/* RFC 4231 - Section 4.2. Test Case 1 */
#define HMAC_SHA_TEST1	.key	= "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"	\
				  "0b0b0b0b",				\
			.data	= "4869205468657265"

static const struct hmac_sha_test hmac_sha224_test1 = {
	HMAC_SHA_TEST1,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "896fb1128abbdf196832107cd49df33f"
		  "47b4b1169912ba4f53684b22",
};

static const struct hmac_sha_test hmac_sha256_test1 = {
	HMAC_SHA_TEST1,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "b0344c61d8db38535ca8afceaf0bf12b"
		  "881dc200c9833da726e9376c2e32cff7",
};

static const struct hmac_sha_test hmac_sha384_test1 = {
	HMAC_SHA_TEST1,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "afd03944d84895626b0825f4ab46907f"
		  "15f9dadbe4101ec682aa034c7cebc59c"
		  "faea9ea9076ede7f4af152e8b2fa9cb6",
};

static const struct hmac_sha_test hmac_sha512_test1 = {
	HMAC_SHA_TEST1,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "87aa7cdea5ef619d4ff0b4241a1d6cb0"
		  "2379f4e2ce4ec2787ad0b30545e17cde"
		  "daa833b7d6b8a702038b274eaea3f4e4"
		  "be9d914eeb61f1702e696c203a126854",
};

/* RFC 4231 - Section 4.3. Test Case 2 */
#define HMAC_SHA_TEST2	.key	= "4a656665",				\
			.data	= "7768617420646f2079612077616e7420"	\
				  "666f72206e6f7468696e673f"

static const struct hmac_sha_test hmac_sha224_test2 = {
	HMAC_SHA_TEST2,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "a30e01098bc6dbbf45690f3a7e9e6d0f"
		  "8bbea2a39e6148008fd05e44",
};

static const struct hmac_sha_test hmac_sha256_test2 = {
	HMAC_SHA_TEST2,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "5bdcc146bf60754e6a042426089575c7"
		  "5a003f089d2739839dec58b964ec3843",
};

static const struct hmac_sha_test hmac_sha384_test2 = {
	HMAC_SHA_TEST2,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "af45d2e376484031617f78d2b58a6b1b"
		  "9c7ef464f5a01b47e42ec3736322445e"
		  "8e2240ca5e69e2c78b3239ecfab21649",
};

static const struct hmac_sha_test hmac_sha512_test2 = {
	HMAC_SHA_TEST2,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "164b7a7bfcf819e2e395fbe73b56e0a3"
		  "87bd64222e831fd610270cd7ea250554"
		  "9758bf75c05a994a6d034f65f8f0e6fd"
		  "caeab1a34d4a6b4b636e070a38bce737",
};

/* RFC 4231 - Section 4.4. Test Case 3 */
#define HMAC_SHA_TEST3	.key	= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaa",				\
			.data	= "dddddddddddddddddddddddddddddddd"	\
				  "dddddddddddddddddddddddddddddddd"	\
				  "dddddddddddddddddddddddddddddddd"	\
				  "dddd"

static const struct hmac_sha_test hmac_sha224_test3 = {
	HMAC_SHA_TEST3,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "7fb3cb3588c6c1f6ffa9694d7d6ad264"
		  "9365b0c1f65d69d1ec8333ea",
};

static const struct hmac_sha_test hmac_sha256_test3 = {
	HMAC_SHA_TEST3,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "773ea91e36800e46854db8ebd09181a7"
		  "2959098b3ef8c122d9635514ced565fe",
};

static const struct hmac_sha_test hmac_sha384_test3 = {
	HMAC_SHA_TEST3,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "88062608d3e6ad8a0aa2ace014c8a86f"
		  "0aa635d947ac9febe83ef4e55966144b"
		  "2a5ab39dc13814b94e3ab6e101a34f27",
};

static const struct hmac_sha_test hmac_sha512_test3 = {
	HMAC_SHA_TEST3,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "fa73b0089d56a284efb0f0756c890be9"
		  "b1b5dbdd8ee81a3655f83e33b2279d39"
		  "bf3e848279a722c806b485a47e67c807"
		  "b946a337bee8942674278859e13292fb",
};

/* RFC 4231 - Section 4.5. Test Case 4 */
#define HMAC_SHA_TEST4	.key	= "0102030405060708090a0b0c0d0e0f10"	\
				  "111213141516171819",			\
			.data	= "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"	\
				  "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"	\
				  "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"	\
				  "cdcd"

static const struct hmac_sha_test hmac_sha224_test4 = {
	HMAC_SHA_TEST4,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "6c11506874013cac6a2abc1bb382627c"
		  "ec6a90d86efc012de7afec5a",
};

static const struct hmac_sha_test hmac_sha256_test4 = {
	HMAC_SHA_TEST4,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "82558a389a443c0ea4cc819899f2083a"
		  "85f0faa3e578f8077a2e3ff46729665b",
};

static const struct hmac_sha_test hmac_sha384_test4 = {
	HMAC_SHA_TEST4,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "3e8a69b7783c25851933ab6290af6ca7"
		  "7a9981480850009cc5577c6e1f573b4e"
		  "6801dd23c4a7d679ccf8a386c674cffb",
};

static const struct hmac_sha_test hmac_sha512_test4 = {
	HMAC_SHA_TEST4,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "b0ba465637458c6990e5a8c5f61d4af7"
		  "e576d97ff94b872de76f8050361ee3db"
		  "a91ca5c11aa25eb4d679275cc5788063"
		  "a5f19741120c4f2de2adebeb10a298dd",
};

/* RFC 4231 - Section 4.6. Test Case 5 */
#define HMAC_SHA_TEST5	.key	= "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"	\
				  "0c0c0c0c",				\
			.data	= "546573742057697468205472756e6361"	\
				  "74696f6e"

static const struct hmac_sha_test hmac_sha224_test5 = {
	HMAC_SHA_TEST5,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "0e2aea68a90c8d37c988bcdb9fca6fa8",
	.h_len	= 16,
};

static const struct hmac_sha_test hmac_sha256_test5 = {
	HMAC_SHA_TEST5,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "a3b6167473100ee06e0c796c2955552b",
	.h_len	= 16,
};

static const struct hmac_sha_test hmac_sha384_test5 = {
	HMAC_SHA_TEST5,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "3abf34c3503b2a23a46efc619baef897",
	.h_len	= 16,
};

static const struct hmac_sha_test hmac_sha512_test5 = {
	HMAC_SHA_TEST5,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "415fad6271580a531d4179bc891d87a6",
	.h_len	= 16,
};

/* RFC 4231 - Section 4.7. Test Case 6 */
#define HMAC_SHA_TEST6	.key	= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaa",				\
			.data	= "54657374205573696e67204c61726765"	\
				  "72205468616e20426c6f636b2d53697a"	\
				  "65204b6579202d2048617368204b6579"	\
				  "204669727374"

static const struct hmac_sha_test hmac_sha224_test6 = {
	HMAC_SHA_TEST6,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "95e9a0db962095adaebe9b2d6f0dbce2"
		  "d499f112f2d2b7273fa6870e",
};

static const struct hmac_sha_test hmac_sha256_test6 = {
	HMAC_SHA_TEST6,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "60e431591ee0b67f0d8a26aacbf5b77f"
		  "8e0bc6213728c5140546040f0ee37f54",
};

static const struct hmac_sha_test hmac_sha384_test6 = {
	HMAC_SHA_TEST6,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "4ece084485813e9088d2c63a041bc5b4"
		  "4f9ef1012a2b588f3cd11f05033ac4c6"
		  "0c2ef6ab4030fe8296248df163f44952",
};

static const struct hmac_sha_test hmac_sha512_test6 = {
	HMAC_SHA_TEST6,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "80b24263c7c1a3ebb71493c1dd7be8b4"
		  "9b46d1f41b4aeec1121b013783f8f352"
		  "6b56d037e05f2598bd0fd2215d6a1e52"
		  "95e64f73f63f0aec8b915a985d786598",
};

/* RFC 4231 - Section 4.8. Test Case 7 */
#define HMAC_SHA_TEST7	.key	= "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"	\
				  "aaaaaa",				\
			.data	= "54686973206973206120746573742075"	\
				  "73696e672061206c6172676572207468"	\
				  "616e20626c6f636b2d73697a65206b65"	\
				  "7920616e642061206c61726765722074"	\
				  "68616e20626c6f636b2d73697a652064"	\
				  "6174612e20546865206b6579206e6565"	\
				  "647320746f2062652068617368656420"	\
				  "6265666f7265206265696e6720757365"	\
				  "642062792074686520484d414320616c"	\
				  "676f726974686d2e"

static const struct hmac_sha_test hmac_sha224_test7 = {
	HMAC_SHA_TEST7,
	.type	= L_CHECKSUM_SHA224,
	.hash	= "3a854166ac5d9f023f54d517d0b39dbd"
		  "946770db9c2b95c9f6f565d1",
};

static const struct hmac_sha_test hmac_sha256_test7 = {
	HMAC_SHA_TEST7,
	.type	= L_CHECKSUM_SHA256,
	.hash	= "9b09ffa71b942fcb27635fbcd5b0e944"
		  "bfdc63644f0713938a7f51535c3a35e2",
};

static const struct hmac_sha_test hmac_sha384_test7 = {
	HMAC_SHA_TEST7,
	.type	= L_CHECKSUM_SHA384,
	.hash	= "6617178e941f020d351e2f254e8fd32c"
		  "602420feb0b8fb9adccebb82461e99c5"
		  "a678cc31e799176d3860e6110c46523e",
};

static const struct hmac_sha_test hmac_sha512_test7 = {
	HMAC_SHA_TEST7,
	.type	= L_CHECKSUM_SHA512,
	.hash	= "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
		  "debd71f8867289865df5a32d20cdc944"
		  "b6022cac3c4982b10d5eeb55c3e4de15"
		  "134676fb6de0446065c97440fa8c6a58",
};

static void test_hmac_sha(const void *data)
{
	const struct hmac_sha_test *test = data;
	unsigned char *key;
	size_t key_len;
	unsigned char *msg;
	size_t msg_len;
	struct l_checksum *checksum;
	unsigned char *digest;
	size_t digest_len;
	unsigned char *expected;
	size_t expected_len;

	key = l_util_from_hexstring(test->key, &key_len);
	assert(key);

	checksum = l_checksum_new_hmac(test->type, key, key_len);
	assert(checksum);

	if (test->h_len > 0)
		digest_len = test->h_len;
	else
		digest_len = l_checksum_digest_length(test->type);

	digest = l_malloc(digest_len);

	msg = l_util_from_hexstring(test->data, &msg_len);
	assert(msg);

	l_checksum_update(checksum, msg, msg_len);

	l_checksum_get_digest(checksum, digest, digest_len);

	expected = l_util_from_hexstring(test->hash, &expected_len);
	assert(expected);
	assert(expected_len == digest_len);
	assert(!memcmp(digest, expected, expected_len));

	l_free(expected);
	l_free(digest);
	l_checksum_free(checksum);
	l_free(key);
}

struct cmac_aes_test {
	const char *key;
	const char *msg;
	const char *hash;
};

/* NIST Special Publication 800-38B - D.1 AES-128 - Example 1: Mlen=0 */
static const struct cmac_aes_test cmac_aes128_test1 = {
	.key	= "2b7e151628aed2a6abf7158809cf4f3c",
	.msg	= "",
	.hash	= "bb1d6929e95937287fa37d129b756746",
};

/* NIST Special Publication 800-38B - D.1 AES-128 - Example 2: Mlen=128 */
static const struct cmac_aes_test cmac_aes128_test2 = {
	.key	= "2b7e151628aed2a6abf7158809cf4f3c",
	.msg	= "6bc1bee22e409f96e93d7e117393172a",
	.hash	= "070a16b46b4d4144f79bdd9dd04a287c",
};

/* NIST Special Publication 800-38B - D.1 AES-128 - Example 3: Mlen=320 */
static const struct cmac_aes_test cmac_aes128_test3 = {
	.key	= "2b7e151628aed2a6abf7158809cf4f3c",
	.msg	= "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411",
	.hash	= "dfa66747de9ae63030ca32611497c827",
};

/* NIST Special Publication 800-38B - D.1 AES-128 - Example 4: Mlen=512 */
static const struct cmac_aes_test cmac_aes128_test4 = {
	.key	= "2b7e151628aed2a6abf7158809cf4f3c",
	.msg	= "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411e5fbc1191a0a52ef"
		  "f69f2445df4f9b17ad2b417be66c3710",
	.hash	= "51f0bebf7e3b9d92fc49741779363cfe",
};

/* NIST Special Publication 800-38B - D.2 AES-192 - Example 5: Mlen=0 */
static const struct cmac_aes_test cmac_aes192_test5 = {
	.key	= "8e73b0f7da0e6452c810f32b809079e5"
		  "62f8ead2522c6b7b",
	.msg	= "",
	.hash	= "d17ddf46adaacde531cac483de7a9367",
};

/* NIST Special Publication 800-38B - D.2 AES-192 - Example 6: Mlen=128 */
static const struct cmac_aes_test cmac_aes192_test6 = {
	.key	= "8e73b0f7da0e6452c810f32b809079e5"
		  "62f8ead2522c6b7b",
	.msg	= "6bc1bee22e409f96e93d7e117393172a",
	.hash	= "9e99a7bf31e710900662f65e617c5184",
};

/* NIST Special Publication 800-38B - D.2 AES-192 - Example 7: Mlen=320 */
static const struct cmac_aes_test cmac_aes192_test7 = {
	.key	= "8e73b0f7da0e6452c810f32b809079e5"
		  "62f8ead2522c6b7b",
	.msg	= "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411",
	.hash	= "8a1de5be2eb31aad089a82e6ee908b0e",
};

/* NIST Special Publication 800-38B - D.2 AES-192 - Example 8: Mlen=512 */
static const struct cmac_aes_test cmac_aes192_test8 = {
	.key	= "8e73b0f7da0e6452c810f32b809079e5"
		  "62f8ead2522c6b7b",
	.msg	= "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411e5fbc1191a0a52ef"
		  "f69f2445df4f9b17ad2b417be66c3710",
	.hash	= "a1d5df0eed790f794d77589659f39a11",
};

/* NIST Special Publication 800-38B - D.3 AES-256 - Example 9: Mlen=0 */
static const struct cmac_aes_test cmac_aes256_test9 = {
	.key	= "603deb1015ca71be2b73aef0857d7781"
		  "1f352c073b6108d72d9810a30914dff4",
	.msg	= "",
	.hash	= "028962f61b7bf89efc6b551f4667d983",
};

/* NIST Special Publication 800-38B - D.3 AES-256 - Example 10: Mlen=128 */
static const struct cmac_aes_test cmac_aes256_test10 = {
	.key	= "603deb1015ca71be2b73aef0857d7781"
		  "1f352c073b6108d72d9810a30914dff4",
	.msg	= "6bc1bee22e409f96e93d7e117393172a",
	.hash	= "28a7023f452e8f82bd4bf28d8c37c35c",
};

/* NIST Special Publication 800-38B - D.3 AES-256 - Example 11: Mlen=320 */
static const struct cmac_aes_test cmac_aes256_test11 = {
	.key	= "603deb1015ca71be2b73aef0857d7781"
		  "1f352c073b6108d72d9810a30914dff4",
	.msg	= "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411",
	.hash	= "aaf3d8f1de5640c232f5b169b9c911e6",
};

/* NIST Special Publication 800-38B - D.3 AES-256 - Example 12: Mlen=512 */
static const struct cmac_aes_test cmac_aes256_test12 = {
	.key	= "603deb1015ca71be2b73aef0857d7781"
		  "1f352c073b6108d72d9810a30914dff4",
	.msg	= "6bc1bee22e409f96e93d7e117393172a"
		  "ae2d8a571e03ac9c9eb76fac45af8e51"
		  "30c81c46a35ce411e5fbc1191a0a52ef"
		  "f69f2445df4f9b17ad2b417be66c3710",
	.hash	= "e1992190549f6ed5696a2c056c315410",
};

/* Bluetooth Mesh Profile - 8.1.1 s1 SALT generation function */
static const struct cmac_aes_test cmac_aes128_btmesh1 = {
	.key	= "00000000000000000000000000000000",
	.msg	= "74657374",
	.hash	= "b73cefbd641ef2ea598c2b6efb62f79c",
};

/* Bluetooth Mesh Profile - 8.1.3 k2 function (master) */
static const struct cmac_aes_test cmac_aes128_btmesh2 = {
	.key	= "4f90480c1871bfbffd16971f4d8d10b1",
	.msg	= "f7a2a44f8e8a8029064f173ddc1e2b00",
	.hash	= "2ea6467aa3378c4c545eda62935b9b86",
};

static void test_cmac_aes(const void *data)
{
	const struct cmac_aes_test *test = data;
	unsigned char *key;
	size_t key_len;
	unsigned char *msg;
	size_t msg_len;
	struct l_checksum *checksum;
	unsigned char *digest;
	size_t digest_len;
	unsigned char *expected;
	size_t expected_len;

	key = l_util_from_hexstring(test->key, &key_len);
	assert(key);

	checksum = l_checksum_new_cmac_aes(key, key_len);
	assert(checksum);

	digest_len = 16;
	digest = l_malloc(digest_len);

	if (strlen(test->msg) > 0) {
		msg = l_util_from_hexstring(test->msg, &msg_len);
		assert(msg);

		l_checksum_update(checksum, msg, msg_len);
	}

	l_checksum_get_digest(checksum, digest, digest_len);

	expected = l_util_from_hexstring(test->hash, &expected_len);
	assert(expected);
	assert(expected_len == digest_len);
	assert(!memcmp(digest, expected, expected_len));

	l_free(expected);
	l_free(digest);
	l_checksum_free(checksum);
	l_free(key);
}

#define add_sha_test(name, data) l_test_add_data_func(name, data, \
					test_sha, L_TEST_FLAG_ALLOW_FAILURE)

#define add_hmac_sha_test(name, data) l_test_add_data_func(name, data, \
					test_hmac_sha, L_TEST_FLAG_ALLOW_FAILURE)

#define add_cmac_aes_test(name, data) l_test_add_data_func(name, data, \
					test_cmac_aes, L_TEST_FLAG_ALLOW_FAILURE)

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

	add_hmac_sha_test("HMAC-MD5/1", &hmac_md5_test1);
	add_hmac_sha_test("HMAC-MD5/2", &hmac_md5_test2);
	add_hmac_sha_test("HMAC-MD5/3", &hmac_md5_test3);
	add_hmac_sha_test("HMAC-SHA-224/1", &hmac_sha224_test1);
	add_hmac_sha_test("HMAC-SHA-224/2", &hmac_sha224_test2);
	add_hmac_sha_test("HMAC-SHA-224/3", &hmac_sha224_test3);
	add_hmac_sha_test("HMAC-SHA-224/4", &hmac_sha224_test4);
	add_hmac_sha_test("HMAC-SHA-224/5", &hmac_sha224_test5);
	add_hmac_sha_test("HMAC-SHA-224/6", &hmac_sha224_test6);
	add_hmac_sha_test("HMAC-SHA-224/7", &hmac_sha224_test7);
	add_hmac_sha_test("HMAC-SHA-256/1", &hmac_sha256_test1);
	add_hmac_sha_test("HMAC-SHA-256/2", &hmac_sha256_test2);
	add_hmac_sha_test("HMAC-SHA-256/3", &hmac_sha256_test3);
	add_hmac_sha_test("HMAC-SHA-256/4", &hmac_sha256_test4);
	add_hmac_sha_test("HMAC-SHA-256/5", &hmac_sha256_test5);
	add_hmac_sha_test("HMAC-SHA-256/6", &hmac_sha256_test6);
	add_hmac_sha_test("HMAC-SHA-256/7", &hmac_sha256_test7);
	add_hmac_sha_test("HMAC-SHA-384/1", &hmac_sha384_test1);
	add_hmac_sha_test("HMAC-SHA-384/2", &hmac_sha384_test2);
	add_hmac_sha_test("HMAC-SHA-384/3", &hmac_sha384_test3);
	add_hmac_sha_test("HMAC-SHA-384/4", &hmac_sha384_test4);
	add_hmac_sha_test("HMAC-SHA-384/5", &hmac_sha384_test5);
	add_hmac_sha_test("HMAC-SHA-384/6", &hmac_sha384_test6);
	add_hmac_sha_test("HMAC-SHA-384/7", &hmac_sha384_test7);
	add_hmac_sha_test("HMAC-SHA-512/1", &hmac_sha512_test1);
	add_hmac_sha_test("HMAC-SHA-512/2", &hmac_sha512_test2);
	add_hmac_sha_test("HMAC-SHA-512/3", &hmac_sha512_test3);
	add_hmac_sha_test("HMAC-SHA-512/4", &hmac_sha512_test4);
	add_hmac_sha_test("HMAC-SHA-512/5", &hmac_sha512_test5);
	add_hmac_sha_test("HMAC-SHA-512/6", &hmac_sha512_test6);
	add_hmac_sha_test("HMAC-SHA-512/7", &hmac_sha512_test7);

	add_cmac_aes_test("CMAC-AES-128/1", &cmac_aes128_test1);
	add_cmac_aes_test("CMAC-AES-128/2", &cmac_aes128_test2);
	add_cmac_aes_test("CMAC-AES-128/3", &cmac_aes128_test3);
	add_cmac_aes_test("CMAC-AES-128/4", &cmac_aes128_test4);
	add_cmac_aes_test("CMAC-AES-192/5", &cmac_aes192_test5);
	add_cmac_aes_test("CMAC-AES-192/6", &cmac_aes192_test6);
	add_cmac_aes_test("CMAC-AES-192/7", &cmac_aes192_test7);
	add_cmac_aes_test("CMAC-AES-192/8", &cmac_aes192_test8);
	add_cmac_aes_test("CMAC-AES-256/9", &cmac_aes256_test9);
	add_cmac_aes_test("CMAC-AES-256/10", &cmac_aes256_test10);
	add_cmac_aes_test("CMAC-AES-256/11", &cmac_aes256_test11);
	add_cmac_aes_test("CMAC-AES-256/12", &cmac_aes256_test12);

	add_cmac_aes_test("CMAC-AES-128/BluetoothMesh1", &cmac_aes128_btmesh1);
	add_cmac_aes_test("CMAC-AES-128/BluetoothMesh2", &cmac_aes128_btmesh2);

	return l_test_run();
}

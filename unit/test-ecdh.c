/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "ell/ecc-private.h"

static bool use_real_getrandom = true;

bool __wrap_l_getrandom(void *buf, size_t len);
bool __real_l_getrandom(void *buf, size_t len);

bool __wrap_l_getrandom(void *buf, size_t len)
{
	static const uint8_t random_buf[] = { 0xba, 0xaf, 0x6d, 0x97, 0x71,
						0xe5, 0xda, 0xc9, 0x89, 0x6e,
						0x58, 0x18, 0x92, 0xf8, 0x55,
						0x4f, 0x29, 0xf0, 0xbd, 0x10,
						0xaf, 0x0e, 0x38, 0xb5, 0xe6,
						0x44, 0x56, 0x9d, 0x99, 0x2a,
						0x7f, 0xe2, 0x8d, 0x46, 0xb0,
						0x73, 0xcd, 0xd3, 0x6a, 0x7b,
						0xa6, 0xd3, 0xde, 0xbf, 0x38,
						0x96, 0xb7, 0xc3, 0xd4, 0xc1,
						0xcf, 0x46, 0xd4, 0x35, 0x66,
						0x04, 0x56, 0xd5, 0x61, 0x55,
						0x52, 0x20, 0xfa, 0x18, 0x97,
						0x5a, 0x7c, 0x76, 0x35, 0xd3,
						0x63, 0x3e };


	if (use_real_getrandom)
		return __real_l_getrandom(buf, len);

	if (len > sizeof(random_buf))
		return false;

	memcpy(buf, random_buf, len);

	return true;
}

static bool getrandom_precheck(const void *data)
{
	return l_getrandom_is_supported();
}

/*
 * Tests the most basic case. Generate two full public keys and use to create
 * two identical shared secrets.
 */
static void test_basic(const void *data)
{
	unsigned int group = L_PTR_TO_UINT(data);
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(group);
	size_t nbytes = l_ecc_curve_get_scalar_bytes(curve);

	struct l_ecc_scalar *private1;
	struct l_ecc_scalar *private2;

	struct l_ecc_point *public1;
	struct l_ecc_point *public2;

	struct l_ecc_scalar *secret1;
	struct l_ecc_scalar *secret2;

	assert(l_ecdh_generate_key_pair(curve, &private1, &public1));
	assert(l_ecdh_generate_key_pair(curve, &private2, &public2));

	assert(l_ecdh_generate_shared_secret(private1, public2, &secret1));
	assert(l_ecdh_generate_shared_secret(private2, public1, &secret2));

	assert(!memcmp(secret1->c, secret2->c, nbytes));

	l_ecc_scalar_free(private1);
	l_ecc_scalar_free(private2);
	l_ecc_point_free(public1);
	l_ecc_point_free(public2);
	l_ecc_scalar_free(secret1);
	l_ecc_scalar_free(secret2);
}

/*
 * Test vector from RFC 5114 - 192-bit Random ECP Group
 */
static void test_vector_p192(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(25);

	uint64_t a_sec_buf[3] = { 0xAB5BE0E249C43426ull, 0x93F59476BC142000ull,
				0x323FA3169D8E9C65ull };
	uint64_t a_pub_buf[6] = { 0xE249ABAADD870612ull, 0xE7B3D32566E2B122ull,
				0xCD46489ECFD6C105ull,
				0x8FD3844317916E9Aull, 0x4DC3D6FD11F0A26Full,
				0x68887B4877DF51DDull };

	uint64_t b_sec_buf[3] = { 0x240A0499307FCF62ull, 0x9C476EEE9AB695ABull,
				0x631F95BB4A67632Cull };
	uint64_t b_pub_buf[6] = { 0x973B500577EF13D5ull, 0x66BA21DF2EEE47F5ull,
				0x519A121680E00454ull,
				0xB30CA072C60AA57Full, 0x20875BDB10F953F6ull,
				0xFF613AB4D64CEE3Aull };

	uint64_t ss_buf[3] = { 0xE5FF4F837F54FEBEull, 0xBFE954ACDA376F05ull,
				0xAD420182633F8526ull };

	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	l_ecc_point_multiply_g(a_public, a_secret);
	l_ecc_point_multiply_g(b_public, b_secret);

	assert(!memcmp(a_public->x, a_pub_buf, 24));
	assert(!memcmp(a_public->y, a_pub_buf + 3, 24));
	assert(!memcmp(b_public->x, b_pub_buf, 24));
	assert(!memcmp(b_public->y, b_pub_buf + 3, 24));

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 24));
	assert(!memcmp(b_shared->c, ss_buf, 24));

	use_real_getrandom = true;

	l_ecc_scalar_free(a_secret);
	l_ecc_scalar_free(b_secret);
	l_ecc_point_free(a_public);
	l_ecc_point_free(b_public);
	l_ecc_scalar_free(a_shared);
	l_ecc_scalar_free(b_shared);
}

/*
 * Test vector from RFC 5114 - 224-bit Random ECP Group
 */
static void test_vector_p224(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(26);

	uint64_t a_sec_buf[4] = { 0x5C7573E22E26D37Full, 0xAE2AB9E9CB62E3BCull,
				0x288DA707BBB4F8FBull, 0xB558EB6Cull };
	uint64_t a_pub_buf[8] = { 0x833150E0A51F3EEBull, 0xB3EE5A2154367DC7ull,
				0x9F81488C304CFF5Aull, 0x49DFEF30ull,
				0xCE3D7C228D57ADB4ull, 0x7F54CF88B016B51Bull,
				0x5762C4F654C1A0C6ull, 0x4F2B5EE4ull };

	uint64_t b_sec_buf[4] = { 0xF27F85C88B5E6D18ull, 0x9F3B8E0AB3B480E9ull,
				0x3D9770E6F6A708EEull, 0xAC3B1ADDull };
	uint64_t b_pub_buf[8] = { 0xD219506DCD42A207ull, 0x32EDF10C162D0A8Aull,
				0x8D0CDE6A5599BE80ull, 0x6B3AC96Aull,
				0x3E2609C8B1618AD5ull, 0xBFE305F361AFCBB3ull,
				0xC213A7D1CA3706DEull, 0xD491BE99ull };

	uint64_t ss_buf[4] = { 0x6DC1714A4EA949FAull, 0x92F46DF2D96ECC3Bull,
				0xF46F4EDC91515690ull, 0x52272F50ull };

	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	l_ecc_point_multiply_g(a_public, a_secret);
	l_ecc_point_multiply_g(b_public, b_secret);

	assert(!memcmp(a_public->x, a_pub_buf, 28));
	assert(!memcmp(a_public->y, a_pub_buf + 4, 28));
	assert(!memcmp(b_public->x, b_pub_buf, 28));
	assert(!memcmp(b_public->y, b_pub_buf + 4, 28));

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 28));
	assert(!memcmp(b_shared->c, ss_buf, 28));

	use_real_getrandom = true;

	l_ecc_scalar_free(a_secret);
	l_ecc_scalar_free(b_secret);
	l_ecc_point_free(a_public);
	l_ecc_point_free(b_public);
	l_ecc_scalar_free(a_shared);
	l_ecc_scalar_free(b_shared);
}

/*
 * Test vector from RFC 5114 - 256-bit Random ECP Group
 */
static void test_vector_p256(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(19);

	uint64_t a_sec_buf[4] = { 0x867B7291D507A3AFull, 0x3FAF432A5ABCE59Eull,
				0xE96A8E337A128499ull, 0x814264145F2F56F2ull };
	uint64_t a_pub_buf[8] = { 0x5E8D3B4BA83AEB15ull, 0x7165BE50BC42AE4Aull,
				0xC9B5A8D4160D09E9ull, 0x2AF502F3BE8952F2ull,
				0xC0F5015ECE5EFD85ull, 0x6795BD4BFF6E6DE3ull,
				0x8681A0F9872D79D5ull, 0xEB0FAF4CA986C4D3ull };

	uint64_t b_sec_buf[4] = { 0xEE1B593761CF7F41ull, 0x19CE6BCCAD562B8Eull,
				0xDB95A200CC0AB26Aull, 0x2CE1788EC197E096ull };
	uint64_t b_pub_buf[8] = { 0xB3AB0715F6CE51B0ull, 0xAE06AAEA279FA775ull,
				0x5346E8DE6C2C8646ull, 0xB120DE4AA3649279ull,
				0x85C34DDE5708B2B6ull, 0x3727027092A84113ull,
				0xD8EC685FA3F071D8ull, 0x9F1B7EECE20D7B5Eull };

	uint64_t ss_buf[4] = { 0x7F80D21C820C2788ull,
					0xF5811E9DC8EC8EEAull,
					0x93310412D19A08F1ull,
					0xDD0F5396219D1EA3ull };

	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	l_ecc_point_multiply_g(a_public, a_secret);
	l_ecc_point_multiply_g(b_public, b_secret);

	assert(!memcmp(a_public->x, a_pub_buf, 32));
	assert(!memcmp(a_public->y, a_pub_buf + 4, 32));
	assert(!memcmp(b_public->x, b_pub_buf, 32));
	assert(!memcmp(b_public->y, b_pub_buf + 4, 32));

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 32));
	assert(!memcmp(b_shared->c, ss_buf, 32));

	use_real_getrandom = true;

	l_ecc_scalar_free(a_secret);
	l_ecc_scalar_free(b_secret);
	l_ecc_point_free(a_public);
	l_ecc_point_free(b_public);
	l_ecc_scalar_free(a_shared);
	l_ecc_scalar_free(b_shared);
}

/*
 * Test vector from RFC 5114 - 384-bit Random ECP Group
 */
static void test_vector_p384(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(20);

	uint64_t a_sec_buf[6] = { 0x86F05FEADB9376F1ull, 0xD706A90CBCB5DF29ull,
				0xD709EE7A7962A156ull, 0x5DFD8A7965571C48ull,
				0x44DD14E9FD126071ull, 0xD27335EA71664AF2ull };
	uint64_t a_pub_buf[12] = { 0x7D016FE27A8B8C66ull, 0x7E6A8EA9D1FD7742ull,
				0x0EE6B0403D627954ull, 0xE057AB62F82054D1ull,
				0xDA4C6D9074417D05ull, 0x793148F1787634D5ull,
				0xBACED214A1A1D128ull, 0x8F7A685923DE3B67ull,
				0x6B8F398BB29E4236ull, 0xC947392E94F4C3F0ull,
				0xF480F4FB4CD40504ull, 0xC6C41294331D23E6ull };
	uint64_t b_sec_buf[6] = { 0x2C4A6C768BCD94D2ull, 0x9BE52E00C194A413ull,
				0x1F80231121CCE3D3ull, 0x3B6125262C36A7DFull,
				0x9C0F00D456C2F702ull, 0x52D1791FDB4B70F8ull };
	uint64_t b_pub_buf[12] = { 0x223F12B5A1ABC120ull, 0x789D72A84865AE2Full,
				0x4ABC17647B6B9999ull, 0x5B36DB65915359B4ull,
				0xF74B8D4EFB708B3Dull, 0x5CD42AB9C41B5347ull,
				0xE035B0EDF36755DEull, 0x40BDE8723415A8ECull,
				0x0CECA16356CA9332ull, 0x8F6D5B348C0FA4D8ull,
				0xA3A8BFAC46B404BDull, 0xE171458FEAA939AAull };
	uint64_t ss_buf[6] = { 0xDE159A58028ABC0Eull, 0x27AA8A4540884C37ull,
				0x59D926EB1B8456E4ull, 0xCAE53160137D904Cull,
				0x55981B110575E0A8ull, 0x5EA1FC4AF7256D20ull };
	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	l_ecc_point_multiply_g(a_public, a_secret);
	l_ecc_point_multiply_g(b_public, b_secret);

	assert(!memcmp(a_public->x, a_pub_buf, 48));
	assert(!memcmp(a_public->y, a_pub_buf + 6, 48));
	assert(!memcmp(b_public->x, b_pub_buf, 48));
	assert(!memcmp(b_public->y, b_pub_buf + 6, 48));

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 48));
	assert(!memcmp(b_shared->c, ss_buf, 48));

	use_real_getrandom = true;

	l_ecc_scalar_free(a_secret);
	l_ecc_scalar_free(b_secret);
	l_ecc_point_free(a_public);
	l_ecc_point_free(b_public);
	l_ecc_scalar_free(a_shared);
	l_ecc_scalar_free(b_shared);
}

/*
 * Test vector from RFC 5114 - 521-bit Random ECP Group
 */
static void test_vector_p521(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_from_ike_group(21);

	uint64_t a_sec_buf[9] = { 0x16CD3C1A1FB47362ull, 0x9AF4C6C470BE2545ull,
				0x015D344DCBFEF6FBull, 0x9EE78B3FFB9B8683ull,
				0x430CC4F33459B966ull, 0xD27335EA71664AF2ull,
				0x276683B2B74277BAull, 0xF82DA825735E3D97ull,
				0x0113ull };
	uint64_t a_pub_buf[18] = { 0x3A2DBF59924FD35Cull, 0xF9A45BBDF6413D58ull,
				0xDD046EE30E3FFD20ull, 0xFD4442E689D61CB2ull,
				0x07BB0F2B26E14881ull, 0x65D90A7C60F2CEF0ull,
				0xC9DBED17889CBB97ull, 0xB34DD75721ABF8ADull,
				0x01EBull,
				0x3489B3B42A5A86A4ull, 0x233E4830587BB2EEull,
				0xB5EECAED1A5FC38Aull, 0xEDB0916D1B53C020ull,
				0x08351B2F8C4EDA94ull, 0x95ADFD153F92D749ull,
				0xD8437E558C552AE1ull, 0xB632D194C0388E22ull,
				0x00F6 };
	uint64_t b_sec_buf[9] = { 0x193DC2C9D0891B96ull, 0x72903C361B1A9DC1ull,
				0x35B01048066EBE4Full, 0x8448BCD1DC2496D4ull,
				0xC3378732AA1B2292ull, 0x52D1791FDB4B70F7ull,
				0x9F2776D28BAE6169ull, 0xE3480D8645A17D24ull,
				0x00CEull };
	uint64_t b_pub_buf[18] = { 0xC24295B8A08D0235ull, 0xB5BA4EE5E0D81510ull,
				0xE9F08B33CE7E9FEEull, 0x00430BA97C8AC6A0ull,
				0x39AE44766201AF62ull, 0x34BEEB1B6DEC8C59ull,
				0xFFFCC1A4511DB0E6ull, 0xBFAFC6E85E08D24Bull,
				0x010Eull,
				0x72915FBD4FEF2695ull, 0xBA4D2A0E60711BE5ull,
				0xD36863CC9D448F4Dull, 0x6E30A1419C18E029ull,
				0x18CF8099B9F4212Bull, 0x36719A77887EBB0Bull,
				0x372B5E7ABFEF0934ull, 0xA6EC300DF9E257B0ull,
				0x00A4ull };
	uint64_t ss_buf[9] = { 0xECA77911169C20CCull, 0xA08F5D87521BB0EBull,
				0x2F845DAFF82CEB1Dull, 0x866A0DD3E6126C9Dull,
				0xC98C7A00CDE54ED1ull, 0x4368EB5656634C7Cull,
				0xF9E4CFE2261CDE2Dull, 0xEA89621CFA46B132ull,
				0x00CDull };
	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	l_ecc_point_multiply_g(a_public, a_secret);
	l_ecc_point_multiply_g(b_public, b_secret);

	assert(!memcmp(a_public->x, a_pub_buf, 66));
	assert(!memcmp(a_public->y, a_pub_buf + 9, 66));
	assert(!memcmp(b_public->x, b_pub_buf, 66));
	assert(!memcmp(b_public->y, b_pub_buf + 9, 66));

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 66));
	assert(!memcmp(b_shared->c, ss_buf, 66));

	use_real_getrandom = true;

	l_ecc_scalar_free(a_secret);
	l_ecc_scalar_free(b_secret);
	l_ecc_point_free(a_public);
	l_ecc_point_free(b_public);
	l_ecc_scalar_free(a_shared);
	l_ecc_scalar_free(b_shared);
}

#define add_basic_test(name, group) l_test_add_data_func_precheck(name, \
					L_UINT_TO_PTR(group), \
					test_basic, getrandom_precheck, 0)

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	add_basic_test("ECDH Basic P-192", 25);
	add_basic_test("ECDH Basic P-224", 26);
	add_basic_test("ECDH Basic P-256", 19);
	add_basic_test("ECDH Basic P-384", 20);
	add_basic_test("ECDH Basic P-521", 21);

	l_test_add("ECDH Test Vector P-192", test_vector_p192, NULL);
	l_test_add("ECDH Test Vector P-224", test_vector_p224, NULL);
	l_test_add("ECDH Test Vector P-256", test_vector_p256, NULL);
	l_test_add("ECDH Test Vector P-384", test_vector_p384, NULL);
	l_test_add("ECDH Test Vector P-521", test_vector_p521, NULL);

	return l_test_run();
}

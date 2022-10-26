/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include "util.h"
#include "tls.h"
#include "cipher.h"
#include "checksum.h"
#include "cert.h"
#include "tls-private.h"

/* RFC 7919, Section A.1 */
static const uint8_t tls_ffdhe2048_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58,
	0xa2, 0xbb, 0x4a, 0x9a, 0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1,
	0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41,
	0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
	0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02,
	0xae, 0xc4, 0x61, 0x7a, 0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61,
	0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55,
	0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
	0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda,
	0xf3, 0xef, 0xe8, 0x72, 0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35,
	0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82,
	0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
	0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3,
	0xde, 0x39, 0x4d, 0xf4, 0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19,
	0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1,
	0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
	0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32,
	0xee, 0xf2, 0x81, 0x83, 0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73,
	0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83,
	0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
	0x88, 0x6b, 0x42, 0x38, 0x61, 0x28, 0x5c, 0x97, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
};

/* RFC 7919, Section A.2 */
static const uint8_t tls_ffdhe3072_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58,
	0xa2, 0xbb, 0x4a, 0x9a, 0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1,
	0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41,
	0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
	0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02,
	0xae, 0xc4, 0x61, 0x7a, 0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61,
	0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55,
	0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
	0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda,
	0xf3, 0xef, 0xe8, 0x72, 0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35,
	0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82,
	0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
	0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3,
	0xde, 0x39, 0x4d, 0xf4, 0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19,
	0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1,
	0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
	0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32,
	0xee, 0xf2, 0x81, 0x83, 0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73,
	0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83,
	0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
	0x88, 0x6b, 0x42, 0x38, 0x61, 0x1f, 0xcf, 0xdc, 0xde, 0x35, 0x5b, 0x3b,
	0x65, 0x19, 0x03, 0x5b, 0xbc, 0x34, 0xf4, 0xde, 0xf9, 0x9c, 0x02, 0x38,
	0x61, 0xb4, 0x6f, 0xc9, 0xd6, 0xe6, 0xc9, 0x07, 0x7a, 0xd9, 0x1d, 0x26,
	0x91, 0xf7, 0xf7, 0xee, 0x59, 0x8c, 0xb0, 0xfa, 0xc1, 0x86, 0xd9, 0x1c,
	0xae, 0xfe, 0x13, 0x09, 0x85, 0x13, 0x92, 0x70, 0xb4, 0x13, 0x0c, 0x93,
	0xbc, 0x43, 0x79, 0x44, 0xf4, 0xfd, 0x44, 0x52, 0xe2, 0xd7, 0x4d, 0xd3,
	0x64, 0xf2, 0xe2, 0x1e, 0x71, 0xf5, 0x4b, 0xff, 0x5c, 0xae, 0x82, 0xab,
	0x9c, 0x9d, 0xf6, 0x9e, 0xe8, 0x6d, 0x2b, 0xc5, 0x22, 0x36, 0x3a, 0x0d,
	0xab, 0xc5, 0x21, 0x97, 0x9b, 0x0d, 0xea, 0xda, 0x1d, 0xbf, 0x9a, 0x42,
	0xd5, 0xc4, 0x48, 0x4e, 0x0a, 0xbc, 0xd0, 0x6b, 0xfa, 0x53, 0xdd, 0xef,
	0x3c, 0x1b, 0x20, 0xee, 0x3f, 0xd5, 0x9d, 0x7c, 0x25, 0xe4, 0x1d, 0x2b,
	0x66, 0xc6, 0x2e, 0x37, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* RFC 7919, Section A.3 */
static const uint8_t tls_ffdhe4096_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58,
	0xa2, 0xbb, 0x4a, 0x9a, 0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1,
	0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41,
	0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
	0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02,
	0xae, 0xc4, 0x61, 0x7a, 0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61,
	0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55,
	0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
	0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda,
	0xf3, 0xef, 0xe8, 0x72, 0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35,
	0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82,
	0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
	0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3,
	0xde, 0x39, 0x4d, 0xf4, 0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19,
	0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1,
	0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
	0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32,
	0xee, 0xf2, 0x81, 0x83, 0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73,
	0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83,
	0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
	0x88, 0x6b, 0x42, 0x38, 0x61, 0x1f, 0xcf, 0xdc, 0xde, 0x35, 0x5b, 0x3b,
	0x65, 0x19, 0x03, 0x5b, 0xbc, 0x34, 0xf4, 0xde, 0xf9, 0x9c, 0x02, 0x38,
	0x61, 0xb4, 0x6f, 0xc9, 0xd6, 0xe6, 0xc9, 0x07, 0x7a, 0xd9, 0x1d, 0x26,
	0x91, 0xf7, 0xf7, 0xee, 0x59, 0x8c, 0xb0, 0xfa, 0xc1, 0x86, 0xd9, 0x1c,
	0xae, 0xfe, 0x13, 0x09, 0x85, 0x13, 0x92, 0x70, 0xb4, 0x13, 0x0c, 0x93,
	0xbc, 0x43, 0x79, 0x44, 0xf4, 0xfd, 0x44, 0x52, 0xe2, 0xd7, 0x4d, 0xd3,
	0x64, 0xf2, 0xe2, 0x1e, 0x71, 0xf5, 0x4b, 0xff, 0x5c, 0xae, 0x82, 0xab,
	0x9c, 0x9d, 0xf6, 0x9e, 0xe8, 0x6d, 0x2b, 0xc5, 0x22, 0x36, 0x3a, 0x0d,
	0xab, 0xc5, 0x21, 0x97, 0x9b, 0x0d, 0xea, 0xda, 0x1d, 0xbf, 0x9a, 0x42,
	0xd5, 0xc4, 0x48, 0x4e, 0x0a, 0xbc, 0xd0, 0x6b, 0xfa, 0x53, 0xdd, 0xef,
	0x3c, 0x1b, 0x20, 0xee, 0x3f, 0xd5, 0x9d, 0x7c, 0x25, 0xe4, 0x1d, 0x2b,
	0x66, 0x9e, 0x1e, 0xf1, 0x6e, 0x6f, 0x52, 0xc3, 0x16, 0x4d, 0xf4, 0xfb,
	0x79, 0x30, 0xe9, 0xe4, 0xe5, 0x88, 0x57, 0xb6, 0xac, 0x7d, 0x5f, 0x42,
	0xd6, 0x9f, 0x6d, 0x18, 0x77, 0x63, 0xcf, 0x1d, 0x55, 0x03, 0x40, 0x04,
	0x87, 0xf5, 0x5b, 0xa5, 0x7e, 0x31, 0xcc, 0x7a, 0x71, 0x35, 0xc8, 0x86,
	0xef, 0xb4, 0x31, 0x8a, 0xed, 0x6a, 0x1e, 0x01, 0x2d, 0x9e, 0x68, 0x32,
	0xa9, 0x07, 0x60, 0x0a, 0x91, 0x81, 0x30, 0xc4, 0x6d, 0xc7, 0x78, 0xf9,
	0x71, 0xad, 0x00, 0x38, 0x09, 0x29, 0x99, 0xa3, 0x33, 0xcb, 0x8b, 0x7a,
	0x1a, 0x1d, 0xb9, 0x3d, 0x71, 0x40, 0x00, 0x3c, 0x2a, 0x4e, 0xce, 0xa9,
	0xf9, 0x8d, 0x0a, 0xcc, 0x0a, 0x82, 0x91, 0xcd, 0xce, 0xc9, 0x7d, 0xcf,
	0x8e, 0xc9, 0xb5, 0x5a, 0x7f, 0x88, 0xa4, 0x6b, 0x4d, 0xb5, 0xa8, 0x51,
	0xf4, 0x41, 0x82, 0xe1, 0xc6, 0x8a, 0x00, 0x7e, 0x5e, 0x65, 0x5f, 0x6a,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* RFC 7919, Section A.4 */
static const uint8_t tls_ffdhe6144_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58,
	0xa2, 0xbb, 0x4a, 0x9a, 0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1,
	0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41,
	0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
	0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02,
	0xae, 0xc4, 0x61, 0x7a, 0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61,
	0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55,
	0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
	0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda,
	0xf3, 0xef, 0xe8, 0x72, 0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35,
	0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82,
	0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
	0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3,
	0xde, 0x39, 0x4d, 0xf4, 0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19,
	0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1,
	0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
	0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32,
	0xee, 0xf2, 0x81, 0x83, 0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73,
	0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83,
	0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
	0x88, 0x6b, 0x42, 0x38, 0x61, 0x1f, 0xcf, 0xdc, 0xde, 0x35, 0x5b, 0x3b,
	0x65, 0x19, 0x03, 0x5b, 0xbc, 0x34, 0xf4, 0xde, 0xf9, 0x9c, 0x02, 0x38,
	0x61, 0xb4, 0x6f, 0xc9, 0xd6, 0xe6, 0xc9, 0x07, 0x7a, 0xd9, 0x1d, 0x26,
	0x91, 0xf7, 0xf7, 0xee, 0x59, 0x8c, 0xb0, 0xfa, 0xc1, 0x86, 0xd9, 0x1c,
	0xae, 0xfe, 0x13, 0x09, 0x85, 0x13, 0x92, 0x70, 0xb4, 0x13, 0x0c, 0x93,
	0xbc, 0x43, 0x79, 0x44, 0xf4, 0xfd, 0x44, 0x52, 0xe2, 0xd7, 0x4d, 0xd3,
	0x64, 0xf2, 0xe2, 0x1e, 0x71, 0xf5, 0x4b, 0xff, 0x5c, 0xae, 0x82, 0xab,
	0x9c, 0x9d, 0xf6, 0x9e, 0xe8, 0x6d, 0x2b, 0xc5, 0x22, 0x36, 0x3a, 0x0d,
	0xab, 0xc5, 0x21, 0x97, 0x9b, 0x0d, 0xea, 0xda, 0x1d, 0xbf, 0x9a, 0x42,
	0xd5, 0xc4, 0x48, 0x4e, 0x0a, 0xbc, 0xd0, 0x6b, 0xfa, 0x53, 0xdd, 0xef,
	0x3c, 0x1b, 0x20, 0xee, 0x3f, 0xd5, 0x9d, 0x7c, 0x25, 0xe4, 0x1d, 0x2b,
	0x66, 0x9e, 0x1e, 0xf1, 0x6e, 0x6f, 0x52, 0xc3, 0x16, 0x4d, 0xf4, 0xfb,
	0x79, 0x30, 0xe9, 0xe4, 0xe5, 0x88, 0x57, 0xb6, 0xac, 0x7d, 0x5f, 0x42,
	0xd6, 0x9f, 0x6d, 0x18, 0x77, 0x63, 0xcf, 0x1d, 0x55, 0x03, 0x40, 0x04,
	0x87, 0xf5, 0x5b, 0xa5, 0x7e, 0x31, 0xcc, 0x7a, 0x71, 0x35, 0xc8, 0x86,
	0xef, 0xb4, 0x31, 0x8a, 0xed, 0x6a, 0x1e, 0x01, 0x2d, 0x9e, 0x68, 0x32,
	0xa9, 0x07, 0x60, 0x0a, 0x91, 0x81, 0x30, 0xc4, 0x6d, 0xc7, 0x78, 0xf9,
	0x71, 0xad, 0x00, 0x38, 0x09, 0x29, 0x99, 0xa3, 0x33, 0xcb, 0x8b, 0x7a,
	0x1a, 0x1d, 0xb9, 0x3d, 0x71, 0x40, 0x00, 0x3c, 0x2a, 0x4e, 0xce, 0xa9,
	0xf9, 0x8d, 0x0a, 0xcc, 0x0a, 0x82, 0x91, 0xcd, 0xce, 0xc9, 0x7d, 0xcf,
	0x8e, 0xc9, 0xb5, 0x5a, 0x7f, 0x88, 0xa4, 0x6b, 0x4d, 0xb5, 0xa8, 0x51,
	0xf4, 0x41, 0x82, 0xe1, 0xc6, 0x8a, 0x00, 0x7e, 0x5e, 0x0d, 0xd9, 0x02,
	0x0b, 0xfd, 0x64, 0xb6, 0x45, 0x03, 0x6c, 0x7a, 0x4e, 0x67, 0x7d, 0x2c,
	0x38, 0x53, 0x2a, 0x3a, 0x23, 0xba, 0x44, 0x42, 0xca, 0xf5, 0x3e, 0xa6,
	0x3b, 0xb4, 0x54, 0x32, 0x9b, 0x76, 0x24, 0xc8, 0x91, 0x7b, 0xdd, 0x64,
	0xb1, 0xc0, 0xfd, 0x4c, 0xb3, 0x8e, 0x8c, 0x33, 0x4c, 0x70, 0x1c, 0x3a,
	0xcd, 0xad, 0x06, 0x57, 0xfc, 0xcf, 0xec, 0x71, 0x9b, 0x1f, 0x5c, 0x3e,
	0x4e, 0x46, 0x04, 0x1f, 0x38, 0x81, 0x47, 0xfb, 0x4c, 0xfd, 0xb4, 0x77,
	0xa5, 0x24, 0x71, 0xf7, 0xa9, 0xa9, 0x69, 0x10, 0xb8, 0x55, 0x32, 0x2e,
	0xdb, 0x63, 0x40, 0xd8, 0xa0, 0x0e, 0xf0, 0x92, 0x35, 0x05, 0x11, 0xe3,
	0x0a, 0xbe, 0xc1, 0xff, 0xf9, 0xe3, 0xa2, 0x6e, 0x7f, 0xb2, 0x9f, 0x8c,
	0x18, 0x30, 0x23, 0xc3, 0x58, 0x7e, 0x38, 0xda, 0x00, 0x77, 0xd9, 0xb4,
	0x76, 0x3e, 0x4e, 0x4b, 0x94, 0xb2, 0xbb, 0xc1, 0x94, 0xc6, 0x65, 0x1e,
	0x77, 0xca, 0xf9, 0x92, 0xee, 0xaa, 0xc0, 0x23, 0x2a, 0x28, 0x1b, 0xf6,
	0xb3, 0xa7, 0x39, 0xc1, 0x22, 0x61, 0x16, 0x82, 0x0a, 0xe8, 0xdb, 0x58,
	0x47, 0xa6, 0x7c, 0xbe, 0xf9, 0xc9, 0x09, 0x1b, 0x46, 0x2d, 0x53, 0x8c,
	0xd7, 0x2b, 0x03, 0x74, 0x6a, 0xe7, 0x7f, 0x5e, 0x62, 0x29, 0x2c, 0x31,
	0x15, 0x62, 0xa8, 0x46, 0x50, 0x5d, 0xc8, 0x2d, 0xb8, 0x54, 0x33, 0x8a,
	0xe4, 0x9f, 0x52, 0x35, 0xc9, 0x5b, 0x91, 0x17, 0x8c, 0xcf, 0x2d, 0xd5,
	0xca, 0xce, 0xf4, 0x03, 0xec, 0x9d, 0x18, 0x10, 0xc6, 0x27, 0x2b, 0x04,
	0x5b, 0x3b, 0x71, 0xf9, 0xdc, 0x6b, 0x80, 0xd6, 0x3f, 0xdd, 0x4a, 0x8e,
	0x9a, 0xdb, 0x1e, 0x69, 0x62, 0xa6, 0x95, 0x26, 0xd4, 0x31, 0x61, 0xc1,
	0xa4, 0x1d, 0x57, 0x0d, 0x79, 0x38, 0xda, 0xd4, 0xa4, 0x0e, 0x32, 0x9c,
	0xd0, 0xe4, 0x0e, 0x65, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* RFC 7919, Section A.5 */
static const uint8_t tls_ffdhe8192_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xad, 0xf8, 0x54, 0x58,
	0xa2, 0xbb, 0x4a, 0x9a, 0xaf, 0xdc, 0x56, 0x20, 0x27, 0x3d, 0x3c, 0xf1,
	0xd8, 0xb9, 0xc5, 0x83, 0xce, 0x2d, 0x36, 0x95, 0xa9, 0xe1, 0x36, 0x41,
	0x14, 0x64, 0x33, 0xfb, 0xcc, 0x93, 0x9d, 0xce, 0x24, 0x9b, 0x3e, 0xf9,
	0x7d, 0x2f, 0xe3, 0x63, 0x63, 0x0c, 0x75, 0xd8, 0xf6, 0x81, 0xb2, 0x02,
	0xae, 0xc4, 0x61, 0x7a, 0xd3, 0xdf, 0x1e, 0xd5, 0xd5, 0xfd, 0x65, 0x61,
	0x24, 0x33, 0xf5, 0x1f, 0x5f, 0x06, 0x6e, 0xd0, 0x85, 0x63, 0x65, 0x55,
	0x3d, 0xed, 0x1a, 0xf3, 0xb5, 0x57, 0x13, 0x5e, 0x7f, 0x57, 0xc9, 0x35,
	0x98, 0x4f, 0x0c, 0x70, 0xe0, 0xe6, 0x8b, 0x77, 0xe2, 0xa6, 0x89, 0xda,
	0xf3, 0xef, 0xe8, 0x72, 0x1d, 0xf1, 0x58, 0xa1, 0x36, 0xad, 0xe7, 0x35,
	0x30, 0xac, 0xca, 0x4f, 0x48, 0x3a, 0x79, 0x7a, 0xbc, 0x0a, 0xb1, 0x82,
	0xb3, 0x24, 0xfb, 0x61, 0xd1, 0x08, 0xa9, 0x4b, 0xb2, 0xc8, 0xe3, 0xfb,
	0xb9, 0x6a, 0xda, 0xb7, 0x60, 0xd7, 0xf4, 0x68, 0x1d, 0x4f, 0x42, 0xa3,
	0xde, 0x39, 0x4d, 0xf4, 0xae, 0x56, 0xed, 0xe7, 0x63, 0x72, 0xbb, 0x19,
	0x0b, 0x07, 0xa7, 0xc8, 0xee, 0x0a, 0x6d, 0x70, 0x9e, 0x02, 0xfc, 0xe1,
	0xcd, 0xf7, 0xe2, 0xec, 0xc0, 0x34, 0x04, 0xcd, 0x28, 0x34, 0x2f, 0x61,
	0x91, 0x72, 0xfe, 0x9c, 0xe9, 0x85, 0x83, 0xff, 0x8e, 0x4f, 0x12, 0x32,
	0xee, 0xf2, 0x81, 0x83, 0xc3, 0xfe, 0x3b, 0x1b, 0x4c, 0x6f, 0xad, 0x73,
	0x3b, 0xb5, 0xfc, 0xbc, 0x2e, 0xc2, 0x20, 0x05, 0xc5, 0x8e, 0xf1, 0x83,
	0x7d, 0x16, 0x83, 0xb2, 0xc6, 0xf3, 0x4a, 0x26, 0xc1, 0xb2, 0xef, 0xfa,
	0x88, 0x6b, 0x42, 0x38, 0x61, 0x1f, 0xcf, 0xdc, 0xde, 0x35, 0x5b, 0x3b,
	0x65, 0x19, 0x03, 0x5b, 0xbc, 0x34, 0xf4, 0xde, 0xf9, 0x9c, 0x02, 0x38,
	0x61, 0xb4, 0x6f, 0xc9, 0xd6, 0xe6, 0xc9, 0x07, 0x7a, 0xd9, 0x1d, 0x26,
	0x91, 0xf7, 0xf7, 0xee, 0x59, 0x8c, 0xb0, 0xfa, 0xc1, 0x86, 0xd9, 0x1c,
	0xae, 0xfe, 0x13, 0x09, 0x85, 0x13, 0x92, 0x70, 0xb4, 0x13, 0x0c, 0x93,
	0xbc, 0x43, 0x79, 0x44, 0xf4, 0xfd, 0x44, 0x52, 0xe2, 0xd7, 0x4d, 0xd3,
	0x64, 0xf2, 0xe2, 0x1e, 0x71, 0xf5, 0x4b, 0xff, 0x5c, 0xae, 0x82, 0xab,
	0x9c, 0x9d, 0xf6, 0x9e, 0xe8, 0x6d, 0x2b, 0xc5, 0x22, 0x36, 0x3a, 0x0d,
	0xab, 0xc5, 0x21, 0x97, 0x9b, 0x0d, 0xea, 0xda, 0x1d, 0xbf, 0x9a, 0x42,
	0xd5, 0xc4, 0x48, 0x4e, 0x0a, 0xbc, 0xd0, 0x6b, 0xfa, 0x53, 0xdd, 0xef,
	0x3c, 0x1b, 0x20, 0xee, 0x3f, 0xd5, 0x9d, 0x7c, 0x25, 0xe4, 0x1d, 0x2b,
	0x66, 0x9e, 0x1e, 0xf1, 0x6e, 0x6f, 0x52, 0xc3, 0x16, 0x4d, 0xf4, 0xfb,
	0x79, 0x30, 0xe9, 0xe4, 0xe5, 0x88, 0x57, 0xb6, 0xac, 0x7d, 0x5f, 0x42,
	0xd6, 0x9f, 0x6d, 0x18, 0x77, 0x63, 0xcf, 0x1d, 0x55, 0x03, 0x40, 0x04,
	0x87, 0xf5, 0x5b, 0xa5, 0x7e, 0x31, 0xcc, 0x7a, 0x71, 0x35, 0xc8, 0x86,
	0xef, 0xb4, 0x31, 0x8a, 0xed, 0x6a, 0x1e, 0x01, 0x2d, 0x9e, 0x68, 0x32,
	0xa9, 0x07, 0x60, 0x0a, 0x91, 0x81, 0x30, 0xc4, 0x6d, 0xc7, 0x78, 0xf9,
	0x71, 0xad, 0x00, 0x38, 0x09, 0x29, 0x99, 0xa3, 0x33, 0xcb, 0x8b, 0x7a,
	0x1a, 0x1d, 0xb9, 0x3d, 0x71, 0x40, 0x00, 0x3c, 0x2a, 0x4e, 0xce, 0xa9,
	0xf9, 0x8d, 0x0a, 0xcc, 0x0a, 0x82, 0x91, 0xcd, 0xce, 0xc9, 0x7d, 0xcf,
	0x8e, 0xc9, 0xb5, 0x5a, 0x7f, 0x88, 0xa4, 0x6b, 0x4d, 0xb5, 0xa8, 0x51,
	0xf4, 0x41, 0x82, 0xe1, 0xc6, 0x8a, 0x00, 0x7e, 0x5e, 0x0d, 0xd9, 0x02,
	0x0b, 0xfd, 0x64, 0xb6, 0x45, 0x03, 0x6c, 0x7a, 0x4e, 0x67, 0x7d, 0x2c,
	0x38, 0x53, 0x2a, 0x3a, 0x23, 0xba, 0x44, 0x42, 0xca, 0xf5, 0x3e, 0xa6,
	0x3b, 0xb4, 0x54, 0x32, 0x9b, 0x76, 0x24, 0xc8, 0x91, 0x7b, 0xdd, 0x64,
	0xb1, 0xc0, 0xfd, 0x4c, 0xb3, 0x8e, 0x8c, 0x33, 0x4c, 0x70, 0x1c, 0x3a,
	0xcd, 0xad, 0x06, 0x57, 0xfc, 0xcf, 0xec, 0x71, 0x9b, 0x1f, 0x5c, 0x3e,
	0x4e, 0x46, 0x04, 0x1f, 0x38, 0x81, 0x47, 0xfb, 0x4c, 0xfd, 0xb4, 0x77,
	0xa5, 0x24, 0x71, 0xf7, 0xa9, 0xa9, 0x69, 0x10, 0xb8, 0x55, 0x32, 0x2e,
	0xdb, 0x63, 0x40, 0xd8, 0xa0, 0x0e, 0xf0, 0x92, 0x35, 0x05, 0x11, 0xe3,
	0x0a, 0xbe, 0xc1, 0xff, 0xf9, 0xe3, 0xa2, 0x6e, 0x7f, 0xb2, 0x9f, 0x8c,
	0x18, 0x30, 0x23, 0xc3, 0x58, 0x7e, 0x38, 0xda, 0x00, 0x77, 0xd9, 0xb4,
	0x76, 0x3e, 0x4e, 0x4b, 0x94, 0xb2, 0xbb, 0xc1, 0x94, 0xc6, 0x65, 0x1e,
	0x77, 0xca, 0xf9, 0x92, 0xee, 0xaa, 0xc0, 0x23, 0x2a, 0x28, 0x1b, 0xf6,
	0xb3, 0xa7, 0x39, 0xc1, 0x22, 0x61, 0x16, 0x82, 0x0a, 0xe8, 0xdb, 0x58,
	0x47, 0xa6, 0x7c, 0xbe, 0xf9, 0xc9, 0x09, 0x1b, 0x46, 0x2d, 0x53, 0x8c,
	0xd7, 0x2b, 0x03, 0x74, 0x6a, 0xe7, 0x7f, 0x5e, 0x62, 0x29, 0x2c, 0x31,
	0x15, 0x62, 0xa8, 0x46, 0x50, 0x5d, 0xc8, 0x2d, 0xb8, 0x54, 0x33, 0x8a,
	0xe4, 0x9f, 0x52, 0x35, 0xc9, 0x5b, 0x91, 0x17, 0x8c, 0xcf, 0x2d, 0xd5,
	0xca, 0xce, 0xf4, 0x03, 0xec, 0x9d, 0x18, 0x10, 0xc6, 0x27, 0x2b, 0x04,
	0x5b, 0x3b, 0x71, 0xf9, 0xdc, 0x6b, 0x80, 0xd6, 0x3f, 0xdd, 0x4a, 0x8e,
	0x9a, 0xdb, 0x1e, 0x69, 0x62, 0xa6, 0x95, 0x26, 0xd4, 0x31, 0x61, 0xc1,
	0xa4, 0x1d, 0x57, 0x0d, 0x79, 0x38, 0xda, 0xd4, 0xa4, 0x0e, 0x32, 0x9c,
	0xcf, 0xf4, 0x6a, 0xaa, 0x36, 0xad, 0x00, 0x4c, 0xf6, 0x00, 0xc8, 0x38,
	0x1e, 0x42, 0x5a, 0x31, 0xd9, 0x51, 0xae, 0x64, 0xfd, 0xb2, 0x3f, 0xce,
	0xc9, 0x50, 0x9d, 0x43, 0x68, 0x7f, 0xeb, 0x69, 0xed, 0xd1, 0xcc, 0x5e,
	0x0b, 0x8c, 0xc3, 0xbd, 0xf6, 0x4b, 0x10, 0xef, 0x86, 0xb6, 0x31, 0x42,
	0xa3, 0xab, 0x88, 0x29, 0x55, 0x5b, 0x2f, 0x74, 0x7c, 0x93, 0x26, 0x65,
	0xcb, 0x2c, 0x0f, 0x1c, 0xc0, 0x1b, 0xd7, 0x02, 0x29, 0x38, 0x88, 0x39,
	0xd2, 0xaf, 0x05, 0xe4, 0x54, 0x50, 0x4a, 0xc7, 0x8b, 0x75, 0x82, 0x82,
	0x28, 0x46, 0xc0, 0xba, 0x35, 0xc3, 0x5f, 0x5c, 0x59, 0x16, 0x0c, 0xc0,
	0x46, 0xfd, 0x82, 0x51, 0x54, 0x1f, 0xc6, 0x8c, 0x9c, 0x86, 0xb0, 0x22,
	0xbb, 0x70, 0x99, 0x87, 0x6a, 0x46, 0x0e, 0x74, 0x51, 0xa8, 0xa9, 0x31,
	0x09, 0x70, 0x3f, 0xee, 0x1c, 0x21, 0x7e, 0x6c, 0x38, 0x26, 0xe5, 0x2c,
	0x51, 0xaa, 0x69, 0x1e, 0x0e, 0x42, 0x3c, 0xfc, 0x99, 0xe9, 0xe3, 0x16,
	0x50, 0xc1, 0x21, 0x7b, 0x62, 0x48, 0x16, 0xcd, 0xad, 0x9a, 0x95, 0xf9,
	0xd5, 0xb8, 0x01, 0x94, 0x88, 0xd9, 0xc0, 0xa0, 0xa1, 0xfe, 0x30, 0x75,
	0xa5, 0x77, 0xe2, 0x31, 0x83, 0xf8, 0x1d, 0x4a, 0x3f, 0x2f, 0xa4, 0x57,
	0x1e, 0xfc, 0x8c, 0xe0, 0xba, 0x8a, 0x4f, 0xe8, 0xb6, 0x85, 0x5d, 0xfe,
	0x72, 0xb0, 0xa6, 0x6e, 0xde, 0xd2, 0xfb, 0xab, 0xfb, 0xe5, 0x8a, 0x30,
	0xfa, 0xfa, 0xbe, 0x1c, 0x5d, 0x71, 0xa8, 0x7e, 0x2f, 0x74, 0x1e, 0xf8,
	0xc1, 0xfe, 0x86, 0xfe, 0xa6, 0xbb, 0xfd, 0xe5, 0x30, 0x67, 0x7f, 0x0d,
	0x97, 0xd1, 0x1d, 0x49, 0xf7, 0xa8, 0x44, 0x3d, 0x08, 0x22, 0xe5, 0x06,
	0xa9, 0xf4, 0x61, 0x4e, 0x01, 0x1e, 0x2a, 0x94, 0x83, 0x8f, 0xf8, 0x8c,
	0xd6, 0x8c, 0x8b, 0xb7, 0xc5, 0xc6, 0x42, 0x4c, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
};

/* RFC 3526, Section 3 */
static const uint8_t tls_dh14_prime[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
	0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
	0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
	0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
	0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
	0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
	0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
	0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
	0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
	0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
	0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
	0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
	0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
	0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
	0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
	0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
	0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
	0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
	0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
	0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
	0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xac, 0xaa, 0x68, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
};

static const struct tls_named_group tls_group_pref[] = {
	{ "secp256r1", 23, TLS_GROUP_TYPE_EC },
	{ "secp384r1", 24, TLS_GROUP_TYPE_EC },
	{
		"ffdhe2048", 256, TLS_GROUP_TYPE_FF,
		.ff = {
			.prime = tls_ffdhe2048_prime,
			.prime_len = sizeof(tls_ffdhe2048_prime),
			.generator = 2,
		},
	},
	{
		"ffdhe3072", 257, TLS_GROUP_TYPE_FF,
		.ff = {
			.prime = tls_ffdhe3072_prime,
			.prime_len = sizeof(tls_ffdhe3072_prime),
			.generator = 2,
		},
	},
	{
		"ffdhe4096", 258, TLS_GROUP_TYPE_FF,
		.ff = {
			.prime = tls_ffdhe4096_prime,
			.prime_len = sizeof(tls_ffdhe4096_prime),
			.generator = 2,
		},
	},
	{
		"ffdhe6144", 259, TLS_GROUP_TYPE_FF,
		.ff = {
			.prime = tls_ffdhe6144_prime,
			.prime_len = sizeof(tls_ffdhe6144_prime),
			.generator = 2,
		},
	},
	{
		"ffdhe8192", 260, TLS_GROUP_TYPE_FF,
		.ff = {
			.prime = tls_ffdhe8192_prime,
			.prime_len = sizeof(tls_ffdhe8192_prime),
			.generator = 2,
		},
	},
};

/*
 * For now hardcode a default group for non-RFC7919 clients - same group
 * as some other TLS servers use, which is actually a downside because the
 * more common the group parameters are the less secure they are assumed
 * to be, but it is also a test that the group is sufficiently good.
 *
 * Eventually we need to make this configurable so that a unique
 * likely-prime number generated by either 'openssl dhparam' or
 * 'ssh-keygen -G' can be set, or parse /etc/ssh/moduli to select
 * a random pre-generated FFDH group each time.
 */
static const struct tls_named_group tls_default_ffdh_group = {
	"RFC3526/Oakley Group 14", 0, TLS_GROUP_TYPE_FF,
	.ff = {
		.prime = tls_dh14_prime,
		.prime_len = sizeof(tls_dh14_prime),
		.generator = 2,
	},
};

/* RFC 8422, Section 5.1 + RFC 7919 */
static ssize_t tls_elliptic_curves_client_write(struct l_tls *tls,
						uint8_t *buf, size_t len)
{
	uint8_t *ptr = buf;
	unsigned int i;

	if (len < 2 + L_ARRAY_SIZE(tls_group_pref) * 2)
		return -ENOMEM;

	l_put_be16(L_ARRAY_SIZE(tls_group_pref) * 2, ptr);
	ptr += 2;

	for (i = 0; i < L_ARRAY_SIZE(tls_group_pref); i++) {
		l_put_be16(tls_group_pref[i].id, ptr);
		ptr += 2;
	}

	return ptr - buf;
}

static bool tls_elliptic_curves_client_handle(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	bool ffdh_offered = false;

	if (len < 2)
		return false;

	if (l_get_be16(buf) != len - 2 || (len & 1))
		return false;

	buf += 2;
	len -= 2;

	/*
	 * We select one group for DH and one group for ECDH and we'll
	 * let the cipher suite selection logic decide which one is actually
	 * used.  It will take into account the client's cipher suite
	 * preference but it could just as well look at the strengths of
	 * the groups chosen.  This is not done for simplicity but RFC 7919
	 * suggests the Supported Groups should actually overrule the
	 * cipher suite preference list in case of a conflict:
	 * "A server that encounters such a contradiction when selecting
	 * between an ECDHE or FFDHE key exchange mechanism while trying
	 * to respect client preferences SHOULD give priority to the
	 * Supported Groups extension (...) but MAY resolve the
	 * contradiction any way it sees fit."
	 *
	 * Not implemented: "If a non-anonymous FFDHE cipher suite is
	 * selected and the TLS client has used this extension to offer
	 * an FFDHE group of comparable or greater strength than the server's
	 * public key, the server SHOULD select an FFDHE group at least
	 * as strong as the server's public key."
	 */

	while (len) {
		unsigned int i;
		uint16_t id;
		const struct tls_named_group *group = NULL;

		id = l_get_be16(buf);
		buf += 2;
		len -= 2;

		if (id >> 8 == 1)	/* RFC 7919 ids */
			ffdh_offered = true;

		for (i = 0; i < L_ARRAY_SIZE(tls_group_pref); i++)
			if (tls_group_pref[i].id == id) {
				group = &tls_group_pref[i];
				break;
			}

		if (!group)
			continue;

		switch (group->type) {
		case TLS_GROUP_TYPE_EC:
			if (!tls->negotiated_curve)
				tls->negotiated_curve = group;

			break;
		case TLS_GROUP_TYPE_FF:
			if (!tls->negotiated_ff_group)
				tls->negotiated_ff_group = group;

			break;
		}
	}

	/*
	 * Note we need to treat DH slightly differently from ECDH groups
	 * here because the extension is defined in RFC 8422 and if the
	 * client offers no elliptic curves we can't use ECDH at all:
	 * "If a server (...) is unable to complete the ECC handshake while
	 * restricting itself to the enumerated curves (...), it MUST NOT
	 * negotiate the use of an ECC cipher suite.  Depending on what
	 * other cipher suites are proposed by the client and supported by
	 * the server, this may result in a fatal handshake failure alert
	 * due to the lack of common cipher suites."
	 *
	 * On the other hand if the client offers no FFDH groups we can
	 * only assume the client is okay with us picking a group.  Note
	 * the "includes any FFDHE group" part in RFC 7919 Section 4:
	 * "If a compatible TLS server receives a Supported Groups
	 * extension from a client that includes any FFDHE group (i.e.,
	 * any codepoint between 256 and 511, inclusive, even if unknown
	 * to the server), and if none of the client-proposed FFDHE groups
	 * are known and acceptable to the server, then the server MUST
	 * NOT select an FFDHE cipher suite."
	 */

	if (tls->negotiated_curve)
		TLS_DEBUG("Negotiated %s", tls->negotiated_curve->name);
	else
		TLS_DEBUG("non-fatal: No common supported elliptic curves "
				"for ECDHE");

	if (tls->negotiated_ff_group)
		TLS_DEBUG("Negotiated %s", tls->negotiated_ff_group->name);
	else if (ffdh_offered)
		TLS_DEBUG("non-fatal: No common supported finite-field groups "
				"for DHE");
	else
		tls->negotiated_ff_group = &tls_default_ffdh_group;

	return true;
}

static bool tls_elliptic_curves_client_absent(struct l_tls *tls)
{
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(tls_group_pref); i++)
		if (tls_group_pref[i].type == TLS_GROUP_TYPE_EC) {
			tls->negotiated_curve = &tls_group_pref[i];
			break;
		}

	tls->negotiated_ff_group = &tls_default_ffdh_group;

	return true;
}

static bool tls_ec_point_formats_client_handle(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	if (len < 2)
		return false;

	if (buf[0] != len - 1)
		return false;

	if (!memchr(buf + 1, 0, len - 1)) {
		TLS_DEBUG("Uncompressed point format missing");
		return false;
	}

	return true;
}

/*
 * For compatibility with clients respond to a valid Client Hello Supported
 * Point Formats extension with the hardcoded confirmation that we do
 * support the single valid point format.  As a client we never send this
 * extension so we never have to handle a server response to it either.
 */
static ssize_t tls_ec_point_formats_server_write(struct l_tls *tls,
						uint8_t *buf, size_t len)
{
	if (len < 2)
		return -ENOMEM;

	buf[0] = 0x01;	/* ec_point_format_list length */
	buf[1] = 0x00;	/* uncompressed */
	return 2;
}

/*
 * This is used to append the list of signature algorithm and hash type
 * combinations we support to the Signature Algorithms client hello
 * extension (on the client) and the Certificate Request message (on the
 * server).  In both cases we need to list the algorithms we support for
 * two use cases: certificate chain verification and signing/verifying
 * Server Key Exchange params (server->client) or Certificate Verify
 * data (client->server).
 *
 * For the server side RFC 5462, Section 7.4.1.4.1 says:
 * "If the client [...] is willing to use them for verifying
 * messages sent by the server, i.e., server certificates and
 * server key exchange [...] it MUST send the
 * signature_algorithms extension, listing the algorithms it
 * is willing to accept."
 *
 * As for the certificate chains we mostly rely on the kernel to do
 * this so when we receive the list we do not currently verify the
 * that the whole chain uses only algorithms from the list on either
 * side (TODO). But we know that the chain verification in the kernel
 * can use a superset of the hash algorithms l_checksum supports.
 * For the Server Key Exchange and Certificate Verify signatures we
 * use l_checksum but we need to map the TLS-specific hash IDs to
 * enum l_checksum_type using the tls_handshake_hash_data list in
 * signature->sign() and signature->verify(), so we use
 * tls_handshake_hash_data as the definitive list of allowed hash
 * algorithms.
 *
 * Our supported signature algorithms can work with any hash type so we
 * basically have to send all possible combinations of the signature
 * algorithm IDs from the supported cipher suites (except anonymous)
 * with the hash algorithms we can use for signature verification,
 * i.e. those in the tls_handshake_hash_data table.
 */
ssize_t tls_write_signature_algorithms(struct l_tls *tls,
					uint8_t *buf, size_t len)
{
	uint8_t *ptr = buf;
	unsigned int i, j;
	struct tls_cipher_suite **suite;
	uint8_t sig_alg_ids[16];
	uint8_t hash_ids[16];
	unsigned int sig_alg_cnt = 0;
	unsigned int hash_cnt = 0;

	for (suite = tls->cipher_suite_pref_list; *suite; suite++) {
		uint8_t id;

		if (!(*suite)->signature)
			continue;

		id = (*suite)->signature->id;

		if (memchr(sig_alg_ids, id, sig_alg_cnt))
			continue;

		if (!tls_cipher_suite_is_compatible(tls, *suite, NULL))
			continue;

		if (sig_alg_cnt >= sizeof(sig_alg_ids))
			return -ENOMEM;

		sig_alg_ids[sig_alg_cnt++] = id;
	}

	for (i = 0; i < __HANDSHAKE_HASH_COUNT; i++) {
		const struct tls_hash_algorithm *hash =
			&tls_handshake_hash_data[i];
		bool supported;

		/*
		 * The hash types in the Signature Algorithms extension are
		 * all supported hashes but the ones in the Certificate
		 * Request (server->client) must be in the set for which we
		 * maintain handshake message hashes because that is going
		 * to be used in Certificate Verify.
		 */
		if (tls->server)
			supported = !!tls->handshake_hash[i];
		else
			supported = l_checksum_is_supported(hash->l_id, false);

		if (supported)
			hash_ids[hash_cnt++] = hash->tls_id;
	}

	if (len < 2 + sig_alg_cnt * hash_cnt * 2)
		return -ENOMEM;

	l_put_be16(sig_alg_cnt * hash_cnt * 2, ptr);
	ptr += 2;

	for (i = 0; i < sig_alg_cnt; i++)
		for (j = 0; j < hash_cnt; j++) {
			*ptr++ = hash_ids[j];
			*ptr++ = sig_alg_ids[i];
		}

	return ptr - buf;
}

ssize_t tls_parse_signature_algorithms(struct l_tls *tls,
					const uint8_t *buf, size_t len)
{
	const uint8_t *ptr = buf;
	enum handshake_hash_type first_supported, hash;
	const struct tls_hash_algorithm *preferred;
	struct tls_cipher_suite **suite;
	uint8_t sig_alg_ids[16];
	unsigned int sig_alg_cnt = 0;

	/*
	 * This only makes sense as a variable-length field, assume
	 * there's a typo in RFC5246 7.4.4 here.
	 */
	if (len < 4)
		return -EINVAL;

	if (l_get_be16(ptr) > len - 2)
		return -EINVAL;

	len = l_get_be16(ptr);
	ptr += 2;

	if (len & 1)
		return -EINVAL;

	for (suite = tls->cipher_suite_pref_list; *suite; suite++) {
		uint8_t id;

		if (!(*suite)->signature)
			continue;

		id = (*suite)->signature->id;

		if (memchr(sig_alg_ids, id, sig_alg_cnt))
			continue;

		if (!tls_cipher_suite_is_compatible(tls, *suite, NULL))
			continue;

		if (sig_alg_cnt >= sizeof(sig_alg_ids))
			return -ENOMEM;

		sig_alg_ids[sig_alg_cnt++] = id;
	}

	/*
	 * In 1.2 we force our preference for SHA256/SHA384 (depending on
	 * cipher suite's PRF hmac) if it is supported by the peer because
	 * that must be supported anyway for the PRF and the Finished hash
	 * meaning that we only need to keep one hash instead of two.
	 * If not available fall back to the first common hash algorithm.
	 */
	first_supported = -1;

	if (tls->prf_hmac)
		preferred = tls->prf_hmac;
	else
		preferred = &tls_handshake_hash_data[HANDSHAKE_HASH_SHA256];

	while (len) {
		uint8_t hash_id = *ptr++;
		uint8_t sig_alg_id = *ptr++;
		bool supported;

		len -= 2;

		/* Ignore hash types for signatures other than ours */
		if (tls->pending.cipher_suite &&
				(!tls->pending.cipher_suite->signature ||
				 tls->pending.cipher_suite->signature->id !=
				 sig_alg_id))
			continue;

		if (!tls->pending.cipher_suite &&
				!memchr(sig_alg_ids, sig_alg_id, sig_alg_cnt))
			continue;

		if (hash_id == preferred->tls_id) {
			for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
				if (&tls_handshake_hash_data[hash] == preferred)
					break;
			break;
		}

		if ((int) first_supported != -1)
			continue;

		for (hash = 0; hash < __HANDSHAKE_HASH_COUNT; hash++)
			if (hash_id == tls_handshake_hash_data[hash].tls_id)
				break;

		if (hash == __HANDSHAKE_HASH_COUNT)
			continue;

		if (tls->server)
			supported = l_checksum_is_supported(
					tls_handshake_hash_data[hash].l_id,
					false);
		else
			supported = !!tls->handshake_hash[hash];

		if (supported)
			first_supported = hash;
	}

	if (len)
		tls->signature_hash = hash;
	else if ((int) first_supported != -1)
		tls->signature_hash = first_supported;
	else
		return -ENOTSUP;

	return ptr + len - buf;
}

/* RFC 5246, Section 7.4.1.4.1 */
static ssize_t tls_signature_algorithms_client_write(struct l_tls *tls,
						uint8_t *buf, size_t len)
{
	/*
	 * "Note: this extension is not meaningful for TLS versions
	 * prior to 1.2.  Clients MUST NOT offer it if they are offering
	 * prior versions."
	 */
	if (tls->max_version < L_TLS_V12)
		return -ENOMSG;

	return tls_write_signature_algorithms(tls, buf, len);
}

static bool tls_signature_algorithms_client_handle(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	ssize_t ret;

	/*
	 * "However, even if clients do offer it, the rules specified in
	 * [TLSEXT] require servers to ignore extensions they do not
	 * understand."
	 */
	if (tls->max_version < L_TLS_V12)
		return true;

	ret = tls_parse_signature_algorithms(tls, buf, len);

	if (ret == -ENOTSUP)
		TLS_DEBUG("No common signature algorithms");

	/*
	 * TODO: also check our certificate chain against the parsed
	 * signature algorithms.
	 */

	return ret == (ssize_t) len;
}

static bool tls_signature_algorithms_client_absent(struct l_tls *tls)
{
	/*
	 * "If the client does not send the signature_algorithms extension,
	 * the server MUST do the following:
	 *    - [...] behave as if client had sent the value {sha1,rsa}.
	 *    - [...] behave as if client had sent the value {sha1,dsa}.
	 *    - [...] behave as if client had sent the value {sha1,ecdsa}.
	 */
	if (tls->max_version >= L_TLS_V12)
		tls->signature_hash = HANDSHAKE_HASH_SHA1;

	return true;
}

const struct tls_hello_extension tls_extensions[] = {
	{
		"Supported Groups", "elliptic_curves", 10,
		tls_elliptic_curves_client_write,
		tls_elliptic_curves_client_handle,
		tls_elliptic_curves_client_absent,
		NULL, NULL, NULL,
	},
	{
		"Supported Point Formats", "ec_point_formats", 11,
		NULL,
		tls_ec_point_formats_client_handle,
		NULL,
		tls_ec_point_formats_server_write,
		NULL, NULL,
	},
	{
		"Signature Algorithms", "signature_algoritms", 13,
		tls_signature_algorithms_client_write,
		tls_signature_algorithms_client_handle,
		tls_signature_algorithms_client_absent,
		NULL, NULL, NULL,
	},
	{}
};

const struct tls_named_group *tls_find_group(uint16_t id)
{
	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(tls_group_pref); i++)
		if (tls_group_pref[i].id == id)
			return &tls_group_pref[i];

	return NULL;
}

const struct tls_named_group *tls_find_ff_group(const uint8_t *prime,
						size_t prime_len,
						const uint8_t *generator,
						size_t generator_len)
{
	unsigned int i;

	if (generator_len != 1)
		return NULL;

	for (i = 0; i < L_ARRAY_SIZE(tls_group_pref); i++) {
		const struct tls_named_group *g = &tls_group_pref[i];

		if (g->type != TLS_GROUP_TYPE_FF)
			continue;

		if (g->ff.prime_len != prime_len ||
				memcmp(prime, g->ff.prime, prime_len))
			continue;

		if (g->ff.generator != *generator)
			continue;

		return g;
	}

	return NULL;
}

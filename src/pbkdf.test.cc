#include "pbkdf.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

TEST(pbkdf2, pbkdf_test_32_1) {
	struct pbkdf2_hmac_req req {};
	req.algo		 = HMAC_SHA2_256;
	req.password	 = (uint8_t *) "password";
	req.password_len = strlen((char *) req.password);
	req.salt		 = (uint8_t *) "salt";
	req.salt_len	 = strlen((char *) req.salt);

	req.dklen	   = 32;
	req.iterations = 1;
	std::unique_ptr<uint8_t> dk(pbkdf2(req));

	std::vector<uint8_t>	 actual(dk.get(), dk.get() + req.dklen);
	std::vector<uint8_t>	 expected{
		0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
		0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b,
	};

	EXPECT_EQ(actual, expected);
}

TEST(pbkdf2, pbkdf_test_32_2) {
	struct pbkdf2_hmac_req req {};
	req.algo		 = HMAC_SHA2_256;
	req.password	 = (uint8_t *) "password";
	req.password_len = strlen((char *) req.password);
	req.salt		 = (uint8_t *) "salt";
	req.salt_len	 = strlen((char *) req.salt);

	req.dklen				 = 32;
	req.iterations			 = 2;
	std::unique_ptr<uint8_t> dk(pbkdf2(req));

	std::vector<uint8_t>	 actual(dk.get(), dk.get() + req.dklen);
	std::vector<uint8_t>	 expected{
		 0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
		 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43,
	};

	EXPECT_EQ(actual, expected);
}

TEST(pbkdf2, pbkdf_test_32_4096) {
	struct pbkdf2_hmac_req req {};
	req.algo		 = HMAC_SHA2_256;
	req.password	 = (uint8_t *) "password";
	req.password_len = strlen((char *) req.password);
	req.salt		 = (uint8_t *) "salt";
	req.salt_len	 = strlen((char *) req.salt);

	req.dklen				 = 32;
	req.iterations			 = 4096;
	std::unique_ptr<uint8_t> dk(pbkdf2(req));

	std::vector<uint8_t>	 actual(dk.get(), dk.get() + req.dklen);
	std::vector<uint8_t>	 expected{
		 0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
		 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a,
	};

	EXPECT_EQ(actual, expected);
}

TEST(pbkdf2, pbkdf_test_32_16777216) {
	struct pbkdf2_hmac_req req {};
	req.algo		 = HMAC_SHA2_256;
	req.password	 = (uint8_t *) "password";
	req.password_len = strlen((char *) req.password);
	req.salt		 = (uint8_t *) "salt";
	req.salt_len	 = strlen((char *) req.salt);

	req.dklen				 = 32;
	req.iterations			 = 16777216;
	std::unique_ptr<uint8_t> dk(pbkdf2(req));

	std::vector<uint8_t>	 actual(dk.get(), dk.get() + req.dklen);
	std::vector<uint8_t>	 expected{
		 0xcf, 0x81, 0xc6, 0x6f, 0xe8, 0xcf, 0xc0, 0x4d, 0x1f, 0x31, 0xec, 0xb6, 0x5d, 0xab, 0x40, 0x89,
		 0xf7, 0xf1, 0x79, 0xe8, 0x9b, 0x3b, 0x0b, 0xcb, 0x17, 0xad, 0x10, 0xe3, 0xac, 0x6e, 0xba, 0x46,
	};

	EXPECT_EQ(actual, expected);
}

TEST(pbkdf2, pbkdf_test_40_4096) {
	struct pbkdf2_hmac_req req {};
	req.algo		 = HMAC_SHA2_256;
	req.password	 = (uint8_t *) "passwordPASSWORDpassword";
	req.password_len = strlen((char *) req.password);
	req.salt		 = (uint8_t *) "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	req.salt_len	 = strlen((char *) req.salt);

	req.dklen				= 40;
	req.iterations			= 4096;
	std::unique_ptr<uint8_t> dk(pbkdf2(req));

	std::vector<uint8_t>	 actual(dk.get(), dk.get() + req.dklen);
	std::vector<uint8_t>	 expected{
		0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f, 0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e,
		0x84, 0xcf, 0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18, 0x1c, 0x4e, 0x2a, 0x1f,
		0xb8, 0xdd, 0x53, 0xe1, 0xc6, 0x35, 0x51, 0x8c, 0x7d, 0xac, 0x47, 0xe9,
	};


	EXPECT_EQ(actual, expected);
}

TEST(pbkdf2, pbkdf_test_16_4096) {
	struct pbkdf2_hmac_req req{};
	req.algo		 = HMAC_SHA2_256;
	req.password	 = (uint8_t *) "pass\0word";
	req.password_len = 9;
	req.salt		 = (uint8_t *) "sa\0lt";
	req.salt_len	 = 5;

	req.dklen	   = 16;
	req.iterations = 4096;
	std::unique_ptr<uint8_t> dk(pbkdf2(req));

	std::vector<uint8_t>	 actual(dk.get(), dk.get() + req.dklen);
	std::vector<uint8_t>	 expected{
		0x89, 0xb6, 0x9d, 0x05, 0x16, 0xf8, 0x29, 0x89, 0x3c, 0x69, 0x62, 0x26, 0x65, 0x0a, 0x86, 0x87,
	};

	EXPECT_EQ(actual, expected);
}

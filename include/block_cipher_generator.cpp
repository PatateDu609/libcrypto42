#include <bitset>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define DES 0b000
#define AES128 0b001
#define AES192 0b010
#define AES256 0b011
#define TDES_EDE2 0b100
#define TDES_EDE3 0b101

#define ECB 0b000
#define CBC 0b001
#define OFB 0b010
#define CFB 0b011
#define CFB1 0b100
#define CFB8 0b101
#define CTR 0b110

static bool                           print_default_mode = false;

static std::map<uint8_t, std::string> mode_to_str{
	{ECB,   "ECB" },
    { CBC,  "CBC" },
    { OFB,  "OFB" },
    { CFB,  "CFB" },
    { CFB1, "CFB1"},
    { CFB8, "CFB8"},
    { CTR,  "CTR" },
};

static std::map<uint8_t, std::string> algo_to_str{
	{DES,        "DES"      },
    { AES128,    "AES128"   },
    { AES192,    "AES192"   },
	{ AES256,    "AES256"   },
    { TDES_EDE2, "3DES_EDE2"},
    { TDES_EDE3, "3DES_EDE3"},
};

struct __attribute__((packed)) Algo {
	uint8_t _is_stream  : 1;
	uint8_t _mode       : 3;
	uint8_t _alg        : 3;
	uint8_t _is_default : 1;

	Algo(uint8_t is_default, uint8_t alg, uint8_t mode, uint8_t is_stream)
		: _is_stream(is_stream), _mode(mode), _alg(alg), _is_default(is_default) {}

	std::string get_comment() const {
		std::ostringstream                    oss;

		static std::map<uint8_t, std::string> algo_comment{
			{DES,        "Data Encryption Standard"                        },
			{ AES128,    "Advanced Encryption Standard with a 128 bits key"},
			{ AES192,    "Advanced Encryption Standard with a 192 bits key"},
			{ AES256,    "Advanced Encryption Standard with a 256 bits key"},
			{ TDES_EDE3, "Triple DES with 3 keys"                          },
			{ TDES_EDE2, "Triple DES with 2 keys"                          },
		};

		oss << "///< " << algo_comment[_alg];

		if (print_default_mode) {
			oss << " (defaults to " << mode_to_str[_mode] << " cipher mode)";
		} else {
			oss << " using " << mode_to_str[_mode] << " cipher mode";

			if (_is_default || _is_stream) {
				oss << " (";

				if (_is_default)
					oss << "default cipher mode";
				if (_is_default && _is_stream)
					oss << " - ";
				if (_is_stream)
					oss << "acts as a stream cipher";

				oss << ")";
			}
		}

		return oss.str();
	}
};

std::ostream &operator<<(std::ostream &os, const Algo &algo) {
	os << "BLOCK_CIPHER_" << algo_to_str[algo._alg];
	if (print_default_mode && algo._is_default) {
		os << " = BLOCK_CIPHER_" << algo_to_str[algo._alg] << "_" << mode_to_str[algo._mode];
	} else {
		os << "_" << mode_to_str[algo._mode];
		os << " = 0b" << std::bitset<8>(*reinterpret_cast<const uint8_t *>(&algo));
	}


	return os;
}

int main() {
	std::vector<Algo> algorithms;

	algorithms.emplace_back(false, DES, ECB, false);
	algorithms.emplace_back(true, DES, CBC, false);
	algorithms.emplace_back(false, DES, OFB, true);
	algorithms.emplace_back(false, DES, CFB, true);
	algorithms.emplace_back(false, DES, CFB1, true);
	algorithms.emplace_back(false, DES, CFB8, true);

	algorithms.emplace_back(false, AES128, ECB, false);
	algorithms.emplace_back(true, AES128, CBC, false);
	algorithms.emplace_back(false, AES128, OFB, true);
	algorithms.emplace_back(false, AES128, CFB, true);
	algorithms.emplace_back(false, AES128, CFB1, true);
	algorithms.emplace_back(false, AES128, CFB8, true);
	algorithms.emplace_back(false, AES128, CTR, true);

	algorithms.emplace_back(false, AES192, ECB, false);
	algorithms.emplace_back(true, AES192, CBC, false);
	algorithms.emplace_back(false, AES192, OFB, true);
	algorithms.emplace_back(false, AES192, CFB, true);
	algorithms.emplace_back(false, AES192, CFB1, true);
	algorithms.emplace_back(false, AES192, CFB8, true);
	algorithms.emplace_back(false, AES192, CTR, true);

	algorithms.emplace_back(false, AES256, ECB, false);
	algorithms.emplace_back(true, AES256, CBC, false);
	algorithms.emplace_back(false, AES256, OFB, true);
	algorithms.emplace_back(false, AES256, CFB, true);
	algorithms.emplace_back(false, AES256, CFB1, true);
	algorithms.emplace_back(false, AES256, CFB8, true);
	algorithms.emplace_back(false, AES256, CTR, true);

	algorithms.emplace_back(false, TDES_EDE2, ECB, false);
	algorithms.emplace_back(true, TDES_EDE2, CBC, false);
	algorithms.emplace_back(false, TDES_EDE2, OFB, true);
	algorithms.emplace_back(false, TDES_EDE2, CFB, true);
	algorithms.emplace_back(false, TDES_EDE2, CFB1, true);
	algorithms.emplace_back(false, TDES_EDE2, CFB8, true);
	algorithms.emplace_back(false, TDES_EDE2, CTR, true);

	algorithms.emplace_back(false, TDES_EDE3, ECB, false);
	algorithms.emplace_back(true, TDES_EDE3, CBC, false);
	algorithms.emplace_back(false, TDES_EDE3, OFB, true);
	algorithms.emplace_back(false, TDES_EDE3, CFB, true);
	algorithms.emplace_back(false, TDES_EDE3, CFB1, true);
	algorithms.emplace_back(false, TDES_EDE3, CFB8, true);
	algorithms.emplace_back(false, TDES_EDE3, CTR, true);


	uint8_t             old_alg = 255;
	std::optional<Algo> current_default;

	std::cout << "/**\n"
				 " * @brief Enumerate all available block cipher algorithms.\n"
				 " */\n";
	std::cout << "enum block_cipher {\n";
	for (const auto &item: algorithms) {
		if (old_alg != 255 && item._alg != old_alg) {
			if (current_default) {
				print_default_mode = true;
				std::cout << "\t" << *current_default << "," << current_default->get_comment() << "\n";
				print_default_mode = false;
			}

			current_default.reset();

			std::cout << "\n";
		}

		std::cout << "\t" << item << "," << item.get_comment() << "\n";

		if (item._is_default) {
			if (current_default)
				throw std::runtime_error("The algorithm " + algo_to_str[item._alg] +
				                         " already has a default algorithm which is using " +
				                         mode_to_str[current_default->_mode] + " cipher mode");
			current_default = item;
		}

		old_alg = item._alg;
	}

	if (current_default) {
		print_default_mode = true;
		std::cout << "\t" << *current_default << "," << current_default->get_comment() << "\n";
		print_default_mode = false;
	}
	std::cout << "}";

	return 0;
}

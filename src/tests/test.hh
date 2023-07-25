#ifndef LIBCRYPTO42_TEST_HH
#define LIBCRYPTO42_TEST_HH

#include <cstdio>
#include <openssl/evp.h>

#include <filesystem>
#include <gtest/internal/gtest-param-util.h>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

#define NB_STRING_TESTS 64
#define NB_FILE_TESTS 64

namespace utils {
	double      ceil(double val);
	long double ceil(long double val);
	float       ceil(float val);

	template<typename T>
	std::string to_string_with_precision(const T a_value, const int n = 6) {
		std::ostringstream out;
		out.precision(n);
		out << std::fixed << a_value;
		return std::move(out).str();
	}

	namespace compare {
		struct vector_uint8 {
			constexpr bool operator()(const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs) const {
				return lhs.size() < rhs.size();
			}
		};
	}
}

static inline void get_output(const unsigned char *result, int digest_len, std::string &str) {
	std::ostringstream oss;

	oss << std::hex;

	for (int i = 0; i < digest_len; i++) {
		oss << std::setw(2) << std::setfill('0') << (unsigned int) result[i];
	}

	str = oss.str();
}

struct TestParams {
	bool is_file;
	union {
		fs::path             filename;
		std::vector<uint8_t> string;
	};

	explicit TestParams(std::vector<uint8_t> str) : is_file(false), string(std::move(str)) {}
	explicit TestParams(fs::path path) : is_file(true), filename(std::move(path)) {}

	~TestParams() {
		filename.~path();
	}

	TestParams(const TestParams &other) : is_file(true) {
		*this = other;
	}

	TestParams &operator=(const TestParams &other) {
		this->is_file = other.is_file;

		if (this->is_file)
			this->filename = other.filename;
		else
			this->string = other.string;

		return *this;
	}
};

class TestParamsIdx {
	typedef std::vector<uint8_t>                                               test_string_type;
	typedef fs::path                                                           test_filename_type;
	typedef std::variant<std::monostate, test_filename_type, test_string_type> test_type;

	typedef std::vector<std::vector<uint8_t> >                                 test_strings_source_type;
	typedef std::vector<fs::path>                                              test_filenames_source_type;

public:
	TestParamsIdx(size_t i, bool is_file_test);

	std::shared_ptr<TestParams> get_linked_test();
	std::string                 get_test_name(const testing::TestParamInfo<TestParamsIdx> &info);

private:
	bool                        is_file_test;
	size_t                      idx;
	test_type                   linked_test;


	friend std::ostream        &operator<<(std::ostream &os, TestParamsIdx testParamsIdx);

	void                        refresh_linked_test();
	void                        reset_linked_test();
	std::shared_ptr<TestParams> retrieve_current_linked_test() const;
};

std::ostream                             &operator<<(std::ostream &os, const TestParams &testParams);

extern std::vector<fs::path>              test_filenames;
extern std::vector<std::vector<uint8_t> > test_strings;

void run_digest_string_test(const EVP_MD *md, const char *arg, char *(*mine)(const char *) );
void run_digest_file_test(const EVP_MD *md, const char *filename, char *(*mine)(const char *) );

void set_params_range();

#endif// LIBCRYPTO42_TEST_HH

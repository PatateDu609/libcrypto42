#include "test.h"
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>

#ifdef __APPLE__
#	include <sys/random.h>
#else
#	include <unistd.h>
#endif

std::random_device						 prng;
std::mt19937_64							 prng_engine(prng());

std::vector<std::filesystem::path>		 test_filenames;
std::vector<std::basic_string<uint8_t> > test_strings;

namespace fs = std::filesystem;

static std::vector<uint8_t> get_random_data(size_t length) {
	const size_t		 MAX_LENGTH = 256;
	std::vector<uint8_t> res;
	res.reserve(length);

	if (res.size() <= MAX_LENGTH) {
		if (getentropy(res.data(), res.size()))
			throw std::runtime_error(strerror(errno));
		return res;
	}

	std::vector<uint8_t> buffer(MAX_LENGTH, 0);
	size_t				 i = 0;
	for (; i < length; i += MAX_LENGTH) {
		if (getentropy(buffer.data(), buffer.size()))
			throw std::runtime_error(strerror(errno));

		res.insert(res.end(), buffer.begin(), buffer.end());
		buffer.assign(MAX_LENGTH, 0);
	}

	if (i < length) {
		res.assign(length - i, 0);
		if (getentropy(res.data(), res.size()))
			throw std::runtime_error(strerror(errno));
		return res;
	}

	return res;
}

class FileEnvironment : public testing::Environment {
private:
	std::string generate_name() {
		uint8_t		dir_name_length = length_distrib(prng_engine);

		std::string str;
		str.resize(dir_name_length);
		std::generate_n(str.begin(), dir_name_length, [this] { return filename_charset[fs_distrib(prng_engine)]; });

		return str;
	}

	void create_file(size_t length) {
		fs::path filename = length ? generate_name() : "empty";
		filename		  = dir_name / filename;

		std::ofstream ofs(filename, std::fstream::trunc | std::ios::binary);
		if (!ofs.is_open())
			throw std::runtime_error("couldn't open file: " + filename.string());
		if (length != 0) {
			std::vector<uint8_t> data = get_random_data(length);
			ofs.write(reinterpret_cast<char *>(data.data()), (std::ptrdiff_t) data.size());
		}

		test_filenames.push_back(filename);

		ofs.close();
	}

public:
	FileEnvironment()
		: fs_distrib(0, filename_charset.length()), length_distrib(3, 16), dir_name(fs::temp_directory_path()) {}

	~FileEnvironment() override = default;

	// Override this to define how to set up the environment.
	void SetUp() override {
		dir_name = fs::temp_directory_path() / ("ft_ssl." + generate_name());
		ASSERT_TRUE(fs::create_directories(dir_name));

		ASSERT_NO_THROW(create_file(0));
		ASSERT_NO_THROW(create_file(10));
		ASSERT_NO_THROW(create_file(48));
		ASSERT_NO_THROW(create_file(100));
		ASSERT_NO_THROW(create_file(480));
		ASSERT_NO_THROW(create_file(4096));
		ASSERT_NO_THROW(create_file(8192));
		ASSERT_NO_THROW(create_file(10000));
	}

	// Override this to define how to tear down the environment.
	void TearDown() override {
		if (fs::exists(dir_name))
			fs::remove_all(dir_name);
		else
			std::cerr << "Error: ft_ssl: " << dir_name << ": directory doesn't exist" << std::endl;
	}

private:
	std::uniform_int_distribution<uint16_t> fs_distrib;
	std::uniform_int_distribution<uint8_t>	length_distrib;
	fs::path								dir_name;

	const static std::string				filename_charset;
};
const std::string FileEnvironment::filename_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

class StringEnvironment : public testing::Environment {
	static std::basic_string<uint8_t> get_random_data_as_string(size_t length) {
		if (!length)
			return {};

		std::vector<uint8_t> data = get_random_data(length);
		return { data.begin(), data.end() };
	}

public:
	~StringEnvironment() override = default;

	void SetUp() override {
		test_strings.emplace_back();

		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(10)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(29)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(59)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(80)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(104)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(120)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(134)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(203)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(1202)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(2048)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(4000)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(10000)));
		ASSERT_NO_THROW(test_strings.push_back(get_random_data_as_string(16384)));
	}

	void TearDown() override {}
};

int main(int argc, char **argv) {
	testing::InitGoogleTest(&argc, argv);

	testing::AddGlobalTestEnvironment(new FileEnvironment());
	testing::AddGlobalTestEnvironment(new StringEnvironment());

	return RUN_ALL_TESTS();
}
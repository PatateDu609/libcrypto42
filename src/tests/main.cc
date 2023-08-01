#include "random.hh"
#include "test.hh"
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <set>

std::vector<std::filesystem::path> test_filenames;
std::vector<std::vector<uint8_t> > test_strings;
std::vector<TestParams>            test_params;

using rng::get_random_data;


const std::multiset<size_t> &get_scales(size_t max_idx) {
	static std::multiset<size_t> scales;
	if (scales.size() == max_idx)
		return scales;

	max_idx--;

	std::map<size_t, std::pair<size_t, double> > references{
		{1,      std::make_pair(1, 0)},
        { 5,     std::make_pair(3, 0)},
        { 10,    std::make_pair(3, 0)},
		{ 16,    std::make_pair(3, 0)},
        { 32,    std::make_pair(3, 0)},
        { 50,    std::make_pair(5, 0)},
		{ 50,    std::make_pair(5, 0)},
        { 100,   std::make_pair(4, 0)},
        { 128,   std::make_pair(3, 0)},
		{ 512,   std::make_pair(3, 0)},
        { 400,   std::make_pair(5, 0)},
        { 1000,  std::make_pair(4, 0)},
		{ 4000,  std::make_pair(4, 0)},
        { 4096,  std::make_pair(3, 0)},
        { 10000, std::make_pair(3, 0)},
		{ 20000, std::make_pair(1, 0)},
	};
	auto accumulate = [](size_t acc, decltype(references)::value_type a) {
		return acc + a.second.first;
	};

	size_t ref_count = std::accumulate(references.begin(), references.end(), 0, accumulate);

	auto   set_percentage = [ref_count](decltype(references)::reference a) {
        a.second.second = static_cast<double>(a.second.first) / static_cast<double>(ref_count);
	};
	auto set_references = [max_idx](decltype(references)::reference a) {
		a.second.first = static_cast<size_t>(std::ceil(a.second.second * static_cast<double>(max_idx)));
	};

	std::for_each(references.begin(), references.end(), set_percentage);

	std::for_each(references.begin(), references.end(), set_references);
	ref_count = std::accumulate(references.begin(), references.end(), 0, accumulate);

	double limit = 0.1;
	while (ref_count > max_idx) {
		size_t to_remove = ref_count - max_idx;

		auto   even_out = [&to_remove, &ref_count, limit](decltype(references)::reference a) {
            if (to_remove && a.second.second >= limit) {
                to_remove--;
                a.second.first--;
                ref_count--;
            }
		};
		std::for_each(references.begin(), references.end(), even_out);
		std::for_each(references.begin(), references.end(), set_percentage);

		if (!to_remove)
			break;
		limit -= -.01;
	}

	ref_count = std::accumulate(references.begin(), references.end(), 0, accumulate);

	for (const auto &item: references) {
		for (size_t i = 0; i < item.second.first; i++)
			scales.emplace(item.first);
	}

	scales.emplace(0);
	return scales;
}

namespace fs = std::filesystem;

class FileEnvironment : public testing::Environment {
private:
	std::string generate_name() {
		uint8_t     dir_name_length = length_distrib(rng::engine);

		std::string str;
		str.resize(dir_name_length);
		std::generate_n(str.begin(), dir_name_length, [this] {
			return filename_charset[fs_distrib(rng::engine)];
		});

		return str;
	}

	void create_file(size_t length) {
		fs::path filename = length ? generate_name() : "empty";
		filename          = dir_name / filename;

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
		: fs_distrib(0, filename_charset.length() - 1), length_distrib(3, 16), dir_name(fs::temp_directory_path()) {}

	~FileEnvironment() override = default;

	// Override this to define how to set up the environment.
	void SetUp() override {
		dir_name = fs::temp_directory_path() / ("ft_ssl." + generate_name());
		ASSERT_TRUE(fs::create_directories(dir_name));

		std::multiset<size_t>                        scales = get_scales(NB_FILE_TESTS);
		std::multiset<size_t>                        tests;

		rng::CauchyDistribution<long double>::Params cauchy_params(0.0, 1.0, 0.03, 0.05);
		rng::CauchyDistribution<long double>         cauchy(cauchy_params);

		//		cauchy.debug();

		for (const auto &scale: scales)
			tests.emplace(cauchy(scale));

		cauchy.dump_history(std::cerr);

		std::for_each(tests.begin(), tests.end(), [this](decltype(tests)::value_type length) {
			ASSERT_NO_THROW(this->create_file(length));
		});
		std::cout << "have " << test_filenames.size() << " file tests" << std::endl;
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
	std::uniform_int_distribution<uint8_t>  length_distrib;
	fs::path                                dir_name;

	const static std::string                filename_charset;
};
const std::string FileEnvironment::filename_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

class StringEnvironment : public testing::Environment {
public:
	~StringEnvironment() override = default;

	void SetUp() override {
		std::multiset<size_t>                                             scales = get_scales(NB_STRING_TESTS);
		std::multiset<std::vector<uint8_t>, utils::compare::vector_uint8> tests;

		rng::CauchyDistribution<long double>::Params                      cauchy_params(0.0, 1.0, 0.02, 0.001);
		rng::CauchyDistribution<long double>                              cauchy(cauchy_params);

		//		cauchy.debug();

		for (const auto &item: scales)
			ASSERT_NO_THROW(tests.insert(get_random_data(cauchy(item))));

		cauchy.dump_history(std::cerr);

		test_strings.assign(tests.begin(), tests.end());
		std::cout << "have " << test_strings.size() << " string tests" << std::endl;
	}

	void TearDown() override {}
};

int main(int argc, char **argv) {
	set_params_range();

	testing::InitGoogleTest(&argc, argv);

	testing::AddGlobalTestEnvironment(new FileEnvironment());
	testing::AddGlobalTestEnvironment(new StringEnvironment());

	return RUN_ALL_TESTS();
}
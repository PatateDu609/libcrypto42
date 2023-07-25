#include "test.hh"
#include <cmath>
#include <map>
#include <sstream>

double utils::ceil(double val) {
	return ::ceil(val);
}

long double utils::ceil(long double val) {
	return ::ceill(val);
}

float utils::ceil(float val) {
	return ::ceilf(val);
}

std::ostream &operator<<(std::ostream &os, const TestParams &testParams) {
	if (testParams.is_file) {
		std::ostringstream                                    size;
		static std::map<size_t, std::string, std::greater<> > units{
			{1,				   "B" },
			{ 1024,               "KB"},
			{ 1024 * 1024,        "MB"},
			{ 1024 * 1024 * 1024, "GB"},
		};
		size_t file_size = fs::file_size(testParams.filename);
		size_t remaining = file_size;

		for (const auto &unit: units) {
			size_t q = remaining / unit.first;
			if (q == 0)
				continue;
			size << q << unit.second;
			remaining /= 1024;

			if (remaining == 0) {
				break;
			}
		}

		os << "file: " << testParams.filename << ", size: " << size.str();
	} else
		os << "String of size: " << testParams.string.size();

	return os;
}

std::ostream &operator<<(std::ostream &os, TestParamsIdx testParamsIdx) {
	const auto& params = testParamsIdx.get_linked_test();

	if (params == nullptr)
		return os << "element " << testParamsIdx.idx << " still not instantiated";

	return os << "param(" << params << ") = " << *params;
}

TestParamsIdx::TestParamsIdx(size_t i, bool is_file) : is_file_test(is_file), idx(i), linked_test(std::monostate{}) {
	get_linked_test();
}

std::shared_ptr<TestParams> TestParamsIdx::get_linked_test() {
	refresh_linked_test();

	return retrieve_current_linked_test();
}

std::string TestParamsIdx::get_test_name(const testing::TestParamInfo<TestParamsIdx> &info) {
	refresh_linked_test();

	if (std::holds_alternative<test_filename_type>(linked_test))
		return std::get<test_filename_type>(linked_test).string() + testing::PrintToString(info.index);
	return testing::PrintToString(info.index);
}

void TestParamsIdx::refresh_linked_test() {
	if (is_file_test) {
		try {
			linked_test = test_filenames.at(idx);
		} catch (const std::out_of_range &e) {
			reset_linked_test();
		}
	} else {
		try {
			linked_test = test_strings.at(idx);
		} catch (const std::out_of_range &e) {
			reset_linked_test();
		}
	}
}

void TestParamsIdx::reset_linked_test() {
	linked_test = std::monostate{};
}

std::shared_ptr<TestParams> TestParamsIdx::retrieve_current_linked_test() const {
	try {
		const auto &test = std::get<test_filename_type>(linked_test);

		return std::make_shared<TestParams>(test);
	} catch (const std::bad_variant_access &e) {}

	try {
		const auto &test = std::get<test_string_type>(linked_test);

		return std::make_shared<TestParams>(test);
	} catch (const std::bad_variant_access &e) {}

	return nullptr;
}